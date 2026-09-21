// SPDX-License-Identifier: MIT

package rsync

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zyno-io/sp2p/internal/tunnel"
)

func TestValidateClientArgs(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		direction Direction
		wantErr   bool
	}{
		{"upload", []string{"-av", "--exclude", "*.tmp", "source dir/", "sp2p::share"}, Upload, false},
		{"download", []string{"-av", "--partial", "sp2p::share/photos/", "destination dir/"}, Download, false},
		{"upload remote not last operand", []string{"sp2p::share", "destination"}, Upload, true},
		{"download remote not first operand", []string{"destination", "sp2p::share"}, Download, true},
		{"other module", []string{"source", "host::other"}, Upload, true},
		{"remote shell", []string{"-e", "ssh", "source", "sp2p::share"}, Upload, true},
		{"combined remote shell", []string{"-eSSH", "source", "sp2p::share"}, Upload, true},
		{"bundled remote shell", []string{"-ave", "ssh", "source", "sp2p::share"}, Upload, true},
		{"attached temp option", []string{"-T/tmp/cache", "source", "sp2p::share"}, Upload, false},
		{"attached filter option", []string{"-f- *.exe", "source", "sp2p::share"}, Upload, false},
		{"long option value is not operand", []string{"--compare-dest", "old::tree", "sp2p::share/", "destination"}, Download, false},
		{"partial directory value is not operand", []string{"--partial-dir", ".parts", "sp2p::share/", "destination"}, Download, false},
		{"short modify window value is not operand", []string{"-@", "2", "sp2p::share/", "destination"}, Download, false},
		{"daemon override", []string{"--rsync-path=evil", "source", "sp2p::share"}, Upload, true},
		{"daemon config", []string{"--config", "rsyncd.conf", "source", "sp2p::share"}, Upload, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateClientArgs(test.args, test.direction)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateClientArgs() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestAllRsyncValueTakingOptionsPreserveOperands(t *testing.T) {
	options := []string{
		"--address", "--backup-dir", "--block-size", "--bwlimit",
		"--cc", "--checksum-choice", "--checksum-seed", "--chmod", "--chown",
		"--compare-dest", "--compress-choice", "--compress-level", "--compress-threads",
		"--confine-root", "--contimeout", "--copy-as", "--copy-dest",
		"--debug", "--early-input", "--exclude", "--exclude-from", "--files-from",
		"--filter", "--groupmap", "--iconv", "--include", "--include-from",
		"--info", "--link-dest", "--log-file", "--log-file-format", "--log-format",
		"--max-alloc", "--max-delete", "--max-size", "--min-size", "--modify-window",
		"--out-format", "--outbuf", "--partial-dir", "--password-file", "--port",
		"--protocol", "--skip-compress", "--sockopts", "--stderr", "--stop-after",
		"--stop-at", "--suffix", "--temp-dir", "--time-limit", "--timeout",
		"--usermap", "--zc", "--zl", "--zt",
	}
	for _, option := range options {
		t.Run(option, func(t *testing.T) {
			err := ValidateClientArgs([]string{option, "value", "sp2p::share/", "destination"}, Download)
			if err != nil {
				t.Fatalf("ValidateClientArgs() rejected separated %s value: %v", option, err)
			}
		})
	}
}

func TestClientEnvironmentForcesHelperArgumentEnvironment(t *testing.T) {
	t.Setenv("RSYNC_CONNECT_PROG", "untrusted")
	t.Setenv("RSYNC_RSH", "untrusted")
	t.Setenv("RSYNC_SHELL", "untrusted")
	t.Setenv(helperArgumentEnvName(0), "untrusted")
	t.Setenv("SP2P_TEST_TOKEN", "old")
	helperArgs := []string{"/path with spaces/sp2p", "__rsync-stdio", "%H"}
	env := clientEnvironmentWithForced(
		connectProgramFromEnvironment(len(helperArgs)),
		[]string{"SP2P_TEST_TOKEN=new", helperArgumentEnvName(0) + "=override"},
		helperArgumentEnvironment(helperArgs),
	)
	got := envValue(t, env, "RSYNC_CONNECT_PROG")
	want := `"${SP2P_INTERNAL_RSYNC_HELPER_ARG_0}" "${SP2P_INTERNAL_RSYNC_HELPER_ARG_1}" "${SP2P_INTERNAL_RSYNC_HELPER_ARG_2}"`
	if got != want {
		t.Fatalf("RSYNC_CONNECT_PROG = %q, want %q", got, want)
	}
	for index, want := range helperArgs {
		if got := envValue(t, env, helperArgumentEnvName(index)); got != want {
			t.Fatalf("helper argument %d = %q, want %q", index, got, want)
		}
	}
	if got := envValue(t, env, "SP2P_TEST_TOKEN"); got != "new" {
		t.Fatalf("extra environment = %q, want new", got)
	}
	for _, forbidden := range []string{"RSYNC_RSH", "RSYNC_SHELL"} {
		if got := envValue(t, env, forbidden); got != "" {
			t.Fatalf("%s leaked into child environment: %q", forbidden, got)
		}
	}
}

func TestOpenRsyncUsesFixedRSHHelper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows rsync is explicitly unsupported")
	}
	binary := filepath.Join(t.TempDir(), "openrsync")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf 'openrsync: protocol version 29\\nrsync version 2.6.9 compatible\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	version, err := InspectBinary(binary)
	if err != nil {
		t.Fatal(err)
	}
	if version.Flavor != FlavorOpenRsync {
		t.Fatalf("flavor = %q, want openrsync", version.Flavor)
	}
	client, err := NewClient(ClientConfig{
		Binary: binary, Args: []string{"-av", "source", "sp2p::share"}, Direction: Upload,
		ConnectArgs: []string{"/path with spaces/sp2p", "__rsync-stdio"},
	})
	if err != nil {
		t.Fatal(err)
	}
	command := client.Command()
	if len(command.Args) < 4 || command.Args[1] != "-e" || command.Args[2] != "'/path with spaces/sp2p' '__rsync-stdio'" {
		t.Fatalf("openrsync command args = %#v", command.Args)
	}
	if got := envValue(t, command.Env, "RSYNC_CONNECT_PROG"); got != "" {
		t.Fatalf("openrsync unexpectedly received RSYNC_CONNECT_PROG=%q", got)
	}
}

func TestDaemonConfigIsFixedAndPrivate(t *testing.T) {
	directory := t.TempDir()
	path, cleanup, err := daemonConfig(context.Background(), directory, ServeOptions{Writable: true, AllowDelete: false, TempDir: t.TempDir()})
	if err != nil {
		t.Fatalf("daemonConfig() error = %v", err)
	}
	defer cleanup()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %#o, want 0600", info.Mode().Perm())
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	text := string(contents)
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	requiredValues := []string{"[share]", "path = " + canonical, "read only = false", "write only = true", "copy-links", "delete", "munge symlinks = true"}
	for _, required := range requiredValues {
		if !strings.Contains(text, required) {
			t.Errorf("config missing %q:\n%s", required, text)
		}
	}
}

func TestReadOnlyDaemonConfigRefusesSourceRemoval(t *testing.T) {
	text := makeDaemonConfig(t.TempDir(), false, false)
	for _, required := range []string{"read only = true", "remove-source-files", "remove-sent-files"} {
		if !strings.Contains(text, required) {
			t.Errorf("read-only config missing %q:\n%s", required, text)
		}
	}
}

func TestDaemonConfigRejectsControlPath(t *testing.T) {
	parent := t.TempDir()
	for _, name := range []string{"line\nfeed", "trailing-space "} {
		path := filepath.Join(parent, name)
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		_, _, err := daemonConfig(context.Background(), path, ServeOptions{})
		if err == nil {
			t.Fatalf("daemonConfig accepted unsafe path %q", name)
		}
	}
}

// TestRsyncBridgeHelper is invoked in a child test binary by
// TestServeWithModernRsync. It is deliberately an internal stdio-only bridge;
// no command supplied by rsync can choose a different network endpoint.
func TestRsyncBridgeHelper(t *testing.T) {
	address := os.Getenv("SP2P_RSYNC_TEST_BRIDGE")
	if address == "" {
		return
	}
	conn, err := net.Dial("tcp", address)
	if err != nil {
		os.Exit(20)
	}
	endpoint := &testStdioEndpoint{in: os.Stdin, out: os.Stdout}
	if err := tunnel.Bridge(context.Background(), conn.(*net.TCPConn), endpoint); err != nil {
		os.Exit(21)
	}
	os.Exit(0)
}

func testBridgeHelper(t *testing.T, address string) ([]string, []string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows rsync is explicitly unsupported")
	}
	helper := filepath.Join(t.TempDir(), "rsync-stdio-helper")
	logPath := filepath.Join(t.TempDir(), "rsync-stdio-helper.log")
	// The native -e fallback appends rsync's fixed remote argv. This tiny
	// wrapper intentionally ignores it before invoking the test transport.
	contents := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SP2P_RSYNC_TEST_LOG\"\nexec \"$SP2P_RSYNC_TEST_BINARY\" -test.run='^TestRsyncBridgeHelper$'\n"
	if err := os.WriteFile(helper, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	return []string{helper}, []string{
		"SP2P_RSYNC_TEST_BINARY=" + os.Args[0],
		"SP2P_RSYNC_TEST_BRIDGE=" + address,
		"SP2P_RSYNC_TEST_LOG=" + logPath,
	}, logPath
}

// TestServeWithModernRsync exercises the real daemon protocol with the binary
// supplied by the test environment, including the macOS built-in rsync.
func TestServeWithModernRsync(t *testing.T) {
	binary := os.Getenv("SP2P_TEST_RSYNC")
	if binary == "" {
		t.Skip("set SP2P_TEST_RSYNC to a supported rsync binary")
	}
	if _, err := InspectBinary(binary); err != nil {
		t.Fatalf("test rsync binary: %v", err)
	}
	for _, writable := range []bool{false, true} {
		name := "download"
		if writable {
			name = "upload"
		}
		t.Run(name, func(t *testing.T) {
			testServePrivateDirectories(t, binary, writable)
		})
	}
}

// Private files/directories also catch rsyncd's default switch to nobody when
// this test runs as root in a container: downloads must read and uploads write
// using the caller's identity.
func testServePrivateDirectories(t *testing.T, binary string, writable bool) {
	t.Helper()
	source, destination := t.TempDir(), t.TempDir()
	const sourceName = "one ünicode file.txt"
	if err := os.WriteFile(filepath.Join(source, sourceName), []byte("contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	directory, direction := source, Download
	args := []string{"-avc", "sp2p::share/", destination + "/"}
	if writable {
		directory, direction = destination, Upload
		args = []string{"-avc", source + "/", "sp2p::share/"}
	}
	stream, bridgeStream := rsyncTCPPair(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- Serve(ctx, stream, directory, ServeOptions{Binary: binary, Writable: writable, TempDir: t.TempDir(), Stderr: os.Stderr})
	}()
	bridgeDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			bridgeDone <- acceptErr
			return
		}
		bridgeDone <- tunnel.Bridge(ctx, bridgeStream, conn)
	}()
	connectArgs, extraEnv, helperLog := testBridgeHelper(t, listener.Addr().String())
	var stdout bytes.Buffer
	client, err := NewClient(ClientConfig{
		Binary: binary, Args: args, Direction: direction,
		ConnectArgs: connectArgs,
		ExtraEnv:    extraEnv,
		Stdout:      &stdout, Stderr: os.Stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Run(ctx); err != nil {
		data, _ := os.ReadFile(helperLog)
		var serveState, bridgeState any = "running", "running"
		select {
		case serveState = <-serveDone:
		default:
		}
		select {
		case bridgeState = <-bridgeDone:
		default:
		}
		t.Fatalf("rsync client: %v; helper args: %q; serve=%v bridge=%v", err, data, serveState, bridgeState)
	}
	if !strings.Contains(stdout.String(), sourceName) {
		t.Fatalf("rsync output omitted Unicode source name %q: %q", sourceName, stdout.String())
	}
	contents, err := os.ReadFile(filepath.Join(destination, sourceName))
	if err != nil || string(contents) != "contents" {
		t.Fatalf("rsync transfer into private destination: contents=%q err=%v", contents, err)
	}
	if err := <-bridgeDone; err != nil {
		t.Fatalf("bridge: %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("rsync daemon: %v", err)
	}
}

func TestServeRefusesSourceRemoval(t *testing.T) {
	binary := os.Getenv("SP2P_TEST_RSYNC")
	if binary == "" {
		t.Skip("set SP2P_TEST_RSYNC to a supported rsync binary")
	}
	if _, err := InspectBinary(binary); err != nil {
		t.Fatalf("test rsync binary: %v", err)
	}
	source := t.TempDir()
	sourcePath := filepath.Join(source, "keep.txt")
	if err := os.WriteFile(sourcePath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	stream, bridgeStream := rsyncTCPPair(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- Serve(ctx, stream, source, ServeOptions{Binary: binary, TempDir: t.TempDir(), Stderr: os.Stderr})
	}()
	bridgeDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			bridgeDone <- acceptErr
			return
		}
		bridgeDone <- tunnel.Bridge(ctx, bridgeStream, conn)
	}()
	connectArgs, extraEnv, _ := testBridgeHelper(t, listener.Addr().String())
	client, err := NewClient(ClientConfig{
		Binary: binary, Args: []string{"-a", "--remove-source-files", "sp2p::share/", t.TempDir()}, Direction: Download,
		ConnectArgs: connectArgs,
		ExtraEnv:    extraEnv,
		Stdout:      os.Stdout, Stderr: os.Stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Run(ctx); err == nil {
		t.Fatal("rsync daemon accepted --remove-source-files on a read-only module")
	}
	if _, err := os.Stat(sourcePath); err != nil {
		t.Fatalf("read-only daemon source was removed: %v", err)
	}
	cancel()
	<-bridgeDone
	<-serveDone
}

func TestServeRefusesSymlinkDereference(t *testing.T) {
	binary := os.Getenv("SP2P_TEST_RSYNC")
	if binary == "" {
		t.Skip("set SP2P_TEST_RSYNC to a supported rsync binary")
	}
	if _, err := InspectBinary(binary); err != nil {
		t.Fatalf("test rsync binary: %v", err)
	}
	source := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("must not leave module"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(source, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "short copy-links", args: []string{"-aL"}},
		{name: "long copy-links", args: []string{"-a", "--copy-links"}},
		{name: "copy-unsafe-links", args: []string{"-a", "--copy-unsafe-links"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination := t.TempDir()
			stream, bridgeStream := rsyncTCPPair(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			serveDone := make(chan error, 1)
			go func() {
				serveDone <- Serve(ctx, stream, source, ServeOptions{Binary: binary, TempDir: t.TempDir(), Stderr: os.Stderr})
			}()
			bridgeDone := make(chan error, 1)
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					bridgeDone <- acceptErr
					return
				}
				bridgeDone <- tunnel.Bridge(ctx, bridgeStream, conn)
			}()
			connectArgs, extraEnv, helperLog := testBridgeHelper(t, listener.Addr().String())
			args := append(append([]string(nil), test.args...), "sp2p::share/", destination)
			client, err := NewClient(ClientConfig{
				Binary: binary, Args: args, Direction: Download,
				ConnectArgs: connectArgs,
				ExtraEnv:    extraEnv,
				Stdout:      os.Stdout, Stderr: os.Stderr,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Run(ctx); err == nil {
				helperArgs, _ := os.ReadFile(helperLog)
				target, targetErr := os.Readlink(filepath.Join(destination, "escape"))
				contents, contentsErr := os.ReadFile(filepath.Join(destination, "escape"))
				t.Fatalf("rsync accepted %v for a module containing an outside symlink; helper args=%q destination link=%q (%v) contents=%q (%v)", test.args, helperArgs, target, targetErr, contents, contentsErr)
			}
			if _, err := os.Lstat(filepath.Join(destination, "escape")); !os.IsNotExist(err) {
				t.Fatalf("outside symlink was exposed in destination: %v", err)
			}
			cancel()
			<-bridgeDone
			<-serveDone
		})
	}
}

func TestServeDoesNotTraverseSelectedSymlink(t *testing.T) {
	source := t.TempDir()
	outsideDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsideDir, "secret.txt"), []byte("must not leave module"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(source, "outside-dir")); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateDirectory(context.Background(), source); err == nil {
		t.Fatal("directory validation accepted a directory symlink that an rsync request could traverse")
	}
}

func TestValidateDirectoryCanonicalizesRootAndPermitsFileLinks(t *testing.T) {
	root := t.TempDir()
	rootLink := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(root, rootLink); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(root, "file-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing-target", filepath.Join(root, "dangling-link")); err != nil {
		t.Fatal(err)
	}
	got, err := ValidateDirectory(context.Background(), rootLink)
	if err != nil {
		t.Fatalf("ValidateDirectory() error = %v", err)
	}
	want, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("ValidateDirectory() = %q, want canonical root %q", got, want)
	}
}

func TestValidateDirectoryRejectsUnsafeCanonicalAlias(t *testing.T) {
	unsafe := filepath.Join(t.TempDir(), "unsafe%directory")
	if err := os.Mkdir(unsafe, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "safe-alias")
	if err := os.Symlink(unsafe, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateDirectory(context.Background(), alias); err == nil {
		t.Fatal("ValidateDirectory accepted alias resolving to config-unsafe path")
	}
}

func TestValidateDirectoryCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ValidateDirectory(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("ValidateDirectory() error = %v, want context cancellation", err)
	}
}

func TestValidateDirectoryRejectsEmpty(t *testing.T) {
	if _, err := ValidateDirectory(context.Background(), ""); err == nil {
		t.Fatal("ValidateDirectory accepted an empty directory")
	}
}

type testStdioEndpoint struct {
	in  *os.File
	out *os.File
}

func (s *testStdioEndpoint) Read(p []byte) (int, error)  { return s.in.Read(p) }
func (s *testStdioEndpoint) Write(p []byte) (int, error) { return s.out.Write(p) }
func (s *testStdioEndpoint) Close() error                { return nil }

func rsyncTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	server := <-accepted
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return server, client
}

func envValue(t *testing.T, env []string, name string) string {
	t.Helper()
	for _, entry := range env {
		key, value, found := strings.Cut(entry, "=")
		if key == name && found {
			return value
		}
	}
	return ""
}
