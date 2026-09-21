// SPDX-License-Identifier: MIT

// Package rsync runs a constrained, single-use rsync daemon or client over an
// already-authenticated byte stream. Peer/session setup intentionally belongs to
// its caller.
package rsync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/zyno-io/sp2p/internal/tunnel"
)

// Stream is the subset of stream.Stream used by the stdio daemon.
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
	CloseWrite() error
}

// Direction identifies the direction of files, independent of which side runs
// the rsync client.
type Direction string

const (
	Upload   Direction = "upload"
	Download Direction = "download"
)

// MinimumVersion is the oldest upstream rsync release supported by this
// adapter. It includes Apple's historical upstream 2.6.9; current macOS
// openrsync is detected separately and uses a socket-initiated daemon.
var MinimumVersion = Version{Major: 2, Minor: 6, Patch: 9}

// Version is an rsync release version.
type Version struct {
	Major  int
	Minor  int
	Patch  int
	Flavor BinaryFlavor
}

// BinaryFlavor selects the locally supported rsync connection hook.
type BinaryFlavor string

const (
	FlavorUpstream  BinaryFlavor = "upstream"
	FlavorOpenRsync BinaryFlavor = "openrsync"
)

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

func (v Version) less(other Version) bool {
	if v.Major != other.Major {
		return v.Major < other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor < other.Minor
	}
	return v.Patch < other.Patch
}

var versionPattern = regexp.MustCompile(`(?m)^rsync\s+version\s+(\d+)\.(\d+)\.(\d+)\b`)

// InspectBinary verifies that path is a supported upstream rsync binary.
func InspectBinary(path string) (Version, error) {
	if runtime.GOOS == "windows" {
		return Version{}, errors.New("rsync integration is supported on macOS and Linux; use WSL on Windows")
	}
	if path == "" {
		return Version{}, errors.New("rsync binary path is empty")
	}
	probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(probeCtx, path, "--version")
	output, err := command.CombinedOutput()
	if err != nil {
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return Version{}, errors.New("rsync --version timed out")
		}
		return Version{}, fmt.Errorf("run rsync --version: %w", err)
	}
	match := versionPattern.FindSubmatch(output)
	if match == nil {
		return Version{}, errors.New("rsync binary is not a supported rsync release")
	}
	major, _ := strconv.Atoi(string(match[1]))
	minor, _ := strconv.Atoi(string(match[2]))
	patch, _ := strconv.Atoi(string(match[3]))
	version := Version{Major: major, Minor: minor, Patch: patch, Flavor: FlavorUpstream}
	if strings.HasPrefix(strings.TrimSpace(string(output)), "openrsync:") {
		// macOS ships openrsync with protocol 29. It lacks RSYNC_CONNECT_PROG
		// but accepts -e for daemon syntax, so Client uses that fixed local
		// helper transport instead. Its daemon supports this package's fixed
		// module configuration.
		version.Flavor = FlavorOpenRsync
		return version, nil
	}
	if version.less(MinimumVersion) {
		return Version{}, fmt.Errorf("rsync %s is unsupported; need rsync %s or newer", version, MinimumVersion)
	}
	return version, nil
}

// FindBinary locates and verifies rsync before a caller creates a session or
// displays a code.
func FindBinary(path string) (string, Version, error) {
	if path == "" {
		path = "rsync"
	}
	found, err := exec.LookPath(path)
	if err != nil {
		return "", Version{}, fmt.Errorf("find rsync: %w", err)
	}
	version, err := InspectBinary(found)
	if err != nil {
		return "", Version{}, err
	}
	return found, version, nil
}

// ClientConfig configures an installed rsync client. ConnectArgs names a local
// helper and its fixed arguments, which rsync invokes through
// RSYNC_CONNECT_PROG; it must connect only to the parent-created loopback
// bridge. ExtraEnv commonly carries the private bridge address and capability
// token.
type ClientConfig struct {
	Binary      string
	Args        []string
	Direction   Direction
	ConnectArgs []string
	ExtraEnv    []string
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
}

// Client builds and runs rsync without shell evaluation. It preserves argument
// boundaries and standard stream behavior.
type Client struct {
	config ClientConfig
	flavor BinaryFlavor
}

const helperArgumentEnvPrefix = "SP2P_INTERNAL_RSYNC_HELPER_ARG_"

// NewClient validates a client invocation before it is started.
func NewClient(config ClientConfig) (*Client, error) {
	if config.Binary == "" {
		return nil, errors.New("rsync binary path is empty")
	}
	if len(config.ConnectArgs) == 0 || config.ConnectArgs[0] == "" {
		return nil, errors.New("rsync connection helper is empty")
	}
	for _, arg := range config.ConnectArgs {
		if strings.ContainsRune(arg, '\x00') {
			return nil, errors.New("rsync connection helper contains a NUL byte")
		}
	}
	if err := ValidateClientArgs(config.Args, config.Direction); err != nil {
		return nil, err
	}
	version, err := InspectBinary(config.Binary)
	if err != nil {
		return nil, err
	}
	return &Client{config: config, flavor: version.Flavor}, nil
}

// Command constructs the child command and its clean connection environment.
func (c *Client) Command() *exec.Cmd {
	args := c.config.Args
	connectProgramEnv := connectProgramFromEnvironment(len(c.config.ConnectArgs))
	forcedEnv := helperArgumentEnvironment(c.config.ConnectArgs)
	if c.flavor == FlavorOpenRsync {
		// openrsync has no RSYNC_CONNECT_PROG. Its -e hook still applies to
		// daemon/module syntax, passing fixed rsync server arguments after our
		// helper; the helper ignores them and only bridges its authenticated
		// local connection. User-supplied argument boundaries remain intact.
		args = append([]string{"-e", connectProgram(c.config.ConnectArgs)}, args...)
		connectProgramEnv = ""
		forcedEnv = nil
	}
	command := exec.Command(c.config.Binary, args...)
	command.Stdin = c.config.Stdin
	command.Stdout = c.config.Stdout
	command.Stderr = c.config.Stderr
	command.Env = clientEnvironmentWithForced(connectProgramEnv, c.config.ExtraEnv, forcedEnv)
	configureProcessGroup(command)
	return command
}

// Run starts rsync and reaps its process group on cancellation. rsync's normal
// *exec.ExitError is returned unchanged so callers can preserve its exit code.
func (c *Client) Run(ctx context.Context) error {
	command := c.Command()
	if err := command.Start(); err != nil {
		return fmt.Errorf("start rsync: %w", err)
	}
	return waitCommand(ctx, command)
}

func clientEnvironment(connectProgram string, extra []string) []string {
	return clientEnvironmentWithForced(connectProgram, extra, nil)
}

func clientEnvironmentWithForced(connectProgram string, extra, forced []string) []string {
	env := make([]string, 0, len(os.Environ())+len(extra)+1)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if protectedEnvironmentName(name) {
			continue
		}
		env = append(env, entry)
	}
	// Add caller entries first so the forced connection program remains final.
	for _, entry := range extra {
		name, _, found := strings.Cut(entry, "=")
		if !found || name == "" || strings.Contains(name, "=") || protectedEnvironmentName(name) {
			continue
		}
		replaceEnvironment(&env, name, entry)
	}
	if connectProgram != "" {
		env = append(env, "RSYNC_CONNECT_PROG="+connectProgram)
	}
	env = append(env, forced...)
	return env
}

func protectedEnvironmentName(name string) bool {
	return name == "RSYNC_CONNECT_PROG" || name == "RSYNC_RSH" || name == "RSYNC_SHELL" || name == "RSYNC_PROXY" || strings.HasPrefix(name, helperArgumentEnvPrefix)
}

func replaceEnvironment(env *[]string, name, entry string) {
	for index, existing := range *env {
		existingName, _, _ := strings.Cut(existing, "=")
		if existingName == name {
			(*env)[index] = entry
			return
		}
	}
	*env = append(*env, entry)
}

func connectProgram(args []string) string {
	quoted := make([]string, len(args))
	for index, arg := range args {
		quoted[index] = shellQuote(arg)
	}
	return strings.Join(quoted, " ")
}

// connectProgramFromEnvironment keeps helper argument bytes out of the
// RSYNC_CONNECT_PROG command text. Older rsync releases do not all perform
// percent expansion alike, while the shell expands these fixed variable names
// consistently without reparsing their values.
func connectProgramFromEnvironment(count int) string {
	words := make([]string, count)
	for index := range words {
		words[index] = `"${` + helperArgumentEnvName(index) + `}"`
	}
	return strings.Join(words, " ")
}

func helperArgumentEnvironment(args []string) []string {
	env := make([]string, len(args))
	for index, arg := range args {
		env[index] = helperArgumentEnvName(index) + "=" + arg
	}
	return env
}

func helperArgumentEnvName(index int) string {
	return helperArgumentEnvPrefix + strconv.Itoa(index)
}

// shellQuote makes one OpenRsync -e command-line word. Its local rsh parser
// receives a string, so passing an argument array alone is not sufficient for
// paths containing whitespace or shell metacharacters.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// ValidateClientArgs rejects remote-shell flags and requires exactly one fixed
// daemon operand, sp2p::share. Upload has it as the destination; download has
// it as the source. This prevents an rsync client from bypassing the local
// connection helper or selecting another daemon/module.
func ValidateClientArgs(args []string, direction Direction) error {
	if direction != Upload && direction != Download {
		return fmt.Errorf("unknown rsync direction %q", direction)
	}
	if len(args) < 2 {
		return errors.New("rsync needs source and destination operands")
	}
	operands, err := rsyncOperands(args)
	if err != nil {
		return err
	}
	remote := -1
	for index, arg := range operands {
		if strings.Contains(arg, "::") {
			if remote != -1 {
				return errors.New("rsync invocation must contain exactly one SP2P daemon operand")
			}
			if !isShareOperand(arg) {
				return fmt.Errorf("rsync daemon operand must use sp2p::share, got %q", arg)
			}
			remote = index
		}
	}
	if remote == -1 {
		return errors.New("rsync invocation must contain a sp2p::share daemon operand")
	}
	if direction == Upload && remote != len(operands)-1 {
		return errors.New("rsync upload must use sp2p::share as its destination")
	}
	if direction == Download && remote != 0 {
		return errors.New("rsync download must use sp2p::share as its source")
	}
	return nil
}

func rsyncOperands(args []string) ([]string, error) {
	var operands []string
	endOptions := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if endOptions {
			operands = append(operands, arg)
			continue
		}
		if arg == "--" {
			endOptions = true
			continue
		}
		if strings.HasPrefix(arg, "--") && arg != "--" {
			name, hasValue := arg, strings.Contains(arg, "=")
			if position := strings.IndexByte(name, '='); position >= 0 {
				name = name[:position]
			}
			switch name {
			case "--rsh", "--rsync-path", "--daemon", "--config", "--dparam", "--detach", "--no-detach", "--server", "--sender", "--receiver", "--remote-option", "--old-d", "--read-batch", "--write-batch", "--only-write-batch":
				return nil, fmt.Errorf("rsync option %s is not supported with SP2P daemon mode", name)
			}
			if longOptionTakesValue(name) && !hasValue {
				if index+1 == len(args) {
					return nil, fmt.Errorf("rsync option %s needs an argument", name)
				}
				index++
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			consumeNext, err := shortOptionInfo(arg)
			if err != nil {
				return nil, err
			}
			if consumeNext {
				if index+1 == len(args) {
					return nil, fmt.Errorf("rsync option %s needs an argument", arg)
				}
				index++
			}
			continue
		}
		operands = append(operands, arg)
	}
	if len(operands) < 2 {
		return nil, errors.New("rsync needs source and destination operands")
	}
	return operands, nil
}

func shortOptionInfo(arg string) (bool, error) {
	shortFlags := strings.TrimPrefix(arg, "-")
	for index := 0; index < len(shortFlags); index++ {
		flag := shortFlags[index]
		if flag == 'e' || flag == 'M' {
			return false, errors.New("rsync remote-shell/remote options are not supported; use daemon syntax sp2p::share")
		}
		if flag == 'f' || flag == 'T' || flag == 'B' || flag == '@' {
			// The rest of this short argument is the value, not more flags
			// (for example -T/tmp/cache or -f'- *.exe').
			return index == len(shortFlags)-1, nil
		}
	}
	return false, nil
}

func longOptionTakesValue(name string) bool {
	switch name {
	// Keep this in sync with the value-taking client options in rsync's
	// long_options table. Both --option=value and --option value are valid,
	// including on older OpenRsync installations.
	case "--address", "--backup-dir", "--block-size", "--bwlimit",
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
		"--usermap", "--zc", "--zl", "--zt":
		return true
	default:
		return false
	}
}

func isShareOperand(arg string) bool {
	if !strings.HasPrefix(arg, "sp2p::share") {
		return false
	}
	rest := strings.TrimPrefix(arg, "sp2p::share")
	return rest == "" || strings.HasPrefix(rest, "/")
}

// ServeOptions controls the deliberately small, private daemon configuration.
type ServeOptions struct {
	Binary      string
	Writable    bool
	AllowDelete bool
	TempDir     string
	Stderr      io.Writer
}

// Serve starts a one-use rsync daemon rooted at directory. It is intended to
// run only after the caller completed its authenticated service handshake.
func Serve(ctx context.Context, stream Stream, directory string, options ServeOptions) error {
	if options.Binary == "" {
		return errors.New("rsync binary path is empty")
	}
	version, err := InspectBinary(options.Binary)
	if err != nil {
		return err
	}
	configPath, cleanup, err := daemonConfig(ctx, directory, options)
	if err != nil {
		return err
	}
	defer cleanup()
	return serveSocketDaemon(ctx, stream, options, configPath, version.Flavor)
}

func serveSocketDaemon(ctx context.Context, stream Stream, options ServeOptions, configPath string, flavor BinaryFlavor) error {
	daemonFile, bridgeConn, err := daemonSocketPair()
	if err != nil {
		return err
	}
	defer bridgeConn.Close()
	command := exec.Command(options.Binary, "--daemon", "--no-detach", "--config="+configPath)
	if flavor == FlavorOpenRsync {
		command.Args = append(command.Args, "--log-file=/dev/stderr")
	}
	command.Stdin = daemonFile
	command.Stdout = daemonFile
	command.Stderr = options.Stderr
	// Openrsync assigns copy-unsafe-links an internal option value above ASCII.
	// In a non-C locale, isprint can classify that byte as a short option and
	// bypass the daemon's configured long-option refusal. The daemon protocol
	// itself is byte-oriented, so pinning its parsing locale does not alter
	// transferred file names.
	command.Env = daemonEnvironment()
	configureProcessGroup(command)
	if err := command.Start(); err != nil {
		_ = daemonFile.Close()
		return fmt.Errorf("start rsync daemon: %w", err)
	}
	if err := daemonFile.Close(); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return fmt.Errorf("close rsync daemon socket: %w", err)
	}
	bridgeDone := make(chan error, 1)
	go func() { bridgeDone <- tunnel.Bridge(ctx, stream, bridgeConn) }()
	processDone := make(chan error, 1)
	go func() { processDone <- waitCommand(ctx, command) }()
	var waitErr, bridgeErr error
	select {
	case waitErr = <-processDone:
		if waitErr != nil {
			// A failed daemon cannot produce a graceful EOF. Closing the local
			// bridge unblocks its stream worker so the caller can publish the
			// failure rather than waiting for its overall context deadline.
			_ = bridgeConn.Close()
			<-bridgeDone
			return waitErr
		}
		// The daemon's socket closes on process exit. Let Bridge drain that
		// EOF and emit its directional FIN before closing our peer copy.
		bridgeErr = <-bridgeDone
	case bridgeErr = <-bridgeDone:
		_ = bridgeConn.Close()
		waitErr = <-processDone
	}
	if waitErr != nil {
		return waitErr
	}
	if bridgeErr != nil && !errors.Is(bridgeErr, net.ErrClosed) {
		return fmt.Errorf("bridge rsync daemon: %w", bridgeErr)
	}
	return nil
}

func daemonEnvironment() []string {
	env := append([]string(nil), os.Environ()...)
	replaceEnvironment(&env, "LC_ALL", "LC_ALL=C")
	return env
}

func daemonConfig(ctx context.Context, directory string, options ServeOptions) (string, func() error, error) {
	abs, err := ValidateDirectory(ctx, directory)
	if err != nil {
		return "", nil, err
	}
	file, err := os.CreateTemp(options.TempDir, "sp2p-rsync-*.conf")
	if err != nil {
		return "", nil, fmt.Errorf("create rsync config: %w", err)
	}
	path := file.Name()
	cleanup := func() error { return os.Remove(path) }
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = cleanup()
		return "", nil, fmt.Errorf("protect rsync config: %w", err)
	}
	config := makeDaemonConfig(abs, options.Writable, options.AllowDelete)
	if _, err := io.Copy(file, bytes.NewBufferString(config)); err != nil {
		_ = file.Close()
		_ = cleanup()
		return "", nil, fmt.Errorf("write rsync config: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = cleanup()
		return "", nil, fmt.Errorf("close rsync config: %w", err)
	}
	return path, cleanup, nil
}

// ValidateDirectory returns the canonical module root after validating it for
// one-use daemon serving. It follows a user-selected root symlink under that
// user's authority, but rejects nested directory symlinks because rsync daemon
// subpath requests can otherwise escape the module root. This is not an OS
// sandbox: callers must not allow concurrent untrusted tree modification.
func ValidateDirectory(ctx context.Context, directory string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if directory == "" {
		return "", errors.New("rsync module directory is empty")
	}
	abs, err := filepath.Abs(directory)
	if err != nil {
		return "", fmt.Errorf("resolve rsync module path: %w", err)
	}
	if err := validateConfigPath(abs); err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve rsync module symlinks: %w", err)
	}
	if err := validateConfigPath(canonical); err != nil {
		return "", err
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("inspect rsync module path: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("rsync module path is not a directory")
	}
	if err := rejectDirectorySymlinks(ctx, canonical); err != nil {
		return "", err
	}
	return canonical, nil
}

func validateConfigPath(path string) error {
	// rsyncd.conf performs percent expansion, trims surrounding whitespace, and
	// permits backslash continuations; none is appropriate for a path supplied
	// as one fixed config value.
	if strings.TrimSpace(path) != path || strings.ContainsAny(path, "\x00\r\n%\\") {
		return errors.New("rsync module path contains a config control character")
	}
	return nil
}

func rejectDirectorySymlinks(ctx context.Context, root string) error {
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink == 0 {
			return nil
		}
		target, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			// A dangling symlink cannot be used to enter another directory and
			// is presented as a munged link by the daemon.
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect symlink %q: %w", path, err)
		}
		if target.IsDir() {
			return fmt.Errorf("rsync module contains directory symlink %q; directory symlinks are unsupported", path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("validate rsync module symlinks: %w", err)
	}
	return nil
}

func makeDaemonConfig(path string, writable, allowDelete bool) string {
	var config strings.Builder
	config.WriteString("[share]\n")
	config.WriteString("path = ")
	config.WriteString(path)
	config.WriteString("\nlist = false\nuse chroot = false\nmunge symlinks = true\n")
	uid, gid := effectiveIdentity()
	if uid != "" && gid != "" {
		config.WriteString("uid = ")
		config.WriteString(uid)
		config.WriteString("\ngid = ")
		config.WriteString(gid)
		config.WriteByte('\n')
	}
	// Keep ordinary (munged) symlink transfer available, but reject every
	// option which would dereference a link while walking the module tree.
	// Openrsync's daemon option parser only matches its long spellings against
	// the short client flags when the option has no backing state field. List
	// both forms so -L, -k, and -K cannot bypass these restrictions.
	refused := []string{"copy-links", "copy-dirlinks", "copy-unsafe-links", "keep-dirlinks", "L", "k", "K"}
	if writable {
		config.WriteString("read only = false\nwrite only = true\n")
		if !allowDelete {
			refused = append(refused, "delete", "delete-before", "delete-during", "delete-delay", "delete-after", "delete-excluded", "delete-missing-args")
		}
	} else {
		config.WriteString("read only = true\nwrite only = false\n")
		// A read-only module can still be the sending side. Both spellings
		// request that the sender unlink each file after transmission, which
		// older Apple openrsync permits unless the daemon refuses them.
		refused = append(refused, "remove-source-files", "remove-sent-files")
	}
	config.WriteString("refuse options = ")
	config.WriteString(strings.Join(refused, " "))
	config.WriteByte('\n')
	return config.String()
}
