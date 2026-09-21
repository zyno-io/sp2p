// SPDX-License-Identifier: MIT

//go:build !windows

package tunnel

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestListenUnixRestrictsPermissiveUmask(t *testing.T) {
	if os.Getenv("SP2P_TEST_PERMISSIVE_UMASK") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestListenUnixRestrictsPermissiveUmask$")
		cmd.Env = append(os.Environ(), "SP2P_TEST_PERMISSIVE_UMASK=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("umask subprocess: %v\n%s", err, output)
		}
		return
	}

	originalUmask := unix.Umask(0)
	defer unix.Umask(originalUmask)

	dir, err := os.MkdirTemp("/tmp", "sp2p-umask-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "listener.sock")
	listener, err := listenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got&0o077 != 0 {
		t.Fatalf("socket permissions = %04o, want no group or other access", got)
	}
	if got := unix.Umask(0); got != 0 {
		t.Fatalf("umask after listenUnix = %04o, want 0000", got)
	}
}
