// SPDX-License-Identifier: MIT

//go:build !windows

package rsync

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWaitCommandKillsDescendantAfterLeaderExits(t *testing.T) {
	pidFile := t.TempDir() + "/child-pid"
	command := exec.Command("sh", "-c", "(trap '' TERM; sleep 30) & child=$!; echo $child > \"$1\"; wait $child", "sh", pidFile)
	configureProcessGroup(command)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(pidFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child pid file was not created")
		}
		time.Sleep(10 * time.Millisecond)
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitCommand(ctx, command); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitCommand() = %v, want context cancellation", err)
	}
	deadline = time.Now().Add(time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) || processIsZombie(pid) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child process %d survived group cleanup: %v", pid, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func processIsZombie(pid int) bool {
	output, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	return err == nil && strings.HasPrefix(strings.TrimSpace(string(output)), "Z")
}
