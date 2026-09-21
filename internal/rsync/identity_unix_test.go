// SPDX-License-Identifier: MIT

//go:build !windows

package rsync

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestDaemonConfigUsesEffectiveIdentityOnlyAsRoot(t *testing.T) {
	text := makeDaemonConfig(t.TempDir(), false, false)
	if os.Geteuid() != 0 {
		for _, forbidden := range []string{"\nuid = ", "\ngid = "} {
			if strings.Contains(text, forbidden) {
				t.Errorf("unprivileged daemon config contains %q:\n%s", forbidden, text)
			}
		}
		return
	}
	for _, required := range []string{
		"uid = " + strconv.Itoa(os.Geteuid()),
		"gid = " + strconv.Itoa(os.Getegid()),
	} {
		if !strings.Contains(text, required) {
			t.Errorf("daemon config missing %q:\n%s", required, text)
		}
	}
}

func TestIdentityForEffectiveIDs(t *testing.T) {
	if uid, gid := identityForEffectiveIDs(501, 20); uid != "" || gid != "" {
		t.Fatalf("unprivileged identity = %q, %q, want empty values", uid, gid)
	}
	if uid, gid := identityForEffectiveIDs(0, 20); uid != "0" || gid != "20" {
		t.Fatalf("root identity = %q, %q, want 0, 20", uid, gid)
	}
}
