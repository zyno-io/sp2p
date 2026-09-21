// SPDX-License-Identifier: MIT

//go:build !windows

package rsync

import (
	"os"
	"strconv"
)

func effectiveIdentity() (string, string) {
	return identityForEffectiveIDs(os.Geteuid(), os.Getegid())
}

func identityForEffectiveIDs(uid, gid int) (string, string) {
	if uid != 0 {
		return "", ""
	}
	return strconv.Itoa(uid), strconv.Itoa(gid)
}
