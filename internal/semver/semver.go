// SPDX-License-Identifier: MIT

package semver

import (
	"fmt"
	"strconv"
	"strings"
)

// version holds parsed semver components.
type version struct {
	major, minor, patch int
}

// parse extracts major.minor.patch from a version string, stripping any leading "v".
// Returns false if the string is empty, "dev", or otherwise unparseable.
func parse(s string) (version, bool) {
	s = strings.TrimPrefix(s, "v")
	if s == "" || s == "dev" {
		return version{}, false
	}
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return version{}, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return version{}, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return version{}, false
	}
	// Strip pre-release suffix (e.g. "0-rc1").
	patchStr := strings.SplitN(parts[2], "-", 2)[0]
	patch, err := strconv.Atoi(patchStr)
	if err != nil {
		return version{}, false
	}
	return version{major, minor, patch}, true
}

// IsNewer reports whether the server version is strictly newer than the client version.
// Returns false if either version is empty, "dev", or unparseable.
func IsNewer(client, server string) bool {
	c, cok := parse(client)
	s, sok := parse(server)
	if !cok || !sok {
		return false
	}
	if s.major != c.major {
		return s.major > c.major
	}
	if s.minor != c.minor {
		return s.minor > c.minor
	}
	return s.patch > c.patch
}

// Format returns "vMAJOR.MINOR.PATCH" for display, or the original string if unparseable.
func Format(s string) string {
	v, ok := parse(s)
	if !ok {
		return s
	}
	return fmt.Sprintf("v%d.%d.%d", v.major, v.minor, v.patch)
}
