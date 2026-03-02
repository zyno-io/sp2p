// SPDX-License-Identifier: MIT

package semver

import "testing"

func TestIsNewer(t *testing.T) {
	tests := []struct {
		client, server string
		want           bool
	}{
		{"1.0.0", "1.0.1", true},
		{"1.0.0", "1.1.0", true},
		{"1.0.0", "2.0.0", true},
		{"1.0.1", "1.0.0", false},
		{"1.1.0", "1.0.0", false},
		{"2.0.0", "1.0.0", false},
		{"1.0.0", "1.0.0", false},
		{"v1.0.0", "v1.0.1", true},
		{"dev", "1.0.0", false},
		{"1.0.0", "dev", false},
		{"dev", "dev", false},
		{"", "1.0.0", false},
		{"1.0.0", "", false},
		{"", "", false},
		{"1.0.0-rc1", "1.0.0", false},
		{"0.9.0", "1.0.0-rc1", true},
	}
	for _, tt := range tests {
		t.Run(tt.client+"_vs_"+tt.server, func(t *testing.T) {
			if got := IsNewer(tt.client, tt.server); got != tt.want {
				t.Errorf("IsNewer(%q, %q) = %v, want %v", tt.client, tt.server, got, tt.want)
			}
		})
	}
}
