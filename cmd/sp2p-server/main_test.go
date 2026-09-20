// SPDX-License-Identifier: MIT

package main

import "testing"

func TestTrustProxyEnvironmentBoolean(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{{"", false}, {"true", true}, {"1", true}, {"false", false}, {"0", false}, {"invalid", false}} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("SP2P_TRUST_PROXY", tc.value)
			if got := envBool("SP2P_TRUST_PROXY"); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
