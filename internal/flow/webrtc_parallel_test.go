// SPDX-License-Identifier: MIT

package flow

import (
	"strings"
	"testing"
)

func TestWebRTCSetupControlBoundsAndOrdering(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  byte
		data  string
		valid bool
	}{
		{"valid", webRTCParallelMessage, `{"step":"ready","mask":14}`, true},
		{"wrong type", 2, `{"step":"ready"}`, false},
		{"wrong step", webRTCParallelMessage, `{"step":"commit"}`, false},
		{"malformed", webRTCParallelMessage, `{`, false},
		{"null", webRTCParallelMessage, `null`, false},
		{"negative mask", webRTCParallelMessage, `{"step":"ready","mask":-1}`, false},
		{"overflow mask", webRTCParallelMessage, `{"step":"ready","mask":4294967296}`, false},
		{"fractional mask", webRTCParallelMessage, `{"step":"ready","mask":2.5}`, false},
		{"oversize", webRTCParallelMessage, `{"step":"ready","extra":"` + strings.Repeat("x", 16*1024) + `"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseWebRTCParallelControl(tc.kind, []byte(tc.data), "ready")
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
