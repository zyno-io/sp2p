// SPDX-License-Identifier: MIT

package main

import (
	"flag"
	"strings"
	"testing"
)

func TestDeriveWSURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"http to ws", "http://localhost:8080", "ws://localhost:8080/ws"},
		{"https to wss", "https://sp2p.io", "wss://sp2p.io/ws"},
		{"ws passthrough", "ws://localhost:8080/ws", "ws://localhost:8080/ws"},
		{"wss passthrough", "wss://sp2p.io/ws", "wss://sp2p.io/ws"},
		{"ws custom path passthrough", "ws://relay.example.com:9090/custom", "ws://relay.example.com:9090/custom"},
		{"https with path", "https://sp2p.io/prefix", "wss://sp2p.io/prefix/ws"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveWSURL(tt.in); got != tt.want {
				t.Errorf("deriveWSURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDeriveBaseURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ws to http", "ws://localhost:8080/ws", "http://localhost:8080"},
		{"wss to https", "wss://sp2p.io/ws", "https://sp2p.io"},
		{"http passthrough", "http://localhost:8080", "http://localhost:8080"},
		{"https passthrough", "https://sp2p.io", "https://sp2p.io"},
		{"wss no /ws suffix", "wss://relay.example.com:9090", "https://relay.example.com:9090"},
		{"ws with trailing /ws", "ws://10.0.0.5:8080/ws", "http://10.0.0.5:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveBaseURL(tt.in); got != tt.want {
				t.Errorf("deriveBaseURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDeriveWSURL_RoundTrip(t *testing.T) {
	// Verify that deriveBaseURL(deriveWSURL(url)) returns the original URL
	// for standard http(s) inputs.
	urls := []string{
		"http://localhost:8080",
		"https://sp2p.io",
		"http://10.0.0.5:9090",
	}
	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			if got := deriveBaseURL(deriveWSURL(u)); got != u {
				t.Errorf("round-trip failed: %q -> deriveWSURL -> %q -> deriveBaseURL -> %q", u, deriveWSURL(u), got)
			}
		})
	}
}

func TestReorderArgs(t *testing.T) {
	// Create a FlagSet matching the send command flags.
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("server", "", "")
	fs.String("url", "", "")
	fs.String("name", "", "")
	fs.Int("compress", 3, "")
	fs.Bool("allow-relay", false, "")
	fs.Bool("v", false, "")

	tests := []struct {
		name string
		args []string
		want string // space-joined result
	}{
		{
			"flags before positional",
			[]string{"-server", "ws://example.com", "file.txt"},
			"-server ws://example.com file.txt",
		},
		{
			"positional before flags",
			[]string{"file.txt", "-server", "ws://example.com"},
			"-server ws://example.com file.txt",
		},
		{
			"boolean flag with positional",
			[]string{"file.txt", "-allow-relay"},
			"-allow-relay file.txt",
		},
		{
			"double dash boolean",
			[]string{"file.txt", "--allow-relay"},
			"--allow-relay file.txt",
		},
		{
			"flag=value syntax",
			[]string{"file.txt", "-server=ws://example.com"},
			"-server=ws://example.com file.txt",
		},
		{
			"boolean flag=value",
			[]string{"file.txt", "-allow-relay=true"},
			"-allow-relay=true file.txt",
		},
		{
			"mixed flags and positionals",
			[]string{"a.txt", "-v", "b.txt", "-server", "ws://x", "c.txt"},
			"-v -server ws://x a.txt b.txt c.txt",
		},
		{
			"no args",
			[]string{},
			"",
		},
		{
			"only positional",
			[]string{"a.txt", "b.txt"},
			"a.txt b.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(reorderArgs(fs, tt.args), " ")
			if got != tt.want {
				t.Errorf("reorderArgs(%v) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}
