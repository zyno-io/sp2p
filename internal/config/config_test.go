// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected no error for missing config, got: %v", err)
	}
	if cfg.Server != "" {
		t.Errorf("expected empty server, got %q", cfg.Server)
	}
	if cfg.Compress != nil {
		t.Errorf("expected nil compress, got %v", *cfg.Compress)
	}
}

func TestLoadValidConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	configDir := filepath.Join(dir, "sp2p")
	os.MkdirAll(configDir, 0o755)
	os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(`
server: https://example.com
url: https://example.com
compress: 5
allow-relay: true
output: /tmp/downloads
verbose: true
`), 0o644)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server != "https://example.com" {
		t.Errorf("server = %q, want %q", cfg.Server, "https://example.com")
	}
	if cfg.URL != "https://example.com" {
		t.Errorf("url = %q, want %q", cfg.URL, "https://example.com")
	}
	if cfg.Compress == nil || *cfg.Compress != 5 {
		t.Errorf("compress = %v, want 5", cfg.Compress)
	}
	if !cfg.AllowRelay {
		t.Error("allow-relay = false, want true")
	}
	if cfg.Output != "/tmp/downloads" {
		t.Errorf("output = %q, want %q", cfg.Output, "/tmp/downloads")
	}
	if !cfg.Verbose {
		t.Error("verbose = false, want true")
	}
}

func TestLoadCompressZero(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	configDir := filepath.Join(dir, "sp2p")
	os.MkdirAll(configDir, 0o755)
	os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(`compress: 0`), 0o644)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Compress == nil {
		t.Fatal("compress should not be nil when explicitly set to 0")
	}
	if *cfg.Compress != 0 {
		t.Errorf("compress = %d, want 0", *cfg.Compress)
	}
}

func TestLoadMalformedConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	configDir := filepath.Join(dir, "sp2p")
	os.MkdirAll(configDir, 0o755)
	os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(`{{{not yaml`), 0o644)

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for malformed config")
	}
}

func TestLoadTildeExpansion(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	configDir := filepath.Join(dir, "sp2p")
	os.MkdirAll(configDir, 0o755)
	os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(`output: ~/Downloads`), 0o644)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	home, _ := os.UserHomeDir()
	want := filepath.Join(home, "Downloads")
	if cfg.Output != want {
		t.Errorf("output = %q, want %q", cfg.Output, want)
	}
}

func TestLoadUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	configDir := filepath.Join(dir, "sp2p")
	os.MkdirAll(configDir, 0o755)
	os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(`
server: https://example.com
unknown_key: oops
`), 0o644)

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for unknown config key")
	}
}

func TestLoadCompressOutOfRange(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"negative", "compress: -1"},
		{"too high", "compress: 10"},
		{"way too high", "compress: 100"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", dir)

			configDir := filepath.Join(dir, "sp2p")
			os.MkdirAll(configDir, 0o755)
			os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(tt.value), 0o644)

			_, err := Load()
			if err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
		})
	}
}

func TestExpandHome(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		input string
		want  string
	}{
		{"~/Downloads", filepath.Join(home, "Downloads")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
		{"~", "~"}, // no slash after ~, not expanded
		{"", ""},
	}
	for _, tt := range tests {
		got := expandHome(tt.input)
		if got != tt.want {
			t.Errorf("expandHome(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
