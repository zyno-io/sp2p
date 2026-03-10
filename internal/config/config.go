// SPDX-License-Identifier: MIT

// Package config loads user configuration from a YAML file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds user-level defaults loaded from the config file.
type Config struct {
	Server     string `yaml:"server"`
	URL        string `yaml:"url"`
	Compress   *int   `yaml:"compress"`
	Transport  string `yaml:"transport"`
	AllowRelay bool   `yaml:"allow-relay"`
	Output     string `yaml:"output"`
	Verbose    bool   `yaml:"verbose"`
	Parallel   *int   `yaml:"parallel"` // parallel TCP connections: 0=auto (RTT-based), 1=single, 2-6=force count
}

// Load reads configuration from $XDG_CONFIG_HOME/sp2p/config.yaml
// (defaulting to ~/.config/sp2p/config.yaml). If the file does not
// exist, a zero-value Config is returned with no error. An error is
// returned only if the file exists but cannot be read or parsed.
func Load() (Config, error) {
	path := filepath.Join(configDir(), "sp2p", "config.yaml")

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parsing %s: %w", path, err)
	}

	// Validate compress range.
	if cfg.Compress != nil && (*cfg.Compress < 0 || *cfg.Compress > 9) {
		return Config{}, fmt.Errorf("parsing %s: compress must be 0-9, got %d", path, *cfg.Compress)
	}

	// Validate parallel range.
	if cfg.Parallel != nil && (*cfg.Parallel < 0 || *cfg.Parallel > 6) {
		return Config{}, fmt.Errorf("parsing %s: parallel must be 0-6, got %d", path, *cfg.Parallel)
	}

	// Validate transport if specified.
	switch cfg.Transport {
	case "", "auto", "tcp", "webrtc":
		// valid
	default:
		return Config{}, fmt.Errorf("parsing %s: transport must be auto, tcp, or webrtc, got %q", path, cfg.Transport)
	}

	// Expand ~ in output path.
	if cfg.Output != "" {
		cfg.Output = expandHome(cfg.Output)
	}

	return cfg, nil
}

// configDir returns XDG_CONFIG_HOME or ~/.config as a fallback.
func configDir() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config")
}

// expandHome replaces a leading "~/" with the user's home directory.
func expandHome(path string) string {
	if len(path) < 2 || path[:2] != "~/" {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}
