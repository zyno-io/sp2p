// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/zyno-io/sp2p/internal/cli"
	"github.com/zyno-io/sp2p/internal/config"
)

var version = "dev"
var buildTime string     // set via ldflags (e.g., "2025-01-15T12:00:00Z")
var defaultBaseURL string // set via ldflags for release builds

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Print banner for all commands.
	if buildTime != "" {
		fmt.Fprintf(os.Stderr, "sp2p %s (%s)\n\n", version, buildTime)
	} else {
		fmt.Fprintf(os.Stderr, "sp2p %s\n\n", version)
	}

	// Handle commands that don't need config.
	switch os.Args[1] {
	case "version":
		if buildTime != "" {
			fmt.Printf("sp2p %s (%s)\n", version, buildTime)
		} else {
			fmt.Printf("sp2p %s\n", version)
		}
		return
	case "help", "--help", "-h":
		printUsage()
		return
	}

	// Load user config file (~/.config/sp2p/config.yaml).
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Build defaults: hardcoded < config < env.
	base := "http://localhost:8080"
	if defaultBaseURL != "" {
		base = defaultBaseURL
	}
	if cfg.Server != "" {
		base = cfg.Server
	}
	serverURL := envOr("SP2P_SERVER", base)

	baseURLDefault := ""
	if cfg.URL != "" {
		baseURLDefault = cfg.URL
	}
	baseURL := envOr("SP2P_URL", baseURLDefault)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	switch os.Args[1] {
	case "send":
		err = runSend(ctx, cfg, serverURL, baseURL)
	case "receive", "recv":
		err = runReceive(ctx, cfg, serverURL)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runSend(ctx context.Context, cfg config.Config, serverURL, baseURL string) error {
	compressDefault := 3
	if cfg.Compress != nil {
		compressDefault = *cfg.Compress
	}

	fs := flag.NewFlagSet("send", flag.ExitOnError)
	server := fs.String("server", serverURL, "signaling server URL (env: SP2P_SERVER)")
	base := fs.String("url", baseURL, "public base URL for sharing links (env: SP2P_URL)")
	name := fs.String("name", "", "filename for stdin streams")
	compress := fs.Int("compress", compressDefault, "zstd compression level (0=disabled, 1-9)")
	allowRelay := fs.Bool("allow-relay", cfg.AllowRelay, "allow TURN relay without prompting")
	verbose := fs.Bool("v", cfg.Verbose, "verbose diagnostic output")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: sp2p send [flags] <file|folder|...|->\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(reorderArgs(fs, os.Args[2:]))

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	if *compress < 0 || *compress > 9 {
		return fmt.Errorf("compress must be 0-9, got %d", *compress)
	}

	// If no explicit base URL, derive from the server URL.
	shareBase := *base
	if shareBase == "" {
		shareBase = deriveBaseURL(*server)
	}

	return cli.Send(ctx, cli.SendConfig{
		ServerURL:     deriveWSURL(*server),
		BaseURL:       shareBase,
		Paths:         fs.Args(),
		Name:          *name,
		CompressLevel: *compress,
		RelayOK:       *allowRelay,
		Verbose:       *verbose,
		ClientVersion: version,
	})
}

func runReceive(ctx context.Context, cfg config.Config, serverURL string) error {
	outputDefault := "."
	if cfg.Output != "" {
		outputDefault = cfg.Output
	}

	fs := flag.NewFlagSet("receive", flag.ExitOnError)
	server := fs.String("server", serverURL, "signaling server URL (env: SP2P_SERVER)")
	outputDir := fs.String("output", outputDefault, "output directory")
	stdout := fs.Bool("stdout", false, "write to stdout instead of file")
	allowRelay := fs.Bool("allow-relay", cfg.AllowRelay, "allow TURN relay without prompting")
	verbose := fs.Bool("v", cfg.Verbose, "verbose diagnostic output")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: sp2p receive [flags] <CODE>\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(reorderArgs(fs, os.Args[2:]))

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	return cli.Receive(ctx, cli.ReceiveConfig{
		ServerURL:     deriveWSURL(*server),
		Code:          fs.Arg(0),
		OutputDir:     *outputDir,
		Stdout:        *stdout,
		RelayOK:       *allowRelay,
		Verbose:       *verbose,
		ClientVersion: version,
	})
}

func printUsage() {
	base := "http://localhost:8080"
	if defaultBaseURL != "" {
		base = defaultBaseURL
	}
	fmt.Fprintf(os.Stderr, `SP2P — Secure P2P File Transfer (v%s)

Usage:
  sp2p send [flags] <file|folder|...|-  Send file(s), folder, or stdin
  sp2p receive [flags] <CODE>            Receive a file
  sp2p version                           Show version

Environment variables:
  SP2P_SERVER   Signaling server URL            (default: %s)
  SP2P_URL      Public base URL for share links (default: %s)

Run 'sp2p <command> --help' for flag details.
`, version, base, base)
}

// deriveWSURL converts a base URL to its WebSocket equivalent,
// appending /ws unless the URL already has a ws(s):// scheme
// (indicating the caller provided an explicit WebSocket URL).
func deriveWSURL(base string) string {
	if strings.HasPrefix(base, "ws://") || strings.HasPrefix(base, "wss://") {
		return base
	}
	ws := strings.Replace(base, "https://", "wss://", 1)
	ws = strings.Replace(ws, "http://", "ws://", 1)
	return ws + "/ws"
}

// deriveBaseURL converts a server URL (which may be ws(s)://) back to http(s)://.
func deriveBaseURL(serverURL string) string {
	base := strings.Replace(serverURL, "wss://", "https://", 1)
	base = strings.Replace(base, "ws://", "http://", 1)
	return strings.TrimSuffix(base, "/ws")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// reorderArgs moves flags (arguments starting with "-") before positional
// arguments so that Go's flag package parses them regardless of order.
// For example: ["file.txt", "-server", "ws://..."] becomes ["-server", "ws://...", "file.txt"].
// It uses the FlagSet to determine which flags are boolean (take no value).
func reorderArgs(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}

		// Handle -flag=value and --flag=value (value is embedded, no next arg consumed).
		name := strings.TrimLeft(arg, "-")
		if eqIdx := strings.Index(name, "="); eqIdx >= 0 {
			flags = append(flags, arg)
			continue
		}

		flags = append(flags, arg)

		// Check if this is a boolean flag (doesn't consume next arg).
		if f := fs.Lookup(name); f != nil {
			if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
				continue
			}
		}

		// Non-boolean flag: consume the next argument as its value.
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return append(flags, positional...)
}
