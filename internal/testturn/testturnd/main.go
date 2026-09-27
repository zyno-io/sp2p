// SPDX-License-Identifier: MIT

// Command testturnd runs a minimal, CI-only TURN relay server (see the
// parent internal/testturn package) used by web/tests/relay.spec.ts to
// prove real relay-only WebRTC transfers end-to-end.
//
// This is a deliberate exception to the repo's flat internal/ package
// layout (see AGENTS.md, CLAUDE.md's "Packages are flat within internal/"):
// it lives nested under internal/testturn instead of under cmd/, because it
// is CI test tooling built directly by CI workflows
// (go build ./internal/testturn/testturnd), never by the Makefile or
// .goreleaser.yaml, and it sits next to the only library it wraps.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pion/logging"
	"github.com/zyno-io/sp2p/internal/testturn"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// run parses flags, starts the TURN server, and blocks until a clean
// shutdown signal (or, with -exit-with-parent, until the parent process
// changes -- orphan protection for a daemon left behind by a killed test
// worker). Exit codes: 2 for a usage error, 1 for a startup/runtime error,
// 0 for a clean shutdown.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("testturnd", flag.ContinueOnError)
	fs.SetOutput(stderr)

	listenAddr := fs.String("listen", "10.99.0.1:3478", "UDP address to listen on for STUN/TURN control traffic")
	relayIPFlag := fs.String("relay-ip", "", "IPv4 address advertised for relay allocations (default: the host portion of -listen)")
	minPort := fs.Uint("min-port", 31000, "minimum relay UDP port (inclusive)")
	maxPort := fs.Uint("max-port", 31127, "maximum relay UDP port (inclusive)")
	realm := fs.String("realm", "sp2p.test", "TURN realm")
	secret := fs.String("secret", os.Getenv("SP2P_TESTTURN_SECRET"), "TURN REST shared secret (env: SP2P_TESTTURN_SECRET)")
	userQuota := fs.Int("user-quota", 0, "maximum live allocations per TURN userID -- i.e. per sp2p session, shared by both peers (0 = unlimited)")
	statsPath := fs.String("stats", "", "path to atomically-written stats.json (required)")
	logLevel := fs.String("log-level", "disabled", "pion/turn log level: disabled|error|warn|info|debug|trace (never this package's own accounting; debug/trace log full TURN usernames -- i.e. sp2p session IDs -- local debugging only, never CI)")
	exitWithParent := fs.Bool("exit-with-parent", false, "exit cleanly once the parent process changes (orphan protection)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *statsPath == "" {
		fmt.Fprintln(stderr, "testturnd: -stats is required")
		return 2
	}
	if *secret == "" {
		fmt.Fprintln(stderr, "testturnd: -secret (or SP2P_TESTTURN_SECRET) is required")
		return 2
	}
	if *minPort == 0 || *minPort > 65535 || *maxPort == 0 || *maxPort > 65535 {
		fmt.Fprintln(stderr, "testturnd: -min-port/-max-port must be in 1-65535")
		return 2
	}
	level, err := parseLogLevel(*logLevel)
	if err != nil {
		fmt.Fprintf(stderr, "testturnd: %v\n", err)
		return 2
	}

	relayIPStr := *relayIPFlag
	if relayIPStr == "" {
		host, _, err := net.SplitHostPort(*listenAddr)
		if err != nil {
			fmt.Fprintf(stderr, "testturnd: cannot derive -relay-ip from -listen %q: %v\n", *listenAddr, err)
			return 2
		}
		relayIPStr = host
	}
	relayIP := net.ParseIP(relayIPStr)
	if relayIP == nil {
		fmt.Fprintf(stderr, "testturnd: invalid relay IP %q\n", relayIPStr)
		return 2
	}

	srv, err := testturn.New(testturn.Config{
		ListenAddr: *listenAddr,
		RelayIP:    relayIP,
		MinPort:    uint16(*minPort),
		MaxPort:    uint16(*maxPort),
		Realm:      *realm,
		Secret:     *secret,
		UserQuota:  *userQuota,
		StatsPath:  *statsPath,
		LogLevel:   level,
	})
	if err != nil {
		fmt.Fprintf(stderr, "testturnd: %v\n", err)
		return 1
	}
	defer srv.Close()

	// No secret, and no session identifier of any kind, in this line.
	fmt.Fprintf(stdout, "testturnd ready listen=%s relay=%s:%d-%d quota=%d\n", *listenAddr, relayIP.String(), *minPort, *maxPort, *userQuota)

	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *exitWithParent {
		go watchParent(sigCtx, stop)
	}

	<-sigCtx.Done()
	return 0
}

// watchParent stops ctx once the process's parent PID changes, which
// happens when the original parent (e.g. a Playwright worker) exits and
// this process is reparented (typically to PID 1). Without this, a killed
// test worker could leave testturnd running and holding the TURN port
// across later runs.
func watchParent(ctx context.Context, stop context.CancelFunc) {
	initialParent := os.Getppid()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if os.Getppid() != initialParent {
				stop()
				return
			}
		}
	}
}

func parseLogLevel(s string) (logging.LogLevel, error) {
	switch strings.ToLower(s) {
	case "disabled", "disable", "":
		return logging.LogLevelDisabled, nil
	case "error":
		return logging.LogLevelError, nil
	case "warn":
		return logging.LogLevelWarn, nil
	case "info":
		return logging.LogLevelInfo, nil
	case "debug":
		return logging.LogLevelDebug, nil
	case "trace":
		return logging.LogLevelTrace, nil
	default:
		return 0, fmt.Errorf("invalid -log-level %q (want disabled|error|warn|info|debug|trace)", s)
	}
}
