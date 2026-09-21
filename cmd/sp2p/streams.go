// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/zyno-io/sp2p/internal/cli"
	"github.com/zyno-io/sp2p/internal/config"
)

type streamFlags struct {
	server, transport, format, events, status *string
	relay, verbose                            *bool
}

func addStreamFlags(fs *flag.FlagSet, cfg config.Config, serverURL string) streamFlags {
	transport := cfg.Transport
	if transport == "" {
		transport = "auto"
	}
	return streamFlags{
		server:    fs.String("server", serverURL, "signaling server URL (env: SP2P_SERVER)"),
		transport: fs.String("transport", transport, "connection method: auto, tcp, webrtc"),
		format:    fs.String("format", "human", "output format: human or json"),
		events:    fs.String("event-output", "stdout", "JSON events: stdout or stderr (stdio requires stderr)"),
		status:    fs.String("status-file", "", "private JSON status snapshot (requires -format json)"),
		relay:     fs.Bool("allow-relay", cfg.AllowRelay, "allow encrypted TURN relay without prompting"),
		verbose:   fs.Bool("v", cfg.Verbose, "verbose diagnostic output"),
	}
}

func (f streamFlags) config(stdio bool) (cli.StreamConfig, error) {
	output, err := cli.NewOutputConfig(*f.format, *f.events, *f.status, stdio)
	if err != nil {
		return cli.StreamConfig{}, err
	}
	transport, err := parseTransport(*f.transport)
	if err != nil {
		return cli.StreamConfig{Output: output}, err
	}
	return cli.StreamConfig{ServerURL: deriveWSURL(*f.server), Transport: transport,
		ClientVersion: version, RelayOK: *f.relay, Verbose: *f.verbose, Output: output}, nil
}

func newStreamFlagSet(name string, args []string, usage string) (*flag.FlagSet, func()) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	machine, events := requestedMachineOutput(args)
	if machine {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(os.Stderr)
	}
	showUsage := func(w io.Writer) {
		fs.SetOutput(w)
		fmt.Fprintln(w, usage)
		fs.PrintDefaults()
	}
	fs.Usage = func() {
		if !machine {
			showUsage(os.Stderr)
		}
	}
	return fs, func() {
		if machine {
			var help strings.Builder
			showUsage(&help)
			service, role, _ := strings.Cut(name, " ")
			cli.EmitStreamHelp(machineEventWriter(events), service, role, help.String())
		}
	}
}

func showStreamHelp(service string, args []string, usage string) {
	machine, events := requestedMachineOutput(args)
	if machine {
		cli.EmitStreamHelp(machineEventWriter(events), service, "help", usage)
		return
	}
	fmt.Fprintln(os.Stderr, usage)
}

func streamCommandFailure(output cli.OutputConfig, service, role string, client bool, err error) error {
	mode := role
	if service == "rsync" {
		mode += "-daemon"
		if client {
			mode = role + "-client"
		}
	}
	return cli.ReportStreamFailure(output, service, role, mode, err)
}

func runTunnel(ctx context.Context, cfg config.Config, serverURL string) error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: sp2p tunnel serve|connect [flags]")
	}
	role := os.Args[2]
	if role == "--help" || role == "-h" || role == "help" {
		showStreamHelp("tunnel", os.Args[3:], "Usage: sp2p tunnel serve --to tcp://HOST:PORT|unix:///PATH (or --stdio)\n       sp2p tunnel connect --listen tcp://HOST:PORT|unix:///PATH CODE (or --stdio CODE)\nOne accepted connection per code; TCP listeners must specify an address (loopback recommended).")
		return nil
	}
	if role != "serve" && role != "connect" {
		return fmt.Errorf("tunnel role must be serve or connect")
	}
	args := os.Args[3:]
	fs, onHelp := newStreamFlagSet("tunnel "+role, args, "Usage: sp2p tunnel "+role+" [flags] [CODE]\nOne connection per code; stdout is payload with --stdio.")
	f := addStreamFlags(fs, cfg, serverURL)
	to := fs.String("to", "", "provider's fixed target: tcp://HOST:PORT or unix:///PATH")
	listen := fs.String("listen", "", "local listener: tcp://HOST:PORT or unix:///PATH")
	stdio := fs.Bool("stdio", false, "bridge stdin/stdout instead of a socket")
	timeout := fs.Duration("accept-timeout", 5*time.Minute, "maximum wait for the local socket client")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			onHelp()
			return nil
		}
		return err
	}
	c, err := f.config(*stdio)
	if err != nil {
		return streamCommandFailure(c.Output, "tunnel", role, false, err)
	}
	if role == "serve" && fs.NArg() != 0 {
		return streamCommandFailure(c.Output, "tunnel", role, false, fmt.Errorf("tunnel serve takes no code"))
	}
	if role == "connect" {
		if fs.NArg() != 1 {
			return streamCommandFailure(c.Output, "tunnel", role, false, fmt.Errorf("tunnel connect requires a code"))
		}
		c.Code = fs.Arg(0)
	}
	return cli.Tunnel(ctx, cli.TunnelConfig{StreamConfig: c, Create: role == "serve", Target: *to, Listen: *listen, Stdio: *stdio, AcceptTimeout: *timeout})
}

// splitRsyncArgs leaves rsync's argument boundaries and ordering untouched.
func splitRsyncArgs(args []string) (options, forwarded []string, client bool) {
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:], true
		}
	}
	return args, nil, false
}

func runRsync(ctx context.Context, cfg config.Config, serverURL string) error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: sp2p rsync send|recv [flags]")
	}
	role := os.Args[2]
	if role == "--help" || role == "-h" || role == "help" {
		showStreamHelp("rsync", os.Args[3:], "Usage: sp2p rsync send [flags] -- RSYNC_ARGS\n       sp2p rsync recv [flags] CODE DIRECTORY\n       sp2p rsync send [flags] DIRECTORY\n       sp2p rsync recv [flags] CODE -- RSYNC_ARGS\nThe sender always creates the code. Use sp2p::share/ as the remote rsync operand.")
		return nil
	}
	if role != "send" && role != "recv" {
		return fmt.Errorf("rsync role must be send or recv")
	}
	options, forwarded, client := splitRsyncArgs(os.Args[3:])
	commandUsage := "sp2p rsync " + role + " [flags]"
	if role == "recv" {
		commandUsage += " CODE"
	}
	fs, onHelp := newStreamFlagSet("rsync "+role, options, "Usage: "+commandUsage+" DIRECTORY\n   or: "+commandUsage+" -- RSYNC_ARGS\nOnly recv takes CODE; send always creates it. Uses installed rsync, including macOS's built-in rsync.")
	f := addStreamFlags(fs, cfg, serverURL)
	binary := fs.String("rsync-binary", "rsync", "path to the installed rsync executable")
	allowDelete := fs.Bool("allow-delete", false, "allow deletion within a receiver's shared directory")
	if err := fs.Parse(reorderArgs(fs, options)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			onHelp()
			return nil
		}
		return err
	}
	c, err := f.config(false)
	if err != nil {
		return streamCommandFailure(c.Output, "rsync", role, client, err)
	}
	args := fs.Args()
	if role == "recv" {
		if len(args) == 0 {
			return streamCommandFailure(c.Output, "rsync", role, client, fmt.Errorf("rsync recv requires a code"))
		}
		c.Code, args = args[0], args[1:]
	}
	directory := ""
	if client {
		if len(args) != 0 || len(forwarded) == 0 {
			return streamCommandFailure(c.Output, "rsync", role, client, fmt.Errorf("supply rsync arguments after --; only recv takes a code before it"))
		}
	} else {
		if len(args) != 1 {
			return streamCommandFailure(c.Output, "rsync", role, client, fmt.Errorf("a local directory is required, or supply rsync arguments after --"))
		}
		directory = args[0]
	}
	if *allowDelete && (role != "recv" || client) {
		return streamCommandFailure(c.Output, "rsync", role, client, fmt.Errorf("--allow-delete applies only to rsync recv CODE DIRECTORY"))
	}
	return cli.Rsync(ctx, cli.RsyncConfig{StreamConfig: c, Send: role == "send", Client: client, Directory: directory, Args: forwarded, Binary: *binary, AllowDelete: *allowDelete})
}
