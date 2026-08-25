package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"wedecent.com/wedecent/internal/appdirs"
	"wedecent.com/wedecent/internal/discovery"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/session"
	"wedecent.com/wedecent/internal/transport"
	"wedecent.com/wedecent/internal/trust"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = runInit(os.Args[2:])
	case "pairing-secret":
		err = runPairingSecret(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "identity":
		err = runIdentity(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "wd-agent:", err)
		os.Exit(1)
	}
}

func runInit(args []string) error {
	state, _ := appdirs.Agent()
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	stateDir := fs.String("state", state, "agent state directory")
	name := fs.String("name", hostname(), "device display name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := identity.Ensure(*stateDir, *name)
	if err != nil {
		return err
	}
	if _, err := trust.Open(filepath.Join(*stateDir, "trusted-clients.json")); err != nil {
		return err
	}
	secret, err := trust.RotatePairingSecret(*stateDir)
	if err != nil {
		return err
	}
	fp, _ := identity.FingerprintPublicKey(id.PublicKey)
	fmt.Printf("Device ID:    %s\n", id.ID)
	fmt.Printf("Device name:  %s\n", id.Name)
	fmt.Printf("Fingerprint:  %s\n", fp)
	fmt.Printf("Pair secret:  %s\n", secret)
	fmt.Println("\nThe pair secret is single-use. Keep it private.")
	return nil
}

func runPairingSecret(args []string) error {
	state, _ := appdirs.Agent()
	fs := flag.NewFlagSet("pairing-secret", flag.ContinueOnError)
	stateDir := fs.String("state", state, "agent state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	secret, err := trust.RotatePairingSecret(*stateDir)
	if err != nil {
		return err
	}
	fmt.Println(secret)
	return nil
}

func runIdentity(args []string) error {
	state, _ := appdirs.Agent()
	fs := flag.NewFlagSet("identity", flag.ContinueOnError)
	stateDir := fs.String("state", state, "agent state directory")
	name := fs.String("name", hostname(), "device display name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := identity.Ensure(*stateDir, *name)
	if err != nil {
		return err
	}
	fp, _ := identity.FingerprintPublicKey(id.PublicKey)
	fmt.Printf("%s\t%s\t%s\n", id.ID, id.Name, fp)
	return nil
}

func runServe(args []string) error {
	state, _ := appdirs.Agent()
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	stateDir := fs.String("state", state, "agent state directory")
	name := fs.String("name", hostname(), "device display name")
	listenAddr := fs.String("listen", "127.0.0.1:7443", "TCP listen address; empty disables inbound TCP")
	shell := fs.String("shell", defaultShell(), "absolute shell path")
	discover := fs.Bool("discover", false, "advertise on the local IPv4 multicast network")
	maxConnections := fs.Int("max-connections", 32, "maximum concurrent direct client connections")
	relayAddr := fs.String("relay", "", "legacy outbound TCP relay address, e.g. relay.wedecent.com:443")
	webRelay := fs.String("web-relay", "", "serverless WebSocket relay URL, e.g. https://relay.wedecent.com")
	relaySlots := fs.Int("relay-slots", 4, "number of parked outbound relay connections")
	relayCA := fs.String("relay-ca", "", "optional PEM CA bundle for a private/dev relay")
	relayServerName := fs.String("relay-server-name", "", "optional TLS server-name override for the relay")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *maxConnections < 1 || *maxConnections > 1024 {
		return errors.New("max-connections must be between 1 and 1024")
	}
	if *relaySlots < 1 || *relaySlots > 32 {
		return errors.New("relay-slots must be between 1 and 32")
	}
	if *listenAddr == "" && *relayAddr == "" && *webRelay == "" {
		return errors.New("at least one of --listen, --relay, or --web-relay must be configured")
	}
	if *discover && *listenAddr == "" {
		return errors.New("--discover requires a direct --listen address")
	}

	id, err := identity.Ensure(*stateDir, *name)
	if err != nil {
		return err
	}
	store, err := trust.Open(filepath.Join(*stateDir, "trusted-clients.json"))
	if err != nil {
		return err
	}
	server := &session.Server{Identity: id, Trust: store, StateDir: *stateDir, Shell: *shell, Logger: slog.Default()}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fp, _ := identity.FingerprintPublicKey(id.PublicKey)
	fmt.Printf("WeDecent agent %s (%s)\n", id.Name, id.ID)
	fmt.Printf("Fingerprint: %s\n", fp)

	if *relayAddr != "" {
		relayOpts := transport.RelayOptions{CAFile: *relayCA, ServerName: *relayServerName, Timeout: 10 * time.Second}
		fmt.Printf("Relay:       %s (%d outbound slots)\n", *relayAddr, *relaySlots)
		for i := 0; i < *relaySlots; i++ {
			go relayLoop(ctx, i+1, *relayAddr, relayOpts, id, server)
		}
	}

	if *webRelay != "" {
		webOpts := transport.WebRelayOptions{Token: os.Getenv("WEDECENT_RELAY_TOKEN"), Timeout: 15 * time.Second, KeepAliveInterval: 30 * time.Second}
		fmt.Printf("Web relay:   %s (%d outbound WSS slots)\n", *webRelay, *relaySlots)
		for i := 0; i < *relaySlots; i++ {
			go webRelayLoop(ctx, i+1, *webRelay, webOpts, id, server)
		}
	}

	if *listenAddr == "" {
		<-ctx.Done()
		return nil
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	fmt.Printf("Listening:   %s\n", ln.Addr())

	if *discover {
		port, err := listenerPort(ln.Addr())
		if err != nil {
			return err
		}
		go func() {
			if err := discovery.Advertise(ctx, id, port); err != nil && ctx.Err() == nil {
				slog.Error("LAN discovery stopped", "error", err)
			}
		}()
	}

	sem := make(chan struct{}, *maxConnections)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				server.ServeConn(conn)
			}()
		default:
			_ = conn.Close()
			slog.Warn("connection limit reached", "remote", conn.RemoteAddr())
		}
	}
}

func webRelayLoop(ctx context.Context, slot int, baseURL string, opts transport.WebRelayOptions, id *identity.Identity, server *session.Server) {
	backoff := time.Second
	for ctx.Err() == nil {
		conn, err := transport.WaitWebRelaySession(ctx, baseURL, opts, id.ID)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("web relay slot disconnected", "slot", slot, "error", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		slog.Info("web relay slot parked", "slot", slot, "remote", conn.RemoteAddr())
		server.ServeParkedRelayConn(conn)
	}
}

func relayLoop(ctx context.Context, slot int, address string, opts transport.RelayOptions, id *identity.Identity, server *session.Server) {
	backoff := time.Second
	for ctx.Err() == nil {
		conn, err := transport.WaitRelaySession(ctx, address, opts, id)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("relay slot disconnected", "slot", slot, "error", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		server.ServeConn(conn)
	}
}

func listenerPort(addr net.Addr) (int, error) {
	_, portString, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(portString)
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "wedecent-device"
	}
	return h
}

func defaultShell() string {
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	}
	if shell := os.Getenv("SHELL"); shell != "" && len(shell) > 0 && shell[0] == '/' {
		return shell
	}
	return "/bin/sh"
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: wd-agent <command> [options]

Commands:
  init             Create identity and one-time pairing secret
  identity         Print device ID and fingerprint
  pairing-secret   Rotate and print a one-time pairing secret
  serve            Run the terminal agent (direct, relay, or both)`)
}
