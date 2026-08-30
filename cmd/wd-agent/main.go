package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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
	"strings"
	"syscall"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/appdirs"
	"wedecent.com/wedecent/internal/buildinfo"
	"wedecent.com/wedecent/internal/discovery"
	"wedecent.com/wedecent/internal/enrollment"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/relayauth"
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
	case "version":
		err = buildinfo.Write(os.Stdout, "wd-agent")
	case "enrollment-proof":
		err = runEnrollmentProof(os.Args[2:])
	case "service":
		err = runServiceCommand(os.Args[2:])
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

func runEnrollmentProof(args []string) error {
	state, _ := appdirs.Agent()
	fs := flag.NewFlagSet("enrollment-proof", flag.ContinueOnError)
	stateDir := fs.String("state", state, "agent state directory")
	name := fs.String("name", hostname(), "device display name")
	request := fs.Bool("request", false, "print an enrollment challenge request instead of signing a challenge")
	challengeFile := fs.String("challenge-file", "", "enrollment challenge JSON file to sign")
	kind := fs.String("kind", "agent", "device kind: client, agent, or hybrid")
	organizationID := fs.String("organization-id", "", "optional organization UUID")
	challengeID := fs.String("challenge-id", "", "challenge UUID returned by the enrollment service")
	challenge := fs.String("challenge", "", "base64url enrollment challenge")
	userID := fs.String("user-id", "", "Supabase Auth user UUID returned by the enrollment service")
	expiresUnixMS := fs.Int64("expires-unix-ms", 0, "challenge expiry in Unix milliseconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd-agent enrollment-proof [--request | --challenge-file path | challenge flags]")
	}
	if *request && strings.TrimSpace(*challengeFile) != "" {
		return errors.New("--request and --challenge-file are mutually exclusive")
	}

	id, err := identity.Ensure(*stateDir, *name)
	if err != nil {
		return err
	}
	pub := base64.RawURLEncoding.EncodeToString(id.PublicKey)

	if *request {
		payload := map[string]any{
			"action":     "challenge",
			"device_id":  id.ID,
			"public_key": pub,
			"kind":       *kind,
			"name":       id.Name,
		}
		if *organizationID != "" {
			payload["organization_id"] = *organizationID
		}
		return writeJSON(payload)
	}

	if challengePath := strings.TrimSpace(*challengeFile); challengePath != "" {
		if strings.TrimSpace(*challengeID) != "" || strings.TrimSpace(*challenge) != "" || strings.TrimSpace(*userID) != "" || *expiresUnixMS != 0 {
			return errors.New("--challenge-file cannot be combined with manual challenge fields")
		}
		info, err := os.Stat(challengePath)
		if err != nil {
			return fmt.Errorf("stat enrollment challenge file: %w", err)
		}
		if info.IsDir() {
			return errors.New("enrollment challenge path is a directory")
		}
		if info.Size() <= 0 || info.Size() > 64*1024 {
			return errors.New("enrollment challenge file must contain between 1 byte and 64 KiB")
		}
		data, err := os.ReadFile(challengePath)
		if err != nil {
			return fmt.Errorf("read enrollment challenge file: %w", err)
		}
		var received account.EnrollmentChallenge
		if err := json.Unmarshal(data, &received); err != nil {
			return fmt.Errorf("decode enrollment challenge file: %w", err)
		}
		if received.Action != "challenge" {
			return errors.New("enrollment challenge file has an invalid action")
		}
		if received.DeviceID != id.ID || received.PublicKey != pub || received.Name != id.Name {
			return errors.New("enrollment challenge does not match this agent identity")
		}
		switch received.Kind {
		case "client", "agent", "hybrid":
		default:
			return errors.New("enrollment challenge has an invalid device kind")
		}
		if received.Kind != strings.TrimSpace(*kind) {
			return errors.New("enrollment challenge kind does not match the requested device kind")
		}
		if received.ChallengeID == "" || received.Challenge == "" || received.UserID == "" || received.ExpiresUnixMS <= 0 {
			return errors.New("enrollment challenge is missing required metadata")
		}
		*kind = received.Kind
		*organizationID = received.OrganizationID
		*challengeID = received.ChallengeID
		*challenge = received.Challenge
		*userID = received.UserID
		*expiresUnixMS = received.ExpiresUnixMS
	}

	msg, err := enrollment.Message(enrollment.ProofFields{
		ChallengeID:    *challengeID,
		Challenge:      *challenge,
		UserID:         *userID,
		DeviceID:       id.ID,
		PublicKey:      pub,
		Kind:           *kind,
		OrganizationID: *organizationID,
		ExpiresUnixMS:  *expiresUnixMS,
	})
	if err != nil {
		return err
	}
	sig := ed25519.Sign(id.PrivateKey, msg)
	payload := map[string]any{
		"action":          "complete",
		"challenge_id":    *challengeID,
		"challenge":       *challenge,
		"device_id":       id.ID,
		"public_key":      pub,
		"kind":            *kind,
		"name":            id.Name,
		"expires_unix_ms": *expiresUnixMS,
		"signature":       base64.RawURLEncoding.EncodeToString(sig),
	}
	if *organizationID != "" {
		payload["organization_id"] = *organizationID
	}
	return writeJSON(payload)
}

func writeJSON(value any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

type serveConfig struct {
	StateDir        string
	Name            string
	ListenAddr      string
	Shell           string
	Discover        bool
	MaxConnections  int
	RelayAddr       string
	WebRelay        string
	RelaySlots      int
	RelayCA         string
	RelayServerName string
}

func parseServeConfig(args []string) (serveConfig, error) {
	state, _ := appdirs.Agent()
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfg := serveConfig{}
	fs.StringVar(&cfg.StateDir, "state", state, "agent state directory")
	fs.StringVar(&cfg.Name, "name", hostname(), "device display name")
	fs.StringVar(&cfg.ListenAddr, "listen", "127.0.0.1:7443", "TCP listen address; empty disables inbound TCP")
	fs.StringVar(&cfg.Shell, "shell", defaultShell(), "absolute shell path")
	fs.BoolVar(&cfg.Discover, "discover", false, "advertise on the local IPv4 multicast network")
	fs.IntVar(&cfg.MaxConnections, "max-connections", 32, "maximum concurrent direct client connections")
	fs.StringVar(&cfg.RelayAddr, "relay", "", "legacy outbound TCP relay address, e.g. relay.wedecent.com:443")
	fs.StringVar(&cfg.WebRelay, "web-relay", "", "serverless WebSocket relay URL, e.g. https://relay.wedecent.com")
	fs.IntVar(&cfg.RelaySlots, "relay-slots", 4, "number of parked outbound relay connections")
	fs.StringVar(&cfg.RelayCA, "relay-ca", "", "optional PEM CA bundle for a private/dev relay")
	fs.StringVar(&cfg.RelayServerName, "relay-server-name", "", "optional TLS server-name override for the relay")
	if err := fs.Parse(args); err != nil {
		return serveConfig{}, err
	}
	if cfg.MaxConnections < 1 || cfg.MaxConnections > 1024 {
		return serveConfig{}, errors.New("max-connections must be between 1 and 1024")
	}
	if cfg.RelaySlots < 1 || cfg.RelaySlots > 32 {
		return serveConfig{}, errors.New("relay-slots must be between 1 and 32")
	}
	if cfg.ListenAddr == "" && cfg.RelayAddr == "" && cfg.WebRelay == "" {
		return serveConfig{}, errors.New("at least one of --listen, --relay, or --web-relay must be configured")
	}
	if cfg.Discover && cfg.ListenAddr == "" {
		return serveConfig{}, errors.New("--discover requires a direct --listen address")
	}
	return cfg, nil
}

func runServe(args []string) error {
	cfg, err := parseServeConfig(args)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runAgent(ctx, cfg)
}

func runAgent(ctx context.Context, cfg serveConfig) error {
	id, err := identity.Ensure(cfg.StateDir, cfg.Name)
	if err != nil {
		return err
	}
	store, err := trust.Open(filepath.Join(cfg.StateDir, "trusted-clients.json"))
	if err != nil {
		return err
	}
	server := &session.Server{Identity: id, Trust: store, StateDir: cfg.StateDir, Shell: cfg.Shell, Logger: slog.Default()}

	fp, _ := identity.FingerprintPublicKey(id.PublicKey)
	fmt.Printf("WeDecent agent %s (%s)\n", id.Name, id.ID)
	fmt.Printf("Fingerprint: %s\n", fp)

	if cfg.RelayAddr != "" {
		relayOpts := transport.RelayOptions{CAFile: cfg.RelayCA, ServerName: cfg.RelayServerName, Timeout: 10 * time.Second}
		fmt.Printf("Relay:       %s (%d outbound slots)\n", cfg.RelayAddr, cfg.RelaySlots)
		for i := 0; i < cfg.RelaySlots; i++ {
			go relayLoop(ctx, i+1, cfg.RelayAddr, relayOpts, id, server)
		}
	}

	if cfg.WebRelay != "" {
		webOpts := transport.WebRelayOptions{
			TicketSource:      relayauth.NewTicketSource(id),
			Timeout:           15 * time.Second,
			KeepAliveInterval: 30 * time.Second,
		}
		fmt.Printf("Web relay:   %s (%d outbound WSS slots)\n", cfg.WebRelay, cfg.RelaySlots)
		for i := 0; i < cfg.RelaySlots; i++ {
			go webRelayLoop(ctx, i+1, cfg.WebRelay, webOpts, id, server)
		}
	}

	if cfg.ListenAddr == "" {
		<-ctx.Done()
		return nil
	}

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	fmt.Printf("Listening:   %s\n", ln.Addr())

	if cfg.Discover {
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

	sem := make(chan struct{}, cfg.MaxConnections)
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
		conn, err := transport.WaitWebRelaySession(ctx, baseURL, opts, id.ID, slot)
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
  version          Print build and release metadata
  enrollment-proof Print or sign a cryptographic device-enrollment request
  pairing-secret   Rotate and print a one-time pairing secret
  serve            Run the terminal agent (direct, relay, or both)
  service          Install and manage the native Windows service`)
}
