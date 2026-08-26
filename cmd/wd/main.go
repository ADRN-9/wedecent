package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/appdirs"
	"wedecent.com/wedecent/internal/discovery"
	"wedecent.com/wedecent/internal/enrollment"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/relayauth"
	"wedecent.com/wedecent/internal/session"
	"wedecent.com/wedecent/internal/terminal"
	"wedecent.com/wedecent/internal/transport"
	"wedecent.com/wedecent/internal/trust"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var code int
	var err error
	switch os.Args[1] {
	case "init":
		err = runInit(os.Args[2:])
	case "identity":
		err = runIdentity(os.Args[2:])
	case "account":
		err = runAccount(os.Args[2:])
	case "enrollment-proof":
		err = runEnrollmentProof(os.Args[2:])
	case "discover":
		err = runDiscover(os.Args[2:])
	case "devices":
		err = runDevices(os.Args[2:])
	case "pair":
		err = runPair(os.Args[2:])
	case "connect":
		code, err = runConnect(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "wd:", err)
		os.Exit(1)
	}
	if code != 0 {
		if code < 0 || code > 255 {
			code = 255
		}
		os.Exit(code)
	}
}

func runInit(args []string) error {
	state, _ := appdirs.Client()
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	name := fs.String("name", hostname(), "client display name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := identity.Ensure(*stateDir, *name)
	if err != nil {
		return err
	}
	if _, err := trust.Open(filepath.Join(*stateDir, "trusted-devices.json")); err != nil {
		return err
	}
	fp, _ := identity.FingerprintPublicKey(id.PublicKey)
	fmt.Printf("Client ID:   %s\n", id.ID)
	fmt.Printf("Client name: %s\n", id.Name)
	fmt.Printf("Fingerprint: %s\n", fp)
	return nil
}

func runIdentity(args []string) error {
	state, _ := appdirs.Client()
	fs := flag.NewFlagSet("identity", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	name := fs.String("name", hostname(), "client display name")
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

func runAccount(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: wd account <login|status|logout> [options]")
	}
	switch args[0] {
	case "login":
		return runAccountLogin(args[1:])
	case "status":
		return runAccountStatus(args[1:])
	case "logout":
		return runAccountLogout(args[1:])
	default:
		return fmt.Errorf("unknown account command %q; use login, status, or logout", args[0])
	}
}

func runAccountLogin(args []string) error {
	state, err := appdirs.Client()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("account login", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	supabaseURL := fs.String("supabase-url", strings.TrimSpace(os.Getenv("WEDECENT_SUPABASE_URL")), "Supabase project URL (or WEDECENT_SUPABASE_URL)")
	publishableKey := fs.String("publishable-key", strings.TrimSpace(os.Getenv("WEDECENT_SUPABASE_PUBLISHABLE_KEY")), "Supabase publishable key (or WEDECENT_SUPABASE_PUBLISHABLE_KEY)")
	email := fs.String("email", strings.TrimSpace(os.Getenv("WEDECENT_ACCOUNT_EMAIL")), "account email (or WEDECENT_ACCOUNT_EMAIL)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd account login [--email address]")
	}
	if strings.TrimSpace(*supabaseURL) == "" {
		return errors.New("Supabase URL is required; set WEDECENT_SUPABASE_URL or use --supabase-url")
	}
	if strings.TrimSpace(*publishableKey) == "" {
		return errors.New("Supabase publishable key is required; set WEDECENT_SUPABASE_PUBLISHABLE_KEY or use --publishable-key")
	}
	if strings.TrimSpace(*email) == "" {
		return errors.New("account email is required; set WEDECENT_ACCOUNT_EMAIL or use --email")
	}

	password, err := readAccountPassword()
	if err != nil {
		return err
	}
	defer func() { password = "" }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accountClient := account.Client{}
	session, err := accountClient.Login(ctx, *supabaseURL, *publishableKey, *email, password)
	if err != nil {
		return err
	}
	if err := account.Save(account.SessionPath(*stateDir), session); err != nil {
		return err
	}
	fmt.Printf("Signed in as %s (%s)\n", session.Email, session.UserID)
	return nil
}

func runAccountStatus(args []string) error {
	state, err := appdirs.Client()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("account status", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd account status")
	}

	path := account.SessionPath(*stateDir)
	session, err := account.Load(path)
	if errors.Is(err, account.ErrNoSession) {
		fmt.Println("Signed in: no")
		return nil
	}
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accountClient := account.Client{}
	session, refreshed, err := accountClient.EnsureFresh(ctx, session, 2*time.Minute)
	if err != nil {
		return err
	}
	if refreshed {
		if err := account.Save(path, session); err != nil {
			return err
		}
	}
	user, err := accountClient.VerifyUser(ctx, session)
	if err != nil {
		return err
	}
	if session.UserID != "" && user.ID != session.UserID {
		return errors.New("Supabase session user does not match the stored account")
	}
	if user.Email != "" && user.Email != session.Email {
		session.Email = user.Email
		if err := account.Save(path, session); err != nil {
			return err
		}
	}

	fmt.Println("Signed in: yes")
	fmt.Printf("Email: %s\n", session.Email)
	fmt.Printf("User ID: %s\n", user.ID)
	fmt.Printf("Access token expires: %s\n", time.Unix(session.ExpiresAt, 0).UTC().Format(time.RFC3339))
	return nil
}

func runAccountLogout(args []string) error {
	state, err := appdirs.Client()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("account logout", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd account logout")
	}

	path := account.SessionPath(*stateDir)
	session, err := account.Load(path)
	if errors.Is(err, account.ErrNoSession) {
		fmt.Println("Signed in: no")
		return nil
	}
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accountClient := account.Client{}
	fresh, _, refreshErr := accountClient.EnsureFresh(ctx, session, 0)
	var remoteErr error
	if refreshErr != nil {
		remoteErr = refreshErr
	} else {
		remoteErr = accountClient.Logout(ctx, fresh)
	}
	if err := account.Delete(path); err != nil {
		return err
	}
	if remoteErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: local account session removed, but remote logout failed: %v\n", remoteErr)
	} else {
		fmt.Println("Signed out")
	}
	return nil
}

func readAccountPassword() (string, error) {
	fmt.Fprint(os.Stderr, "Supabase password: ")
	tty, err := openPasswordTTY()
	if err != nil {
		return "", err
	}
	password, readErr := terminal.ReadPassword(tty)
	closeErr := tty.Close()
	fmt.Fprintln(os.Stderr)
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if password == "" {
		return "", errors.New("account password is empty")
	}
	return password, nil
}

func openPasswordTTY() (*os.File, error) {
	for _, path := range []string{"/dev/tty", "CONIN$"} {
		if tty, err := os.OpenFile(path, os.O_RDWR, 0); err == nil {
			return tty, nil
		}
	}
	return nil, errors.New("no interactive terminal is available for secure password entry")
}

func runEnrollmentProof(args []string) error {
	state, _ := appdirs.Client()
	fs := flag.NewFlagSet("enrollment-proof", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	name := fs.String("name", hostname(), "client display name")
	request := fs.Bool("request", false, "print an enrollment challenge request instead of signing a challenge")
	kind := fs.String("kind", "client", "device kind: client, agent, or hybrid")
	organizationID := fs.String("organization-id", "", "optional organization UUID")
	challengeID := fs.String("challenge-id", "", "challenge UUID returned by the enrollment service")
	challenge := fs.String("challenge", "", "base64url enrollment challenge")
	userID := fs.String("user-id", "", "Supabase Auth user UUID returned by the enrollment service")
	expiresUnixMS := fs.Int64("expires-unix-ms", 0, "challenge expiry in Unix milliseconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := identity.Ensure(*stateDir, *name)
	if err != nil {
		return err
	}
	pub := base64.RawURLEncoding.EncodeToString(id.PublicKey)

	if *request {
		payload := map[string]any{
			"action": "challenge", "device_id": id.ID, "public_key": pub,
			"kind": *kind, "name": id.Name,
		}
		if *organizationID != "" {
			payload["organization_id"] = *organizationID
		}
		return writeJSON(payload)
	}

	msg, err := enrollment.Message(enrollment.ProofFields{
		ChallengeID: *challengeID, Challenge: *challenge, UserID: *userID,
		DeviceID: id.ID, PublicKey: pub, Kind: *kind,
		OrganizationID: *organizationID, ExpiresUnixMS: *expiresUnixMS,
	})
	if err != nil {
		return err
	}
	payload := map[string]any{
		"action": "complete", "challenge_id": *challengeID, "challenge": *challenge,
		"device_id": id.ID, "public_key": pub, "kind": *kind, "name": id.Name,
		"expires_unix_ms": *expiresUnixMS,
		"signature":       base64.RawURLEncoding.EncodeToString(ed25519.Sign(id.PrivateKey, msg)),
	}
	if *organizationID != "" {
		payload["organization_id"] = *organizationID
	}
	return writeJSON(payload)
}

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func runDiscover(args []string) error {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 6*time.Second, "discovery duration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *timeout <= 0 || *timeout > time.Minute {
		return errors.New("timeout must be between 1ns and 1m")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	results, errs := discovery.Discover(ctx)
	for results != nil || errs != nil {
		select {
		case r, ok := <-results:
			if !ok {
				results = nil
				continue
			}
			fmt.Printf("%s\t%s\ttcp://%s\t%s\n", r.DeviceID, r.Name, r.Endpoint, r.Fingerprint)
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func runDevices(args []string) error {
	state, _ := appdirs.Client()
	fs := flag.NewFlagSet("devices", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := trust.Open(filepath.Join(*stateDir, "trusted-devices.json"))
	if err != nil {
		return err
	}
	peers := store.List()
	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
	for _, p := range peers {
		fmt.Printf("%s\t%s\t%s\t%s\n", p.ID, p.Name, p.Endpoint, p.Fingerprint)
	}
	return nil
}

func runPair(args []string) error {
	state, _ := appdirs.Client()
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	name := fs.String("name", hostname(), "client display name")
	endpoint := fs.String("endpoint", "", "direct device endpoint, e.g. 192.168.1.20:7443")
	relayAddr := fs.String("relay", "", "legacy TCP relay address, e.g. relay.wedecent.com:443")
	webRelay := fs.String("web-relay", "", "serverless WebSocket relay URL, e.g. https://relay.wedecent.com")
	deviceID := fs.String("device-id", "", "target device ID when pairing through a relay")
	fingerprint := fs.String("fingerprint", "", "expected SHA256 device public-key fingerprint")
	relayCA := fs.String("relay-ca", "", "optional PEM CA bundle for a private/dev relay")
	relayServerName := fs.String("relay-server-name", "", "optional TLS server-name override for the relay")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fingerprint == "" {
		return errors.New("--fingerprint is required; obtain it from wd discover or wd-agent identity")
	}
	selected := 0
	if *endpoint != "" {
		selected++
	}
	if *relayAddr != "" {
		selected++
	}
	if *webRelay != "" {
		selected++
	}
	if selected != 1 {
		return errors.New("specify exactly one of --endpoint, --relay, or --web-relay")
	}

	var locator string
	var err error
	if *endpoint != "" {
		locator, err = directLocator(*endpoint)
	} else {
		if *deviceID == "" {
			return errors.New("--device-id is required with a relay")
		}
		if *webRelay != "" {
			locator, err = webRelayLocator(*webRelay, *deviceID)
		} else {
			locator, err = relayLocator(*relayAddr, *deviceID)
		}
	}
	if err != nil {
		return err
	}
	fp, err := identity.ParseFingerprint(*fingerprint)
	if err != nil {
		return err
	}

	secret := os.Getenv("WEDECENT_PAIRING_SECRET")
	if secret == "" {
		fmt.Fprint(os.Stderr, "Pairing secret: ")
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return errors.New("no TTY available; set WEDECENT_PAIRING_SECRET")
		}
		secret, err = terminal.ReadPassword(tty)
		_ = tty.Close()
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
	}
	if len(secret) < 20 {
		return errors.New("pairing secret is too short")
	}

	id, err := identity.Ensure(*stateDir, *name)
	if err != nil {
		return err
	}
	store, err := trust.Open(filepath.Join(*stateDir, "trusted-devices.json"))
	if err != nil {
		return err
	}
	dialer := transport.MultiDialer{Relay: transport.RelayOptions{CAFile: *relayCA, ServerName: *relayServerName, Timeout: 10 * time.Second}, WebRelay: clientWebRelayOptions(id)}
	client := &session.Client{Identity: id, Trust: store, Dialer: dialer}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	peer, err := client.Pair(ctx, locator, fp, secret)
	if err != nil {
		return err
	}
	fmt.Printf("Paired %s (%s) via %s\n", peer.Name, peer.ID, peer.Endpoint)
	return nil
}

func runConnect(args []string) (int, error) {
	state, _ := appdirs.Client()
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	name := fs.String("name", hostname(), "client display name")
	endpoint := fs.String("endpoint", "", "override with a direct host:port")
	relayAddr := fs.String("relay", "", "override with a legacy relay host:port")
	webRelay := fs.String("web-relay", "", "override with a serverless WebSocket relay URL")
	connectionGrantFile := fs.String("connection-grant-file", "", "path to a short-lived connection grant JWT for WebSocket relay access")
	relayCA := fs.String("relay-ca", "", "optional PEM CA bundle for a private/dev relay")
	relayServerName := fs.String("relay-server-name", "", "optional TLS server-name override for the relay")
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	if fs.NArg() != 1 {
		return 0, errors.New("usage: wd connect [--endpoint host:port | --relay host:port] <device-id>")
	}
	selected := 0
	if *endpoint != "" {
		selected++
	}
	if *relayAddr != "" {
		selected++
	}
	if *webRelay != "" {
		selected++
	}
	if selected > 1 {
		return 0, errors.New("--endpoint, --relay, and --web-relay are mutually exclusive")
	}
	deviceID := fs.Arg(0)
	id, err := identity.Ensure(*stateDir, *name)
	if err != nil {
		return 0, err
	}
	store, err := trust.Open(filepath.Join(*stateDir, "trusted-devices.json"))
	if err != nil {
		return 0, err
	}
	peer, ok := store.Get(deviceID)
	if !ok {
		return 0, fmt.Errorf("device %s is not paired", deviceID)
	}
	if *endpoint != "" {
		peer.Endpoint, err = directLocator(*endpoint)
		if err != nil {
			return 0, err
		}
	} else if *relayAddr != "" {
		peer.Endpoint, err = relayLocator(*relayAddr, deviceID)
		if err != nil {
			return 0, err
		}
	} else if *webRelay != "" {
		peer.Endpoint, err = webRelayLocator(*webRelay, deviceID)
		if err != nil {
			return 0, err
		}
	}
	if peer.Endpoint == "" {
		return 0, errors.New("device has no connection locator")
	}
	connectionGrant, err := readConnectionGrantFile(*connectionGrantFile)
	if err != nil {
		return 0, err
	}
	isWebRelay := strings.HasPrefix(peer.Endpoint, "wsrelay://")
	if connectionGrant != "" && !isWebRelay {
		return 0, errors.New("--connection-grant-file is only valid for a WebSocket relay connection")
	}
	if isWebRelay && connectionGrant == "" {
		return 0, errors.New("--connection-grant-file is required for a WebSocket relay terminal connection")
	}
	dialer := transport.MultiDialer{Relay: transport.RelayOptions{CAFile: *relayCA, ServerName: *relayServerName, Timeout: 10 * time.Second}, WebRelay: clientWebRelayOptionsWithGrant(id, connectionGrant)}
	client := &session.Client{Identity: id, Trust: store, Dialer: dialer}
	return client.ConnectTerminal(context.Background(), peer, os.Stdin, os.Stdout)
}

func clientWebRelayOptions(id *identity.Identity) transport.WebRelayOptions {
	return clientWebRelayOptionsWithGrant(id, "")
}

func clientWebRelayOptionsWithGrant(id *identity.Identity, connectionGrant string) transport.WebRelayOptions {
	return transport.WebRelayOptions{
		TicketSource:    relayauth.NewTicketSource(id),
		ConnectionGrant: connectionGrant,
		Timeout:         15 * time.Second,
	}
}

func readConnectionGrantFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read connection grant file: %w", err)
	}
	if len(data) == 0 || len(data) > 16*1024 {
		return "", errors.New("connection grant file has an invalid size")
	}
	grant := strings.TrimSpace(string(data))
	if grant == "" || strings.ContainsAny(grant, "\r\n\t ") {
		return "", errors.New("connection grant file must contain exactly one JWT without embedded whitespace")
	}
	parts := strings.Split(grant, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", errors.New("connection grant file does not contain a JWT")
	}
	return grant, nil
}

func directLocator(endpoint string) (string, error) {
	hostPort, err := normalizeHostPort(strings.TrimPrefix(strings.TrimSpace(endpoint), "tcp://"))
	if err != nil {
		return "", err
	}
	return "tcp://" + hostPort, nil
}

func relayLocator(address, deviceID string) (string, error) {
	hostPort, err := normalizeHostPort(strings.TrimPrefix(strings.TrimSpace(address), "relay://"))
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(deviceID, "wd_") || len(deviceID) != 19 {
		return "", errors.New("invalid WeDecent device ID")
	}
	return (&url.URL{Scheme: "relay", Host: hostPort, Path: "/" + deviceID}).String(), nil
}

func webRelayLocator(baseURL, deviceID string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Host == "" {
		return "", errors.New("web relay must be a URL such as https://relay.wedecent.com")
	}
	if u.Scheme != "https" && u.Scheme != "wss" {
		return "", errors.New("web relay must use https or wss")
	}
	if !strings.HasPrefix(deviceID, "wd_") || len(deviceID) != 19 {
		return "", errors.New("invalid WeDecent device ID")
	}
	return (&url.URL{Scheme: "wsrelay", Host: u.Host, Path: "/" + deviceID}).String(), nil
}

func normalizeHostPort(endpoint string) (string, error) {
	host, portString, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil || strings.TrimSpace(host) == "" {
		return "", errors.New("address must be host:port (IPv6 addresses must use brackets)")
	}
	port, err := strconv.Atoi(portString)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("port must be between 1 and 65535")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "wedecent-client"
	}
	return h
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: wd <command> [options]

Commands:
  init       Create this client's identity
  identity   Print client ID and fingerprint
  account    Sign in, inspect, or sign out of the WeDecent account session
  enrollment-proof  Prove possession of this client identity for account enrollment
  discover   Find signed WeDecent LAN advertisements
  devices    List paired devices
  pair       Pair directly or through a relay
  connect    Open an interactive terminal directly or through a relay`)
}
