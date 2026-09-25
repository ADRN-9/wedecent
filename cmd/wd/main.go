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
	"wedecent.com/wedecent/internal/buildinfo"
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
	case "version":
		err = buildinfo.Write(os.Stdout, "wd")
	case "account":
		err = runAccount(os.Args[2:])
	case "enrollment-proof":
		err = runEnrollmentProof(os.Args[2:])
	case "discover":
		err = runDiscover(os.Args[2:])
	case "devices":
		err = runDevices(os.Args[2:])
	case "unpair":
		err = runUnpair(os.Args[2:])
	case "pair":
		err = runPair(os.Args[2:])
	case "route-trust":
		err = runRouteTrust(os.Args[2:])
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
		return errors.New("usage: wd account <login|status|enroll|enroll-device|logout> [options]")
	}
	switch args[0] {
	case "login":
		return runAccountLogin(args[1:])
	case "status":
		return runAccountStatus(args[1:])
	case "enroll":
		return runAccountEnroll(args[1:])
	case "enroll-device":
		return runAccountEnrollDevice(args[1:])
	case "logout":
		return runAccountLogout(args[1:])
	default:
		return fmt.Errorf("unknown account command %q; use login, status, enroll, enroll-device, or logout", args[0])
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

func runAccountEnroll(args []string) error {
	state, err := appdirs.Client()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("account enroll", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	name := fs.String("name", hostname(), "client display name")
	organizationID := fs.String("organization-id", strings.TrimSpace(os.Getenv("WEDECENT_ORGANIZATION_ID")), "optional organization UUID (or WEDECENT_ORGANIZATION_ID)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd account enroll [--organization-id uuid]")
	}

	path := account.SessionPath(*stateDir)
	accountSession, err := account.Load(path)
	if errors.Is(err, account.ErrNoSession) {
		return errors.New("WeDecent account sign-in is required; run 'wd account login'")
	}
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accountClient := account.Client{}
	fresh, refreshed, err := accountClient.EnsureFresh(ctx, accountSession, 2*time.Minute)
	if err != nil {
		return err
	}
	if refreshed {
		if err := account.Save(path, fresh); err != nil {
			return err
		}
	}

	id, err := identity.Ensure(*stateDir, *name)
	if err != nil {
		return err
	}
	publicKey := base64.RawURLEncoding.EncodeToString(id.PublicKey)
	challenge, err := accountClient.RequestClientEnrollmentChallenge(ctx, fresh, id.ID, publicKey, id.Name, *organizationID)
	if err != nil {
		return err
	}

	message, err := enrollment.Message(enrollment.ProofFields{
		ChallengeID:    challenge.ChallengeID,
		Challenge:      challenge.Challenge,
		UserID:         challenge.UserID,
		DeviceID:       id.ID,
		PublicKey:      publicKey,
		Kind:           "client",
		OrganizationID: challenge.OrganizationID,
		ExpiresUnixMS:  challenge.ExpiresUnixMS,
	})
	if err != nil {
		return fmt.Errorf("build device enrollment proof: %w", err)
	}
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(id.PrivateKey, message))
	device, err := accountClient.CompleteClientEnrollment(ctx, fresh, account.DeviceEnrollmentProof{
		ChallengeID:    challenge.ChallengeID,
		Challenge:      challenge.Challenge,
		DeviceID:       id.ID,
		PublicKey:      publicKey,
		Kind:           "client",
		Name:           id.Name,
		OrganizationID: challenge.OrganizationID,
		ExpiresUnixMS:  challenge.ExpiresUnixMS,
		Signature:      signature,
	})
	if err != nil {
		return err
	}

	fmt.Printf("Enrolled %s as client", device.DeviceID)
	if device.OrganizationID != "" {
		fmt.Printf(" in organization %s", device.OrganizationID)
	}
	fmt.Println()
	return nil
}

func runAccountEnrollDevice(args []string) error {
	state, err := appdirs.Client()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("account enroll-device", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	requestFile := fs.String("request-file", "", "agent enrollment request JSON file")
	proofFile := fs.String("proof-file", "", "agent enrollment proof JSON file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd account enroll-device (--request-file path | --proof-file path)")
	}
	requestPath := strings.TrimSpace(*requestFile)
	proofPath := strings.TrimSpace(*proofFile)
	if (requestPath == "") == (proofPath == "") {
		return errors.New("specify exactly one of --request-file or --proof-file")
	}

	path := account.SessionPath(*stateDir)
	accountSession, err := account.Load(path)
	if errors.Is(err, account.ErrNoSession) {
		return errors.New("WeDecent account sign-in is required; run 'wd account login'")
	}
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accountClient := account.Client{}
	fresh, refreshed, err := accountClient.EnsureFresh(ctx, accountSession, 2*time.Minute)
	if err != nil {
		return err
	}
	if refreshed {
		if err := account.Save(path, fresh); err != nil {
			return err
		}
	}

	if requestPath != "" {
		var request account.DeviceEnrollmentRequest
		if err := readSmallJSONFile(requestPath, &request); err != nil {
			return fmt.Errorf("read device enrollment request: %w", err)
		}
		challenge, err := accountClient.RequestDeviceEnrollmentChallenge(ctx, fresh, request)
		if err != nil {
			return err
		}
		return writeJSON(challenge)
	}

	var proof account.DeviceEnrollmentProof
	if err := readSmallJSONFile(proofPath, &proof); err != nil {
		return fmt.Errorf("read device enrollment proof: %w", err)
	}
	device, err := accountClient.CompleteDeviceEnrollment(ctx, fresh, proof)
	if err != nil {
		return err
	}
	return writeJSON(map[string]any{
		"action": "complete",
		"device": device,
	})
}

func readSmallJSONFile(path string, value any) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("JSON file path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("JSON path is a directory")
	}
	if info.Size() <= 0 || info.Size() > 64*1024 {
		return errors.New("JSON file must contain between 1 byte and 64 KiB")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
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
	rfcomm := fs.String("rfcomm", "", "Linux Bluetooth RFCOMM endpoint, MAC/channel")
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
	locator, err := pairTransportLocator(*endpoint, *rfcomm, *relayAddr, *webRelay, *deviceID)
	if err != nil {
		return err
	}
	fp, err := identity.ParseFingerprint(*fingerprint)
	if err != nil {
		return err
	}

	secret, err := readPairingSecret()
	if err != nil {
		return err
	}

	id, err := identity.Ensure(*stateDir, *name)
	if err != nil {
		return err
	}
	store, err := trust.Open(filepath.Join(*stateDir, "trusted-devices.json"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pairingGrant, err := automaticPairingRelayGrant(ctx, *stateDir, id.ID, *deviceID, locator, account.Client{})
	if err != nil {
		return err
	}
	dialer := transport.MultiDialer{Relay: transport.RelayOptions{CAFile: *relayCA, ServerName: *relayServerName, Timeout: 10 * time.Second}, WebRelay: clientWebRelayOptionsWithGrant(id, pairingGrant)}
	client := &session.Client{Identity: id, Trust: store, Dialer: dialer}
	peer, err := client.Pair(ctx, locator, fp, secret)
	if err != nil {
		return err
	}
	fmt.Printf("Paired %s (%s) via %s\n", peer.Name, peer.ID, peer.Endpoint)
	return nil
}

func readPairingSecret() (string, error) {
	secret := strings.TrimSpace(os.Getenv("WEDECENT_PAIRING_SECRET"))
	if secret == "" {
		fmt.Fprint(os.Stderr, "Pairing secret: ")
		tty, err := openPasswordTTY()
		if err != nil {
			return "", errors.New("no interactive terminal is available for secure pairing-secret entry; set WEDECENT_PAIRING_SECRET only for controlled automation")
		}
		readSecret, readErr := terminal.ReadPassword(tty)
		closeErr := tty.Close()
		secret = readSecret
		fmt.Fprintln(os.Stderr)
		if readErr != nil {
			return "", readErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	if len(secret) < 20 {
		return "", errors.New("pairing secret is too short")
	}
	return secret, nil
}

func automaticPairingRelayGrant(ctx context.Context, stateDir, clientDeviceID, targetDeviceID, locator string, accountClient account.Client) (string, error) {
	if !strings.HasPrefix(locator, "wsrelay://") {
		return "", nil
	}
	grant, err := automaticConnectionGrant(ctx, stateDir, clientDeviceID, targetDeviceID, accountClient)
	if err != nil {
		return "", fmt.Errorf("authorize relay pairing: %w", err)
	}
	return grant, nil
}

func runConnect(args []string) (int, error) {
	state, _ := appdirs.Client()
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	name := fs.String("name", hostname(), "client display name")
	endpoint := fs.String("endpoint", "", "override with a direct host:port")
	rfcomm := fs.String("rfcomm", "", "override with a Linux Bluetooth RFCOMM MAC/channel")
	relayAddr := fs.String("relay", "", "override with a legacy relay host:port")
	webRelay := fs.String("web-relay", "", "override with a serverless WebSocket relay URL")
	lanTimeout := fs.Duration("lan-timeout", 1500*time.Millisecond, "trusted LAN discovery window; 0 disables automatic LAN selection")
	connectionGrantFile := fs.String("connection-grant-file", "", "path to a short-lived connection grant JWT")
	relayCA := fs.String("relay-ca", "", "optional PEM CA bundle for a private/dev relay")
	relayServerName := fs.String("relay-server-name", "", "optional TLS server-name override for the relay")
	routeRouter := fs.String("route-router", "", "explicit one-hop router device ID")
	routeFirstTransport := fs.String("route-first-transport", "", "source-to-router transport: lan or internet")
	routeSecondTransport := fs.String("route-second-transport", "", "router-to-destination transport: lan or internet")
	routeFirstCost := fs.Uint64("route-first-cost", 0, "source-to-router route cost")
	routeSecondCost := fs.Uint64("route-second-cost", 0, "router-to-destination route cost")
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	if fs.NArg() != 1 {
		return 0, errors.New(
			"usage: wd connect [--endpoint host:port | --rfcomm MAC/channel | --relay host:port | --web-relay URL | " +
				"--route-router device-id --route-first-transport lan|internet --route-second-transport lan|internet " +
				"[--route-first-cost n] [--route-second-cost n]] [--lan-timeout duration] <device-id>",
		)
	}
	if *lanTimeout < 0 || *lanTimeout > 10*time.Second {
		return 0, errors.New("--lan-timeout must be between 0 and 10s")
	}
	deviceID := fs.Arg(0)
	overrideLocator, overrideSelected, err := connectTransportOverride(*endpoint, *rfcomm, *relayAddr, *webRelay, deviceID)
	if err != nil {
		return 0, err
	}
	routeConfig := routedConnectConfig{
		RouterDeviceID:  *routeRouter,
		FirstTransport:  *routeFirstTransport,
		SecondTransport: *routeSecondTransport,
		FirstCost:       *routeFirstCost,
		SecondCost:      *routeSecondCost,
	}
	_, routed, err := buildRoutedConnectRequest("", deviceID, routeConfig)
	if err != nil {
		return 0, err
	}
	if routed && overrideSelected {
		return 0, errors.New("routed connections cannot be combined with --endpoint, --rfcomm, --relay, or --web-relay")
	}
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
	if routed {
		if _, err := openRoutedSourceRouterTrust(*stateDir, routeConfig.RouterDeviceID); err != nil {
			return 0, err
		}
	}
	if !routed {
		if overrideSelected {
			peer.Endpoint = overrideLocator
		} else if *lanTimeout > 0 && (peer.Endpoint == "" || strings.HasPrefix(peer.Endpoint, "relay://") || strings.HasPrefix(peer.Endpoint, "wsrelay://")) {
			fallbackEndpoint := peer.Endpoint
			lanCtx, lanCancel := context.WithTimeout(context.Background(), *lanTimeout)
			result, found, discoverErr := discovery.FindTrusted(lanCtx, deviceID, peer.Fingerprint)
			lanCancel()
			if discoverErr != nil && errors.Is(discoverErr, discovery.ErrTrustedIdentityMismatch) {
				return 0, discoverErr
			}
			if found {
				directEndpoint, directErr := directLocator(result.Endpoint)
				if directErr == nil {
					directPeer := peer
					directPeer.Endpoint = directEndpoint
					probeDialer := transport.MultiDialer{Relay: transport.RelayOptions{Timeout: 2 * time.Second}}
					probeClient := &session.Client{Identity: id, Trust: store, Dialer: probeDialer}
					probeCtx, probeCancel := context.WithTimeout(context.Background(), 3*time.Second)
					probeErr := probeClient.Probe(probeCtx, directPeer)
					probeCancel()
					if probeErr == nil {
						peer = directPeer
						fmt.Fprintf(os.Stderr, "WeDecent: using trusted LAN path %s\n", result.Endpoint)
					} else {
						peer.Endpoint = fallbackEndpoint
					}
				}
			}
		}
		if peer.Endpoint == "" {
			return 0, errors.New("device has no connection locator")
		}
	}
	connectionGrant, err := readConnectionGrantFile(*connectionGrantFile)
	if err != nil {
		return 0, err
	}
	isWebRelay := strings.HasPrefix(peer.Endpoint, "wsrelay://")
	if connectionGrant == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		connectionGrant, err = automaticConnectionGrant(ctx, *stateDir, id.ID, deviceID, account.Client{})
		if err != nil {
			return 0, err
		}
	}

	if routed {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		routedDialer, enabled, err := prepareRoutedDialer(
			ctx,
			*stateDir,
			id,
			deviceID,
			routeConfig,
			*lanTimeout,
			account.Client{},
		)
		if err != nil {
			return 0, err
		}
		if !enabled {
			return 0, errors.New("routed connection configuration unexpectedly disabled")
		}
		client := &session.Client{
			Identity:        id,
			Trust:           store,
			Dialer:          routedDialer,
			ConnectionGrant: connectionGrant,
		}
		return client.ConnectTerminal(context.Background(), peer, os.Stdin, os.Stdout)
	}

	webRelayGrant := ""
	if isWebRelay {
		webRelayGrant = connectionGrant
	}
	dialer := transport.MultiDialer{Relay: transport.RelayOptions{CAFile: *relayCA, ServerName: *relayServerName, Timeout: 10 * time.Second}, WebRelay: clientWebRelayOptionsWithGrant(id, webRelayGrant)}
	client := &session.Client{Identity: id, Trust: store, Dialer: dialer, ConnectionGrant: connectionGrant}
	return client.ConnectTerminal(context.Background(), peer, os.Stdin, os.Stdout)
}

func automaticConnectionGrant(ctx context.Context, stateDir, clientDeviceID, targetDeviceID string, accountClient account.Client) (string, error) {
	path := account.SessionPath(stateDir)
	accountSession, err := account.Load(path)
	if errors.Is(err, account.ErrNoSession) {
		return "", errors.New("WeDecent account sign-in is required for terminal connections; run 'wd account login'")
	}
	if err != nil {
		return "", err
	}

	fresh, refreshed, err := accountClient.EnsureFresh(ctx, accountSession, 2*time.Minute)
	if err != nil {
		return "", err
	}
	if refreshed {
		if err := account.Save(path, fresh); err != nil {
			return "", err
		}
	}
	grant, err := accountClient.IssueConnectionGrant(ctx, fresh, clientDeviceID, targetDeviceID)
	if err != nil {
		return "", err
	}
	return grant, nil
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
  version    Print build and release metadata
  account    Sign in, inspect, or sign out of the WeDecent account session
  enrollment-proof  Prove possession of this client identity for account enrollment
  discover   Find signed WeDecent LAN advertisements
  devices    List paired devices
  unpair     Remove local trust for one paired device
  pair       Pair directly, over RFCOMM, or through a relay
  route-trust  Manage dedicated source-to-router routing trust
  connect    Open an interactive terminal directly, over RFCOMM, through a relay, or via one trusted router`)
}
