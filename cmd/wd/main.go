package main

import (
	"context"
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

	"wedecent.com/wedecent/internal/appdirs"
	"wedecent.com/wedecent/internal/discovery"
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
	dialer := transport.MultiDialer{Relay: transport.RelayOptions{CAFile: *relayCA, ServerName: *relayServerName, Timeout: 10 * time.Second}, WebRelay: clientWebRelayOptions(id)}
	client := &session.Client{Identity: id, Trust: store, Dialer: dialer}
	return client.ConnectTerminal(context.Background(), peer, os.Stdin, os.Stdout)
}

func clientWebRelayOptions(id *identity.Identity) transport.WebRelayOptions {
	return transport.WebRelayOptions{
		TicketSource: relayauth.NewTicketSource(id),
		Timeout:      15 * time.Second,
	}
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
  discover   Find signed WeDecent LAN advertisements
  devices    List paired devices
  pair       Pair directly or through a relay
  connect    Open an interactive terminal directly or through a relay`)
}
