package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/appdirs"
	"wedecent.com/wedecent/internal/discovery"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/meshnet"
	"wedecent.com/wedecent/internal/trust"
)

type routeTrustFinder func(context.Context, string, string) (discovery.Result, bool, error)

func runRouteTrust(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: wd route-trust <add|list|revoke> [options]")
	}

	switch args[0] {
	case "add":
		return runRouteTrustAdd(args[1:])
	case "list":
		return runRouteTrustList(args[1:])
	case "revoke":
		return runRouteTrustRevoke(args[1:])
	default:
		return fmt.Errorf("unknown route-trust command %q; use add, list, or revoke", args[0])
	}
}

func runRouteTrustAdd(args []string) error {
	return runRouteTrustAddWithFinder(args, discovery.FindTrusted)
}

func runRouteTrustAddWithFinder(args []string, find routeTrustFinder) error {
	state, _ := appdirs.Client()
	fs := flag.NewFlagSet("route-trust add", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	fingerprint := fs.String("fingerprint", "", "expected SHA256 router public-key fingerprint")
	endpoint := fs.String("endpoint", "", "direct router route-control host:port; omit to verify via signed LAN discovery")
	discoverTimeout := fs.Duration("discover-timeout", 3*time.Second, "signed LAN discovery window when --endpoint is omitted")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: wd route-trust add --fingerprint SHA256:... [--endpoint host:port] <router-device-id>")
	}
	if strings.TrimSpace(*fingerprint) == "" {
		return errors.New("--fingerprint is required; obtain it from wd discover or the router identity")
	}

	peer, err := addRouteRouterTrust(
		context.Background(),
		*stateDir,
		fs.Arg(0),
		*fingerprint,
		*endpoint,
		*discoverTimeout,
		find,
	)
	if err != nil {
		return err
	}

	fmt.Printf("Trusted route router %s\t%s\t%s\n", peer.ID, peer.Endpoint, peer.Fingerprint)
	return nil
}

func runRouteTrustList(args []string) error {
	state, _ := appdirs.Client()
	fs := flag.NewFlagSet("route-trust list", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: wd route-trust list [--state directory]")
	}

	peers, err := listRouteRouterTrust(*stateDir)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		fmt.Printf("%s\t%s\t%s\t%s\n", peer.ID, peer.Name, peer.Endpoint, peer.Fingerprint)
	}
	return nil
}

func runRouteTrustRevoke(args []string) error {
	state, _ := appdirs.Client()
	fs := flag.NewFlagSet("route-trust revoke", flag.ContinueOnError)
	stateDir := fs.String("state", state, "client state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: wd route-trust revoke [--state directory] <router-device-id>")
	}

	routerID := strings.TrimSpace(fs.Arg(0))
	if !validWeDecentDeviceID(routerID) {
		return errors.New("invalid WeDecent router device ID")
	}

	removed, err := revokeRouteRouterTrust(*stateDir, routerID)
	if err != nil {
		return err
	}
	if !removed {
		return fmt.Errorf("router %s is not trusted for routing", routerID)
	}
	fmt.Printf("Revoked route router %s\n", routerID)
	return nil
}

func addRouteRouterTrust(
	ctx context.Context,
	stateDir string,
	routerDeviceID string,
	fingerprint string,
	endpoint string,
	discoverTimeout time.Duration,
	find routeTrustFinder,
) (trust.Peer, error) {
	routerDeviceID = strings.TrimSpace(routerDeviceID)
	if !validWeDecentDeviceID(routerDeviceID) {
		return trust.Peer{}, errors.New("invalid WeDecent router device ID")
	}

	fp, err := identity.ParseFingerprint(fingerprint)
	if err != nil {
		return trust.Peer{}, err
	}

	peer := trust.Peer{
		ID:          routerDeviceID,
		Fingerprint: fp,
	}

	endpoint = strings.TrimSpace(endpoint)
	if endpoint != "" {
		locator, err := directLocator(endpoint)
		if err != nil {
			return trust.Peer{}, fmt.Errorf("router endpoint: %w", err)
		}
		peer.Endpoint = locator
	} else {
		if discoverTimeout <= 0 || discoverTimeout > time.Minute {
			return trust.Peer{}, errors.New("--discover-timeout must be between 1ns and 1m")
		}
		if find == nil {
			return trust.Peer{}, errors.New("route router discovery is unavailable")
		}

		discoveryCtx, cancel := context.WithTimeout(ctx, discoverTimeout)
		defer cancel()
		result, found, err := find(discoveryCtx, routerDeviceID, fp)
		if err != nil {
			return trust.Peer{}, err
		}
		if !found {
			return trust.Peer{}, fmt.Errorf("router %s was not found by signed LAN discovery", routerDeviceID)
		}
		if result.DeviceID != routerDeviceID {
			return trust.Peer{}, discovery.ErrTrustedIdentityMismatch
		}
		gotFP, err := identity.ParseFingerprint(result.Fingerprint)
		if err != nil || gotFP != fp {
			return trust.Peer{}, discovery.ErrTrustedIdentityMismatch
		}
		locator, err := directLocator(result.Endpoint)
		if err != nil {
			return trust.Peer{}, fmt.Errorf("discovered router endpoint: %w", err)
		}
		peer.Name = strings.TrimSpace(result.Name)
		peer.Endpoint = locator
	}

	store, err := meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		return trust.Peer{}, err
	}
	if err := store.Put(peer); err != nil {
		return trust.Peer{}, err
	}
	stored, ok := store.Get(routerDeviceID)
	if !ok {
		return trust.Peer{}, errors.New("route router trust was not persisted")
	}
	return stored, nil
}

func listRouteRouterTrust(stateDir string) ([]trust.Peer, error) {
	store, err := meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		return nil, err
	}
	peers := store.List()
	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
	return peers, nil
}

func revokeRouteRouterTrust(stateDir string, routerDeviceID string) (bool, error) {
	store, err := meshnet.OpenRouteSourceRoutersTrust(stateDir)
	if err != nil {
		return false, err
	}
	return store.Delete(strings.TrimSpace(routerDeviceID))
}

func validWeDecentDeviceID(deviceID string) bool {
	deviceID = strings.TrimSpace(deviceID)
	if len(deviceID) != 19 || !strings.HasPrefix(deviceID, "wd_") {
		return false
	}
	for _, r := range deviceID[3:] {
		if (r >= 'a' && r <= 'z') || (r >= '2' && r <= '7') {
			continue
		}
		return false
	}
	return true
}
