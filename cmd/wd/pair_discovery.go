package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/discovery"
	"wedecent.com/wedecent/internal/identity"
)

const defaultPairDiscoveryTimeout = 3 * time.Second

type pairCandidateFinder func(context.Context, string, string) (discovery.Result, error)

func resolvePairLocator(ctx context.Context, discoverLAN bool, discoverTimeout time.Duration, endpoint, rfcomm, relayAddr, webRelay, deviceID, fingerprint, serialDevice string) (string, error) {
	return resolvePairLocatorWithFinder(ctx, discoverLAN, discoverTimeout, endpoint, rfcomm, relayAddr, webRelay, deviceID, fingerprint, serialDevice, discovery.FindPairCandidate)
}

func resolvePairLocatorWithFinder(ctx context.Context, discoverLAN bool, discoverTimeout time.Duration, endpoint, rfcomm, relayAddr, webRelay, deviceID, fingerprint, serialDevice string, finder pairCandidateFinder) (string, error) {
	if !discoverLAN {
		return pairTransportLocator(endpoint, rfcomm, relayAddr, webRelay, deviceID, serialDevice)
	}
	if _, err := identity.ParseFingerprint(fingerprint); err != nil {
		return "", err
	}

	for _, value := range []string{endpoint, rfcomm, serialDevice, relayAddr, webRelay} {
		if strings.TrimSpace(value) != "" {
			return "", errors.New("--discover-lan cannot be combined with --endpoint, --rfcomm, --serial, --relay, or --web-relay")
		}
	}
	if strings.TrimSpace(deviceID) != deviceID || !strings.HasPrefix(deviceID, "wd_") || len(deviceID) != 19 {
		return "", errors.New("--device-id must be a canonical WeDecent device ID with --discover-lan")
	}
	if discoverTimeout <= 0 || discoverTimeout > 10*time.Second {
		return "", errors.New("--discover-timeout must be greater than 0 and at most 10s")
	}
	if finder == nil {
		return "", errors.New("internal error: LAN pair candidate finder is unavailable")
	}

	discoverCtx, cancel := context.WithTimeout(ctx, discoverTimeout)
	defer cancel()
	result, err := finder(discoverCtx, deviceID, fingerprint)
	if err != nil {
		return "", err
	}
	return directLocator(result.Endpoint)
}
