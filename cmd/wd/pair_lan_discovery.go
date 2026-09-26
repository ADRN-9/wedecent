package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/discovery"
	"wedecent.com/wedecent/internal/identity"
)

type pairLANFinder func(context.Context, string, string) (discovery.Result, error)

type pairLocatorOptions struct {
	Endpoint        string
	RFCOMM          string
	SerialDevice    string
	Relay           string
	WebRelay        string
	DeviceID        string
	Fingerprint     string
	DiscoverLAN     bool
	DiscoverTimeout time.Duration
}

func resolvePairLocator(ctx context.Context, opts pairLocatorOptions, finder pairLANFinder) (string, error) {
	if !opts.DiscoverLAN {
		return pairTransportLocator(opts.Endpoint, opts.RFCOMM, opts.Relay, opts.WebRelay, opts.DeviceID, opts.SerialDevice)
	}
	if _, err := identity.ParseFingerprint(opts.Fingerprint); err != nil {
		return "", err
	}
	if strings.TrimSpace(opts.DeviceID) != opts.DeviceID || !strings.HasPrefix(opts.DeviceID, "wd_") || len(opts.DeviceID) != 19 {
		return "", errors.New("--discover-lan requires a canonical --device-id")
	}
	if opts.DiscoverTimeout <= 0 || opts.DiscoverTimeout > time.Minute {
		return "", errors.New("--discover-timeout must be greater than 0 and at most 1m")
	}
	if strings.TrimSpace(opts.Endpoint) != "" || strings.TrimSpace(opts.RFCOMM) != "" || strings.TrimSpace(opts.SerialDevice) != "" || strings.TrimSpace(opts.Relay) != "" || strings.TrimSpace(opts.WebRelay) != "" {
		return "", errors.New("--discover-lan cannot be combined with --endpoint, --rfcomm, --serial, --relay, or --web-relay")
	}
	if finder == nil {
		return "", errors.New("LAN pair discovery is unavailable")
	}

	discoverCtx, cancel := context.WithTimeout(ctx, opts.DiscoverTimeout)
	defer cancel()
	candidate, err := finder(discoverCtx, opts.DeviceID, opts.Fingerprint)
	if err != nil {
		return "", err
	}
	return directLocator(candidate.Endpoint)
}
