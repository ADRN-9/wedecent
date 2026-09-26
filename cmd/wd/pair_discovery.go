package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/discovery"
	"wedecent.com/wedecent/internal/identity"
)

type pairCandidateFinder func(context.Context, string, string) (discovery.Result, error)

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

func resolvePairLocator(ctx context.Context, opts pairLocatorOptions, finder pairCandidateFinder) (string, error) {
	if !opts.DiscoverLAN {
		return pairTransportLocator(opts.Endpoint, opts.RFCOMM, opts.Relay, opts.WebRelay, opts.DeviceID, opts.SerialDevice)
	}
	if _, err := identity.ParseFingerprint(opts.Fingerprint); err != nil {
		return "", err
	}
	for _, value := range []string{opts.Endpoint, opts.RFCOMM, opts.SerialDevice, opts.Relay, opts.WebRelay} {
		if strings.TrimSpace(value) != "" {
			return "", errors.New("--discover-lan cannot be combined with --endpoint, --rfcomm, --serial, --relay, or --web-relay")
		}
	}
	if strings.TrimSpace(opts.DeviceID) != opts.DeviceID || !strings.HasPrefix(opts.DeviceID, "wd_") || len(opts.DeviceID) != 19 {
		return "", errors.New("--device-id must be a canonical WeDecent device ID with --discover-lan")
	}
	if opts.DiscoverTimeout <= 0 || opts.DiscoverTimeout > 10*time.Second {
		return "", errors.New("--discover-timeout must be greater than 0 and at most 10s")
	}
	if finder == nil {
		return "", errors.New("internal error: LAN pair candidate finder is unavailable")
	}

	discoverCtx, cancel := context.WithTimeout(ctx, opts.DiscoverTimeout)
	defer cancel()
	result, err := finder(discoverCtx, opts.DeviceID, opts.Fingerprint)
	if err != nil {
		return "", err
	}
	return directLocator(result.Endpoint)
}
