package main

import (
	"errors"
	"strings"

	"wedecent.com/wedecent/internal/transport"
)

func rfcommLocator(endpoint string) (string, error) {
	raw := strings.TrimSpace(endpoint)
	if strings.HasPrefix(raw, "rfcomm://") {
		raw = strings.TrimPrefix(raw, "rfcomm://")
	}
	canonical, err := transport.NormalizeRFCOMMLocator(raw)
	if err != nil {
		return "", err
	}
	return "rfcomm://" + canonical, nil
}

func pairTransportLocator(endpoint, rfcomm, relayAddr, webRelay, deviceID string) (string, error) {
	selected := 0
	for _, value := range []string{endpoint, rfcomm, relayAddr, webRelay} {
		if strings.TrimSpace(value) != "" {
			selected++
		}
	}
	if selected != 1 {
		return "", errors.New("specify exactly one of --endpoint, --rfcomm, --relay, or --web-relay")
	}

	switch {
	case strings.TrimSpace(endpoint) != "":
		return directLocator(endpoint)
	case strings.TrimSpace(rfcomm) != "":
		return rfcommLocator(rfcomm)
	case strings.TrimSpace(webRelay) != "":
		if strings.TrimSpace(deviceID) == "" {
			return "", errors.New("--device-id is required with a relay")
		}
		return webRelayLocator(webRelay, deviceID)
	default:
		if strings.TrimSpace(deviceID) == "" {
			return "", errors.New("--device-id is required with a relay")
		}
		return relayLocator(relayAddr, deviceID)
	}
}

func connectTransportOverride(endpoint, rfcomm, relayAddr, webRelay, deviceID string) (string, bool, error) {
	selected := 0
	for _, value := range []string{endpoint, rfcomm, relayAddr, webRelay} {
		if strings.TrimSpace(value) != "" {
			selected++
		}
	}
	if selected > 1 {
		return "", false, errors.New("--endpoint, --rfcomm, --relay, and --web-relay are mutually exclusive")
	}
	if selected == 0 {
		return "", false, nil
	}

	switch {
	case strings.TrimSpace(endpoint) != "":
		locator, err := directLocator(endpoint)
		return locator, true, err
	case strings.TrimSpace(rfcomm) != "":
		locator, err := rfcommLocator(rfcomm)
		return locator, true, err
	case strings.TrimSpace(webRelay) != "":
		locator, err := webRelayLocator(webRelay, deviceID)
		return locator, true, err
	default:
		locator, err := relayLocator(relayAddr, deviceID)
		return locator, true, err
	}
}
