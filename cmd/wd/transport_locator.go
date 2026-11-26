package main

import (
	"errors"
	"path"
	"strings"

	"wedecent.com/wedecent/internal/transport"
)

func rfcommLocator(endpoint string) (string, error) {
	if strings.TrimSpace(endpoint) != endpoint {
		return "", errors.New("RFCOMM locator must not contain surrounding whitespace")
	}
	raw := endpoint
	if strings.HasPrefix(raw, "rfcomm://") {
		raw = strings.TrimPrefix(raw, "rfcomm://")
	}
	canonical, err := transport.NormalizeRFCOMMLocator(raw)
	if err != nil {
		return "", err
	}
	return "rfcomm://" + canonical, nil
}

func serialLocator(endpoint string) (string, error) {
	if endpoint == "" {
		return "", errors.New("serial device path is required")
	}
	if strings.TrimSpace(endpoint) != endpoint {
		return "", errors.New("serial device path must not contain surrounding whitespace")
	}
	raw := endpoint
	if strings.HasPrefix(raw, "serial://") {
		raw = strings.TrimPrefix(raw, "serial://")
	}
	if strings.IndexByte(raw, 0) >= 0 || strings.ContainsAny(raw, "?#") {
		return "", errors.New("invalid serial device path")
	}
	if raw == "/dev" || !strings.HasPrefix(raw, "/dev/") || path.Clean(raw) != raw {
		return "", errors.New("serial device path must be a canonical absolute path under /dev")
	}
	return "serial://" + raw, nil
}

func countTransportSelections(values ...string) (int, error) {
	selected := 0
	for _, value := range values {
		if value == "" {
			continue
		}
		if strings.TrimSpace(value) != value {
			return 0, errors.New("transport locator must not contain surrounding whitespace")
		}
		selected++
	}
	return selected, nil
}

// pairTransportLocator keeps the original five-argument command contract while
// allowing the serial device to be supplied by the CLI wiring slice as the
// optional sixth argument. This lets locator validation land independently.
func pairTransportLocator(endpoint, rfcomm, relayAddr, webRelay, deviceID string, serialDevice ...string) (string, error) {
	serial := ""
	if len(serialDevice) > 1 {
		return "", errors.New("internal error: multiple serial transport arguments")
	}
	if len(serialDevice) == 1 {
		serial = serialDevice[0]
	}
	selected, err := countTransportSelections(endpoint, rfcomm, serial, relayAddr, webRelay)
	if err != nil {
		return "", err
	}
	if selected != 1 {
		return "", errors.New("specify exactly one of --endpoint, --rfcomm, --serial, --relay, or --web-relay")
	}

	switch {
	case endpoint != "":
		return directLocator(endpoint)
	case rfcomm != "":
		return rfcommLocator(rfcomm)
	case serial != "":
		return serialLocator(serial)
	case webRelay != "":
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

// connectTransportOverride accepts an optional serial device after the existing
// arguments so the command entrypoint can be wired in a separate auditable PR.
func connectTransportOverride(endpoint, rfcomm, relayAddr, webRelay, deviceID string, serialDevice ...string) (string, bool, error) {
	serial := ""
	if len(serialDevice) > 1 {
		return "", false, errors.New("internal error: multiple serial transport arguments")
	}
	if len(serialDevice) == 1 {
		serial = serialDevice[0]
	}
	selected := 0
	for _, value := range []string{endpoint, rfcomm, serial, relayAddr, webRelay} {
		if strings.TrimSpace(value) != "" {
			selected++
		}
	}
	if selected > 1 {
		return "", false, errors.New("--endpoint, --rfcomm, --serial, --relay, and --web-relay are mutually exclusive")
	}
	if selected == 0 {
		return "", false, nil
	}

	switch {
	case endpoint != "":
		locator, err := directLocator(endpoint)
		return locator, true, err
	case rfcomm != "":
		locator, err := rfcommLocator(rfcomm)
		return locator, true, err
	case serial != "":
		locator, err := serialLocator(serial)
		return locator, true, err
	case webRelay != "":
		locator, err := webRelayLocator(webRelay, deviceID)
		return locator, true, err
	default:
		locator, err := relayLocator(relayAddr, deviceID)
		return locator, true, err
	}
}
