package discovery

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"wedecent.com/wedecent/internal/identity"
)

var (
	ErrNoPairCandidate        = errors.New("discovery: no matching pair candidate")
	ErrAmbiguousPairCandidate = errors.New("discovery: multiple matching pair candidates")
)

// SelectPairCandidate selects exactly one LAN routing hint for first pairing.
// The caller must supply an independently verified expected fingerprint.
// Discovery metadata never creates trust.
func SelectPairCandidate(results []Result, deviceID, expectedFingerprint string) (Result, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !strings.HasPrefix(deviceID, "wd_") || len(deviceID) != 19 {
		return Result{}, errors.New("discovery: invalid WeDecent device ID")
	}
	expected, err := identity.ParseFingerprint(expectedFingerprint)
	if err != nil {
		return Result{}, fmt.Errorf("%w: expected fingerprint is invalid", ErrTrustedIdentityMismatch)
	}

	matches := make(map[string]Result)
	for _, result := range results {
		if result.DeviceID != deviceID {
			continue
		}
		got, err := identity.ParseFingerprint(result.Fingerprint)
		if err != nil {
			return Result{}, fmt.Errorf("%w: discovered fingerprint is invalid", ErrTrustedIdentityMismatch)
		}
		if got != expected {
			return Result{}, fmt.Errorf("%w for %s", ErrTrustedIdentityMismatch, deviceID)
		}
		endpoint, err := canonicalLANEndpoint(result.Endpoint)
		if err != nil {
			return Result{}, fmt.Errorf("discovery: invalid LAN candidate for %s: %w", deviceID, err)
		}
		result.Endpoint = endpoint
		matches[endpoint] = result
	}

	switch len(matches) {
	case 0:
		return Result{}, ErrNoPairCandidate
	case 1:
		for _, result := range matches {
			return result, nil
		}
	default:
		return Result{}, fmt.Errorf("%w for %s; select one explicitly with --endpoint", ErrAmbiguousPairCandidate, deviceID)
	}
	panic("unreachable")
}

func canonicalLANEndpoint(endpoint string) (string, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil {
		return "", errors.New("endpoint must be IP:port")
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return "", errors.New("endpoint must use a concrete unicast IP address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("endpoint port must be between 1 and 65535")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}
