package meshnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/discovery"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/trust"
)

var (
	ErrResolverUnavailable  = errors.New("meshnet: trusted peer resolver is unavailable")
	ErrPeerNotTrusted       = errors.New("meshnet: routed peer is not trusted")
	ErrPeerIdentityInvalid  = errors.New("meshnet: trusted peer identity is invalid")
	ErrPeerIdentityMismatch = errors.New("meshnet: discovered peer identity does not match trust")
	ErrPeerLocatorMissing   = errors.New("meshnet: trusted peer has no usable locator")
	ErrPeerUnavailable      = errors.New("meshnet: trusted routed peer is unavailable")
	ErrUnsupportedTransport = errors.New("meshnet: routed transport is not supported")
)

// ResolvedPeer is router-owned connection metadata for an authenticated
// neighboring mesh hop.
//
// Locator is never accepted from a route-control request. It comes only from
// local trusted state or fingerprint-pinned signed discovery.
type ResolvedPeer struct {
	ID          mesh.DeviceID
	Fingerprint string
	Locator     string
	Transport   mesh.TransportName
}

type TrustedPeerResolver struct {
	Store *trust.Store

	// LANDiscoveryTimeout is required for TransportLAN resolution. A LAN hop
	// must come from signed fingerprint-pinned discovery; the generic stored TCP
	// locator is not sufficient evidence that an address is actually LAN-local.
	LANDiscoveryTimeout time.Duration

	// FindTrusted exists for deterministic tests. Production callers normally
	// leave it nil so discovery.FindTrusted is used.
	FindTrusted func(context.Context, string, string) (discovery.Result, bool, error)
}

func (r TrustedPeerResolver) Resolve(
	ctx context.Context,
	deviceID mesh.DeviceID,
	transportName mesh.TransportName,
) (ResolvedPeer, error) {
	if err := ctx.Err(); err != nil {
		return ResolvedPeer{}, err
	}
	if r.Store == nil {
		return ResolvedPeer{}, ErrResolverUnavailable
	}

	id := strings.TrimSpace(string(deviceID))
	if id == "" {
		return ResolvedPeer{}, ErrPeerIdentityInvalid
	}

	peer, ok := r.Store.Get(id)
	if !ok {
		return ResolvedPeer{}, ErrPeerNotTrusted
	}
	if peer.ID != id {
		return ResolvedPeer{}, ErrPeerIdentityInvalid
	}

	fp, err := identity.ParseFingerprint(peer.Fingerprint)
	if err != nil {
		return ResolvedPeer{}, fmt.Errorf("%w: %v", ErrPeerIdentityInvalid, err)
	}

	switch transportName {
	case mesh.TransportLAN:
		if r.LANDiscoveryTimeout <= 0 {
			return ResolvedPeer{}, ErrPeerUnavailable
		}

		result, found, err := r.resolveLAN(ctx, peer, fp)
		if err != nil {
			return ResolvedPeer{}, err
		}
		if !found {
			return ResolvedPeer{}, ErrPeerUnavailable
		}

		return ResolvedPeer{
			ID:          deviceID,
			Fingerprint: fp,
			Locator:     "tcp://" + result.Endpoint,
			Transport:   mesh.TransportLAN,
		}, nil

	case mesh.TransportInternet:
	// Initial routed Internet hops are direct authenticated TCP only.
	// Relay/WSS routing must be designed explicitly rather than being
	// accidentally enabled through an arbitrary locator.

	default:
		return ResolvedPeer{}, ErrUnsupportedTransport
	}

	locator, err := trustedTCPLocator(peer.Endpoint)
	if err != nil {
		return ResolvedPeer{}, err
	}

	return ResolvedPeer{
		ID:          deviceID,
		Fingerprint: fp,
		Locator:     locator,
		Transport:   transportName,
	}, nil
}

func (r TrustedPeerResolver) resolveLAN(
	ctx context.Context,
	peer trust.Peer,
	fingerprint string,
) (discovery.Result, bool, error) {
	find := r.FindTrusted
	if find == nil {
		find = discovery.FindTrusted
	}

	discoveryCtx, cancel := context.WithTimeout(ctx, r.LANDiscoveryTimeout)
	defer cancel()

	result, found, err := find(discoveryCtx, peer.ID, fingerprint)
	if err != nil {
		if errors.Is(err, discovery.ErrTrustedIdentityMismatch) {
			return discovery.Result{}, false, fmt.Errorf(
				"%w: %v",
				ErrPeerIdentityMismatch,
				err,
			)
		}

		if ctxErr := ctx.Err(); ctxErr != nil {
			return discovery.Result{}, false, ctxErr
		}

		return discovery.Result{}, false, fmt.Errorf(
			"%w: trusted LAN discovery failed: %v",
			ErrPeerUnavailable,
			err,
		)
	}

	if !found {
		return discovery.Result{}, false, nil
	}

	if result.DeviceID != peer.ID {
		return discovery.Result{}, false, ErrPeerIdentityMismatch
	}

	discoveredFP, err := identity.ParseFingerprint(result.Fingerprint)
	if err != nil || discoveredFP != fingerprint {
		return discovery.Result{}, false, ErrPeerIdentityMismatch
	}

	if _, err := trustedHostPort(result.Endpoint); err != nil {
		return discovery.Result{}, false, err
	}

	return result, true, nil
}

func trustedTCPLocator(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ErrPeerLocatorMissing
	}

	u, err := url.Parse(raw)
	if err != nil ||
		u.Scheme != "tcp" ||
		u.Host == "" ||
		u.User != nil ||
		u.Path != "" ||
		u.RawQuery != "" ||
		u.Fragment != "" {
		return "", ErrPeerLocatorMissing
	}

	hostPort, err := trustedHostPort(u.Host)
	if err != nil {
		return "", err
	}

	return "tcp://" + hostPort, nil
}

func trustedHostPort(raw string) (string, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil || strings.TrimSpace(host) == "" {
		return "", ErrPeerLocatorMissing
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", ErrPeerLocatorMissing
	}

	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
