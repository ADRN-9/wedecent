package session

import (
	"context"
	"net"
	"time"

	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/portforward"
)

// PortForwardRuntime is a fail-closed destination-side capability runtime.
// It contains public trust anchors and policy only; private authorization
// signing keys never belong on an endpoint.
type PortForwardRuntime struct {
	Verifier             portforward.Verifier
	TrustChecker         portforward.PeerTrustChecker
	RouterTrustChecker   portforward.PeerTrustChecker
	PermissionAuthorizer portforward.PermissionAuthorizer
	Resolver             portforward.IPResolver
	Dialer               portforward.ContextDialer
	Policy               portforward.DestinationPolicy
	Audit                portforward.AuditWriter
	TrustPollInterval    time.Duration
	MaxConnections       int
	DialTimeout          time.Duration
}

func (r *PortForwardRuntime) Ready() bool {
	if r == nil || r.Verifier == nil || r.TrustChecker == nil ||
		r.PermissionAuthorizer == nil || r.Resolver == nil || r.Dialer == nil ||
		r.Audit == nil || r.MaxConnections < 1 || r.MaxConnections > 64 ||
		r.DialTimeout < time.Second || r.DialTimeout > 30*time.Second {
		return false
	}
	if r.Policy.Validate() != nil {
		return false
	}
	if r.TrustPollInterval != 0 && (r.TrustPollInterval < 10*time.Millisecond || r.TrustPollInterval > 5*time.Second) {
		return false
	}
	return true
}

func (r *PortForwardRuntime) OpenDestinationSession(
	ctx context.Context,
	localID mesh.DeviceID,
	peerID mesh.DeviceID,
	routerID mesh.DeviceID,
	auth portforward.Authorization,
) (*portforward.DestinationSession, error) {
	if !r.Ready() {
		return nil, portforward.ErrManagerConfig
	}
	return portforward.NewDestinationSession(ctx, portforward.DestinationConfig{
		LocalDeviceID:         localID,
		AuthenticatedPeerID:   peerID,
		AuthenticatedRouterID: routerID,
		Verifier:              r.Verifier,
		TrustChecker:          r.TrustChecker,
		RouterTrustChecker:    r.RouterTrustChecker,
		TrustPollInterval:     r.TrustPollInterval,
		PermissionAuthorizer:  r.PermissionAuthorizer,
		Resolver:              r.Resolver,
		Dialer:                r.Dialer,
		Policy:                r.Policy,
		Audit:                 r.Audit,
		MaxConnections:        r.MaxConnections,
		DialTimeout:           r.DialTimeout,
	}, auth)
}

var _ portforward.IPResolver = (*net.Resolver)(nil)
