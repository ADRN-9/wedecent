package portforward

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/mesh"
)

var (
	ErrWrongDestinationDevice   = errors.New("portforward: capability is not bound to this destination device")
	ErrDestinationSessionClosed = errors.New("portforward: destination forwarding session is closed")
	ErrRouterIdentityMismatch   = errors.New("portforward: authenticated router identity does not match authorization")
	ErrRouterNotTrusted         = errors.New("portforward: routing trust domain does not trust the router")
)

// DestinationConfig.TrustChecker must be the endpoint-device trust domain.
// RouterTrustChecker must be the independent routing trust domain and is only
// consulted when the capability binds a router. Both authenticated identities
// must come from their respective verified TLS peer certificates.
type DestinationConfig struct {
	LocalDeviceID         mesh.DeviceID
	AuthenticatedPeerID   mesh.DeviceID
	AuthenticatedRouterID mesh.DeviceID
	Verifier              Verifier
	TrustChecker          PeerTrustChecker
	RouterTrustChecker    PeerTrustChecker
	TrustPollInterval     time.Duration
	PermissionAuthorizer  PermissionAuthorizer
	Resolver              IPResolver
	Dialer                ContextDialer
	Policy                DestinationPolicy
	Audit                 AuditWriter
	MaxConnections        int
	DialTimeout           time.Duration
}

type DestinationSession struct {
	claims            Claims
	localID           mesh.DeviceID
	peerID            mesh.DeviceID
	approved          ApprovedDestination
	policy            DestinationPolicy
	dialer            ContextDialer
	audit             AuditWriter
	trustChecker       PeerTrustChecker
	routerTrustChecker PeerTrustChecker
	routerID           mesh.DeviceID
	trustPollInterval  time.Duration
	expiryReason       string
	idleTimeout        time.Duration
	maxChildren        int
	dialTimeout        time.Duration
	ctx               context.Context
	cancel            context.CancelFunc

	mu        sync.Mutex
	closed    bool
	nextChild uint64
	children  map[uint64]*destinationChildConn
	closeOnce sync.Once
	closeErr  error
	auditErr  error
	done      chan struct{}
}

type destinationChildConn struct {
	net.Conn
	session  *DestinationSession
	id       uint64
	once     sync.Once
	closeErr error
}

func NewDestinationSession(ctx context.Context, cfg DestinationConfig, auth Authorization) (*DestinationSession, error) {
	if ctx == nil || !deviceIDPattern.MatchString(string(cfg.LocalDeviceID)) ||
		!deviceIDPattern.MatchString(string(cfg.AuthenticatedPeerID)) ||
		cfg.Verifier == nil || cfg.TrustChecker == nil || cfg.PermissionAuthorizer == nil ||
		cfg.Resolver == nil || cfg.Dialer == nil || cfg.Audit == nil ||
		cfg.MaxConnections < 1 || cfg.MaxConnections > 64 ||
		cfg.DialTimeout < time.Second || cfg.DialTimeout > 30*time.Second {
		return nil, ErrManagerConfig
	}
	if err := cfg.Policy.Validate(); err != nil {
		return nil, err
	}
	trustPollInterval := cfg.TrustPollInterval
	if trustPollInterval == 0 {
		trustPollInterval = 250 * time.Millisecond
	}
	if trustPollInterval < 10*time.Millisecond || trustPollInterval > 5*time.Second {
		return nil, ErrManagerConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	claims := cloneClaims(auth.Claims)
	if err := ValidateClaims(claims); err != nil {
		return nil, err
	}
	destinationDevice := claims.DestinationDevice
	peerDevice := claims.InitiatingDevice
	if claims.Direction == DirectionRemote {
		destinationDevice = claims.InitiatingDevice
		peerDevice = claims.DestinationDevice
	}
	if cfg.LocalDeviceID != destinationDevice {
		return nil, ErrWrongDestinationDevice
	}
	if cfg.AuthenticatedPeerID != peerDevice {
		return nil, ErrAuthorizationMismatch
	}
	if claims.Router == "" {
		if cfg.AuthenticatedRouterID != "" {
			return nil, ErrRouterIdentityMismatch
		}
	} else {
		if cfg.AuthenticatedRouterID != claims.Router {
			return nil, ErrRouterIdentityMismatch
		}
		if cfg.RouterTrustChecker == nil {
			return nil, ErrRouterNotTrusted
		}
		routerTrusted, routerTrustErr := cfg.RouterTrustChecker.IsTrusted(ctx, string(cfg.AuthenticatedRouterID))
		if routerTrustErr != nil || !routerTrusted {
			return nil, errors.Join(ErrRouterNotTrusted, routerTrustErr)
		}
	}
	trusted, trustErr := cfg.TrustChecker.IsTrusted(ctx, string(cfg.AuthenticatedPeerID))
	if trustErr != nil || !trusted {
		return nil, errors.Join(ErrPeerNotTrusted, trustErr)
	}
	if err := ValidateRouteAuthorizationBinding(auth); err != nil {
		return nil, err
	}

	verified, err := cfg.Verifier.VerifyAndConsume(ctx, auth)
	if err != nil {
		return nil, err
	}
	if !sameClaims(claims, verified) {
		return nil, ErrAuthorizationMismatch
	}
	if err := cfg.PermissionAuthorizer.AuthorizePortForward(ctx, claims); err != nil {
		return nil, err
	}
	approved, err := ResolveApprovedDestination(ctx, cfg.Resolver, cfg.Policy, claims.DestinationAddress, claims.DestinationPort)
	if err != nil {
		return nil, err
	}
	if err := cfg.Audit.Append(destinationAuditEvent(claims, cfg.LocalDeviceID, cfg.AuthenticatedPeerID, "port_forward.destination_session_opened", "success", "")); err != nil {
		return nil, err
	}

	deadline := time.UnixMilli(claims.ExpiresAtUnixMS)
	expiryReason := "authorization_expired"
	maxDurationDeadline := time.UnixMilli(claims.IssuedAtUnixMS).Add(time.Duration(claims.Limits.MaxDurationSeconds) * time.Second)
	if maxDurationDeadline.Before(deadline) {
		deadline = maxDurationDeadline
		expiryReason = "max_duration_elapsed"
	}
	if !deadline.After(time.Now()) {
		return nil, ErrAuthorizationExpired
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sessionCtx, cancel := context.WithDeadline(ctx, deadline)
	session := &DestinationSession{
		claims:            claims,
		localID:           cfg.LocalDeviceID,
		peerID:            cfg.AuthenticatedPeerID,
		approved:          approved,
		policy:            cfg.Policy,
		dialer:            cfg.Dialer,
		audit:             cfg.Audit,
		trustChecker:       cfg.TrustChecker,
		routerTrustChecker: cfg.RouterTrustChecker,
		routerID:           claims.Router,
		trustPollInterval:  trustPollInterval,
		expiryReason:      expiryReason,
		idleTimeout:       time.Duration(claims.Limits.IdleTimeoutSeconds) * time.Second,
		maxChildren:       min(int(claims.Limits.MaxConnections), cfg.MaxConnections),
		dialTimeout:       cfg.DialTimeout,
		ctx:               sessionCtx,
		cancel:            cancel,
		children:          make(map[uint64]*destinationChildConn),
		done:              make(chan struct{}),
	}
	go session.watchTrust()
	return session, nil
}

func (s *DestinationSession) watchTrust() {
	ticker := time.NewTicker(s.trustPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			reason := s.expiryReason
			if !errors.Is(s.ctx.Err(), context.DeadlineExceeded) {
				reason = "parent_session_closed"
			}
			_ = s.closeWithReason(reason)
			return
		case <-ticker.C:
			trusted, err := s.trustChecker.IsTrusted(s.ctx, string(s.peerID))
			if s.ctx.Err() != nil {
				reason := s.expiryReason
				if !errors.Is(s.ctx.Err(), context.DeadlineExceeded) {
					reason = "parent_session_closed"
				}
				_ = s.closeWithReason(reason)
				return
			}
			if err != nil {
				_ = s.closeWithReason("peer_trust_unavailable")
				return
			}
			if !trusted {
				_ = s.closeWithReason("peer_trust_revoked")
				return
			}
			if s.routerID != "" {
				routerTrusted, routerErr := s.routerTrustChecker.IsTrusted(s.ctx, string(s.routerID))
				if s.ctx.Err() != nil {
					reason := s.expiryReason
					if !errors.Is(s.ctx.Err(), context.DeadlineExceeded) {
						reason = "parent_session_closed"
					}
					_ = s.closeWithReason(reason)
					return
				}
				if routerErr != nil {
					_ = s.closeWithReason("router_trust_unavailable")
					return
				}
				if !routerTrusted {
					_ = s.closeWithReason("router_trust_revoked")
					return
				}
			}
		}
	}
}

func (s *DestinationSession) OpenChild(ctx context.Context) (net.Conn, error) {
	if s == nil || ctx == nil {
		return nil, ErrDestinationSessionClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil {
		s.mu.Unlock()
		return nil, ErrDestinationSessionClosed
	}
	if len(s.children) >= s.maxChildren {
		s.mu.Unlock()
		return nil, ErrForwardLimit
	}
	s.nextChild++
	childID := s.nextChild
	s.children[childID] = nil
	s.mu.Unlock()

	if err := s.audit.Append(destinationAuditEvent(s.claims, s.localID, s.peerID, "port_forward.destination_child", "attempt", "")); err != nil {
		s.releaseReservation(childID)
		return nil, err
	}

	dialCtx, cancelDial := context.WithTimeout(ctx, s.dialTimeout)
	childCtx, cancelChild := context.WithCancel(dialCtx)
	stopSessionCancel := context.AfterFunc(s.ctx, cancelChild)
	conn, dialErr := DialApprovedTCP(childCtx, s.dialer, s.policy, s.approved)
	stopSessionCancel()
	cancelChild()
	cancelDial()
	if dialErr != nil {
		s.releaseReservation(childID)
		auditErr := s.audit.Append(destinationAuditEvent(s.claims, s.localID, s.peerID, "port_forward.destination_child", "failed", "destination_dial_failed"))
		return nil, errors.Join(dialErr, auditErr)
	}

	child := &destinationChildConn{
		Conn:    newIdleConn(conn, s.idleTimeout),
		session: s,
		id:      childID,
	}
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil || s.children[childID] != nil {
		delete(s.children, childID)
		s.mu.Unlock()
		closeErr := conn.Close()
		outcome, reason := "success", "parent_session_closed_before_child_open"
		if closeErr != nil {
			outcome, reason = "failed", "child_connection_cleanup_failed"
		}
		auditErr := s.audit.Append(destinationAuditEvent(s.claims, s.localID, s.peerID, "port_forward.destination_child", outcome, reason))
		if closeErr != nil || auditErr != nil {
			s.mu.Lock()
			s.auditErr = errors.Join(s.auditErr, closeErr, auditErr)
			s.mu.Unlock()
		}
		return nil, errors.Join(ErrDestinationSessionClosed, closeErr, auditErr)
	}
	s.children[childID] = child
	s.mu.Unlock()

	if err := s.audit.Append(destinationAuditEvent(s.claims, s.localID, s.peerID, "port_forward.destination_child", "success", "")); err != nil {
		return nil, errors.Join(err, child.Close())
	}
	if s.ctx.Err() != nil {
		_ = child.Close()
		return nil, ErrDestinationSessionClosed
	}
	return child, nil
}

func (s *DestinationSession) Done() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.done
}

func (s *DestinationSession) Close() error {
	return s.closeWithReason("parent_session_closed")
}

func (s *DestinationSession) closeWithReason(reason string) error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.cancel()
		children := make([]*destinationChildConn, 0, len(s.children))
		for _, child := range s.children {
			if child != nil {
				children = append(children, child)
			}
		}
		s.mu.Unlock()

		var errs []error
		// OpenChild rechecks s.closed after dialing and closes any late result.
		// Do not wait for pending opens here: a context-ignoring dialer or
		// blocked audit append must not hold parent teardown indefinitely.
		closeResults := make(chan error, len(children))
		for _, child := range children {
			go func(child *destinationChildConn) {
				closeResults <- child.Close()
			}(child)
		}
		for range children {
			if err := <-closeResults; err != nil {
				errs = append(errs, err)
			}
		}
		s.mu.Lock()
		if s.auditErr != nil {
			errs = append(errs, s.auditErr)
		}
		s.mu.Unlock()
		outcome := "success"
		if len(errs) > 0 {
			outcome = "failed"
			reason = reason + "_cleanup_failed"
		}
		errs = append(errs, s.audit.Append(destinationAuditEvent(s.claims, s.localID, s.peerID, "port_forward.destination_session_closed", outcome, reason)))
		s.closeErr = errors.Join(errs...)
		close(s.done)
	})
	return s.closeErr
}

func (s *DestinationSession) releaseReservation(id uint64) {
	s.mu.Lock()
	delete(s.children, id)
	s.mu.Unlock()
}

func (c *destinationChildConn) Close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		connErr := c.Conn.Close()
		outcome, reason := "success", ""
		if connErr != nil {
			outcome, reason = "failed", "child_connection_close_failed"
		}
		auditErr := c.session.audit.Append(destinationAuditEvent(
			c.session.claims,
			c.session.localID,
			c.session.peerID,
			"port_forward.destination_child_closed",
			outcome,
			reason,
		))
		c.session.mu.Lock()
		delete(c.session.children, c.id)
		if auditErr != nil {
			c.session.auditErr = errors.Join(c.session.auditErr, auditErr)
		}
		c.session.mu.Unlock()
		c.closeErr = errors.Join(connErr, auditErr)
	})
	return c.closeErr
}

func (c *destinationChildConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return ErrHalfCloseUnsupported
}

func (c *destinationChildConn) CloseRead() error {
	if reader, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return reader.CloseRead()
	}
	return ErrHalfCloseUnsupported
}

func destinationAuditEvent(claims Claims, localID, peerID mesh.DeviceID, eventType, outcome, reason string) audit.Event {
	return audit.Event{
		Type:         eventType,
		Outcome:      outcome,
		ActorID:      string(localID),
		PeerID:       string(peerID),
		Transport:    ProtocolTCP,
		Reason:       reason,
		ForwardingID: claims.ForwardingID,
		Direction:    string(claims.Direction),
		Destination:  net.JoinHostPort(claims.DestinationAddress, strconv.Itoa(int(claims.DestinationPort))),
	}
}

var _ ForwardingSession = (*DestinationSession)(nil)
