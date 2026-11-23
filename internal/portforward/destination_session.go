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
)

type DestinationConfig struct {
	LocalDeviceID        mesh.DeviceID
	AuthenticatedPeerID  mesh.DeviceID
	Verifier             Verifier
	PermissionAuthorizer PermissionAuthorizer
	Resolver             IPResolver
	Dialer               ContextDialer
	Policy               DestinationPolicy
	Audit                AuditWriter
	MaxConnections       int
	DialTimeout          time.Duration
}

type DestinationSession struct {
	claims      Claims
	localID     mesh.DeviceID
	peerID      mesh.DeviceID
	approved    ApprovedDestination
	policy      DestinationPolicy
	dialer      ContextDialer
	audit       AuditWriter
	maxChildren int
	dialTimeout time.Duration
	ctx         context.Context
	cancel      context.CancelFunc

	mu        sync.Mutex
	closed    bool
	nextChild uint64
	children  map[uint64]*destinationChildConn
	opens     sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
	auditErr  error
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
		cfg.Verifier == nil || cfg.PermissionAuthorizer == nil ||
		cfg.Resolver == nil || cfg.Dialer == nil || cfg.Audit == nil ||
		cfg.MaxConnections < 1 || cfg.MaxConnections > 64 ||
		cfg.DialTimeout < time.Second || cfg.DialTimeout > 30*time.Second {
		return nil, ErrManagerConfig
	}
	if err := cfg.Policy.Validate(); err != nil {
		return nil, err
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
	if claims.Router != "" {
		peerDevice = claims.Router
	}
	if cfg.LocalDeviceID != destinationDevice {
		return nil, ErrWrongDestinationDevice
	}
	if cfg.AuthenticatedPeerID != peerDevice {
		return nil, ErrAuthorizationMismatch
	}

	verified, err := cfg.Verifier.VerifyAndConsume(ctx, auth)
	if err != nil {
		return nil, err
	}
	if !sameClaims(claims, verified) {
		return nil, ErrAuthorizationMismatch
	}
	if err := ValidateRouteAuthorizationBinding(auth); err != nil {
		return nil, err
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
	maxDurationDeadline := time.UnixMilli(claims.IssuedAtUnixMS).Add(time.Duration(claims.Limits.MaxDurationSeconds) * time.Second)
	if maxDurationDeadline.Before(deadline) {
		deadline = maxDurationDeadline
	}
	sessionCtx, cancel := context.WithDeadline(context.Background(), deadline)
	session := &DestinationSession{
		claims:      claims,
		localID:     cfg.LocalDeviceID,
		peerID:      cfg.AuthenticatedPeerID,
		approved:    approved,
		policy:      cfg.Policy,
		dialer:      cfg.Dialer,
		audit:       cfg.Audit,
		maxChildren: min(int(claims.Limits.MaxConnections), cfg.MaxConnections),
		dialTimeout: cfg.DialTimeout,
		ctx:         sessionCtx,
		cancel:      cancel,
		children:    make(map[uint64]*destinationChildConn),
	}
	go func() {
		<-sessionCtx.Done()
		_ = session.Close()
	}()
	return session, nil
}

func (s *DestinationSession) OpenChild(ctx context.Context) (net.Conn, error) {
	if s == nil || ctx == nil {
		return nil, ErrDestinationSessionClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.closed {
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
	s.opens.Add(1)
	s.mu.Unlock()
	defer s.opens.Done()

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

	child := &destinationChildConn{Conn: conn, session: s, id: childID}
	s.mu.Lock()
	if s.closed || s.children[childID] != nil {
		delete(s.children, childID)
		s.mu.Unlock()
		_ = conn.Close()
		return nil, ErrDestinationSessionClosed
	}
	s.children[childID] = child
	s.mu.Unlock()

	if err := s.audit.Append(destinationAuditEvent(s.claims, s.localID, s.peerID, "port_forward.destination_child", "success", "")); err != nil {
		_ = child.Close()
		return nil, err
	}
	if s.ctx.Err() != nil {
		_ = child.Close()
		return nil, ErrDestinationSessionClosed
	}
	return child, nil
}

func (s *DestinationSession) Close() error {
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
		for _, child := range children {
			if err := child.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		s.opens.Wait()
		s.mu.Lock()
		errs = append(errs, s.auditErr)
		s.mu.Unlock()
		errs = append(errs, s.audit.Append(destinationAuditEvent(s.claims, s.localID, s.peerID, "port_forward.destination_session_closed", "success", "")))
		s.closeErr = errors.Join(errs...)
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
		auditErr := c.session.audit.Append(destinationAuditEvent(
			c.session.claims,
			c.session.localID,
			c.session.peerID,
			"port_forward.destination_child_closed",
			"success",
			"",
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
