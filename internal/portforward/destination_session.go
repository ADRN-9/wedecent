package portforward

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/mesh"
)

const destinationSessionCloseTimeout = 5 * time.Second

var (
	ErrWrongDestinationDevice   = errors.New("portforward: capability is not bound to this destination device")
	ErrDestinationSessionClosed = errors.New("portforward: destination forwarding session is closed")
	ErrRouterIdentityMismatch   = errors.New("portforward: authenticated router identity does not match authorization")
	ErrRouterNotTrusted         = errors.New("portforward: routing trust domain does not trust the router")
	ErrDestinationCleanupIncomplete = errors.New("portforward: destination cleanup did not finish before its deadline")
	ErrDestinationAuditIncomplete = errors.New("portforward: destination audit operation did not finish before its deadline")
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
	closeTimeout       time.Duration
	ctx               context.Context
	cancel            context.CancelFunc

	mu        sync.Mutex
	closed    bool
	nextChild uint64
	children  map[uint64]*destinationChildConn
	auditSlots chan struct{}
	closeOnce sync.Once
	closeErr  error
	auditErr  error
	done      chan struct{}
}

type destinationChildConn struct {
	net.Conn
	session *DestinationSession
	id      uint64

	doneMu    sync.Mutex
	done      chan struct{}
	doneOnce  sync.Once
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
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
	if err := appendDestinationAuditContext(ctx, cfg.Audit, destinationAuditEvent(claims, cfg.LocalDeviceID, cfg.AuthenticatedPeerID, "port_forward.destination_session_opened", "success", "")); err != nil {
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
		closeTimeout:      destinationSessionCloseTimeout,
		ctx:               sessionCtx,
		cancel:            cancel,
		children:          make(map[uint64]*destinationChildConn),
		auditSlots:        make(chan struct{}, 1),
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
	opCtx, cancelOp := context.WithCancel(ctx)
	stopParentCancel := context.AfterFunc(s.ctx, cancelOp)
	defer func() {
		stopParentCancel()
		cancelOp()
	}()

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

	if err := s.appendAudit(opCtx, destinationAuditEvent(s.claims, s.localID, s.peerID, "port_forward.destination_child", "attempt", "")); err != nil {
		s.releaseReservation(childID)
		return nil, err
	}
	if err := opCtx.Err(); err != nil {
		s.releaseReservation(childID)
		if s.ctx.Err() != nil {
			return nil, ErrDestinationSessionClosed
		}
		return nil, err
	}

	dialCtx, cancelDial := context.WithTimeout(opCtx, s.dialTimeout)
	conn, dialErr := DialApprovedTCP(dialCtx, s.dialer, s.policy, s.approved)
	cancelDial()
	if dialErr != nil {
		s.releaseReservation(childID)
		auditErr := s.appendAudit(opCtx, destinationAuditEvent(s.claims, s.localID, s.peerID, "port_forward.destination_child", "failed", "destination_dial_failed"))
		return nil, errors.Join(dialErr, auditErr)
	}

	if s.idleTimeout > 0 {
		conn = newIdleConn(conn, s.idleTimeout)
	}
	child := &destinationChildConn{
		Conn: conn, session: s, id: childID, done: make(chan struct{}),
	}
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil || opCtx.Err() != nil || s.children[childID] != nil {
		delete(s.children, childID)
		s.mu.Unlock()
		child.startClose(time.Now().Add(s.cleanupTimeout()))
		if s.ctx.Err() != nil {
			return nil, ErrDestinationSessionClosed
		}
		return nil, opCtx.Err()
	}
	s.children[childID] = child
	s.mu.Unlock()

	if err := s.appendAudit(opCtx, destinationAuditEvent(s.claims, s.localID, s.peerID, "port_forward.destination_child", "success", "")); err != nil {
		return nil, errors.Join(err, s.closeWithReason("child_open_audit_failed"))
	}
	if opCtx.Err() != nil {
		return nil, ErrDestinationSessionClosed
	}
	select {
	case <-child.Done():
		return nil, ErrDestinationSessionClosed
	default:
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
		close(s.done)
		s.mu.Unlock()

		deadline := time.Now().Add(s.cleanupTimeout())
		for _, child := range children {
			child.Cancel()
			child.startClose(deadline)
		}

		var errs []error
		if len(children) > 0 {
			timer := time.NewTimer(time.Until(deadline))
			cases := make([]reflect.SelectCase, 0, len(children)+1)
			for _, child := range children {
				cases = append(cases, reflect.SelectCase{
					Dir: reflect.SelectRecv, Chan: reflect.ValueOf(child.closeDone),
				})
			}
			timerIndex := len(cases)
			cases = append(cases, reflect.SelectCase{
				Dir: reflect.SelectRecv, Chan: reflect.ValueOf(timer.C),
			})
			pending := len(children)
			for pending > 0 {
				chosen, _, _ := reflect.Select(cases)
				if chosen == timerIndex {
					errs = append(errs, ErrDestinationCleanupIncomplete)
					break
				}
				if childErr := children[chosen].closeErr; childErr != nil {
					errs = append(errs, childErr)
				}
				cases[chosen].Chan = reflect.ValueOf(nil)
				pending--
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
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
			reason += "_cleanup_failed"
		}
		errs = append(errs, s.appendAuditUntil(deadline, destinationAuditEvent(
			s.claims, s.localID, s.peerID, "port_forward.destination_session_closed", outcome, reason,
		)))
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

func (s *DestinationSession) releaseReservation(id uint64) {
	s.mu.Lock()
	delete(s.children, id)
	s.mu.Unlock()
}

func (c *destinationChildConn) doneChannel() chan struct{} {
	c.doneMu.Lock()
	defer c.doneMu.Unlock()
	if c.done == nil {
		c.done = make(chan struct{})
	}
	return c.done
}

func (c *destinationChildConn) Done() <-chan struct{} {
	if c == nil {
		return nil
	}
	return c.doneChannel()
}

// Cancel signals closure and interrupts pending network I/O without waiting
// for the potentially blocking underlying Conn.Close call.
func (c *destinationChildConn) Cancel() {
	if c == nil {
		return
	}
	c.doneOnce.Do(func() {
		close(c.doneChannel())
		if c.Conn != nil {
			_ = c.Conn.SetDeadline(time.Now())
		}
	})
}

func (c *destinationChildConn) startClose(deadline time.Time) <-chan struct{} {
	c.Cancel()
	c.closeOnce.Do(func() {
		c.closeDone = make(chan struct{})
		go func() {
			connErr := c.Conn.Close()
			outcome, reason := "success", ""
			if connErr != nil {
				outcome, reason = "failed", "child_connection_close_failed"
			}
			auditErr := c.session.appendAuditUntil(deadline, destinationAuditEvent(
				c.session.claims, c.session.localID, c.session.peerID,
				"port_forward.destination_child_closed", outcome, reason,
			))
			c.session.mu.Lock()
			delete(c.session.children, c.id)
			if auditErr != nil {
				c.session.auditErr = errors.Join(c.session.auditErr, auditErr)
			}
			c.session.mu.Unlock()
			c.closeErr = errors.Join(connErr, auditErr)
			close(c.closeDone)
		}()
	})
	return c.closeDone
}

func (c *destinationChildConn) Close() error {
	if c == nil {
		return nil
	}
	timeout := destinationSessionCloseTimeout
	if c.session != nil {
		timeout = c.session.cleanupTimeout()
	}
	deadline := time.Now().Add(timeout)
	done := c.startClose(deadline)
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-done:
		return c.closeErr
	case <-timer.C:
		return ErrDestinationCleanupIncomplete
	}
}

func (s *DestinationSession) cleanupTimeout() time.Duration {
	if s == nil || s.closeTimeout <= 0 {
		return destinationSessionCloseTimeout
	}
	return s.closeTimeout
}

func (s *DestinationSession) appendAudit(ctx context.Context, event audit.Event) error {
	if s == nil || ctx == nil || s.audit == nil {
		return ErrDestinationAuditIncomplete
	}
	s.mu.Lock()
	if s.auditSlots == nil {
		s.auditSlots = make(chan struct{}, 1)
	}
	slots := s.auditSlots
	s.mu.Unlock()
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return errors.Join(ErrDestinationAuditIncomplete, ctx.Err())
	}
	result := make(chan error, 1)
	go func() {
		defer func() { <-slots }()
		result <- s.audit.Append(event)
	}()
	select {
	case err := <-result:
		if ctx.Err() != nil {
			return errors.Join(ErrDestinationAuditIncomplete, ctx.Err(), err)
		}
		return err
	case <-ctx.Done():
		return errors.Join(ErrDestinationAuditIncomplete, ctx.Err())
	}
}

func (s *DestinationSession) appendAuditUntil(deadline time.Time, event audit.Event) error {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	return s.appendAudit(ctx, event)
}

func appendDestinationAuditContext(ctx context.Context, writer AuditWriter, event audit.Event) error {
	if ctx == nil || writer == nil {
		return ErrDestinationAuditIncomplete
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrDestinationAuditIncomplete, err)
	}
	result := make(chan error, 1)
	go func() { result <- writer.Append(event) }()
	select {
	case err := <-result:
		if ctx.Err() != nil {
			return errors.Join(ErrDestinationAuditIncomplete, ctx.Err(), err)
		}
		return err
	case <-ctx.Done():
		return errors.Join(ErrDestinationAuditIncomplete, ctx.Err())
	}
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


func appendDestinationAuditUntil(writer AuditWriter, event audit.Event, deadline time.Time) error {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	return appendDestinationAuditContext(ctx, writer, event)
}
