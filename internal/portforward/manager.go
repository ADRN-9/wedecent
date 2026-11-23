package portforward

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/mesh"
)

var (
	ErrManagerConfig         = errors.New("portforward: invalid manager configuration")
	ErrManagerClosed         = errors.New("portforward: manager is closed")
	ErrForwardExists         = errors.New("portforward: forwarding is already active")
	ErrForwardRevoked        = errors.New("portforward: forwarding authorization was revoked before start")
	ErrForwardNotFound       = errors.New("portforward: forwarding was not found")
	ErrWrongListenerDevice   = errors.New("portforward: capability is not bound to this listener device")
	ErrListenerAdminRequired = errors.New("portforward: router-administration authorization is required")
	ErrForwardLimit          = errors.New("portforward: resource limit reached")
	ErrPermissionDenied      = errors.New("portforward: dedicated forwarding permission denied")
	ErrPeerNotTrusted        = errors.New("portforward: remote device is not trusted")
)

type AuditWriter interface{ Append(audit.Event) error }

type Connector interface {
	// Open establishes one authenticated parent forwarding session and consumes
	// the forwarding capability once. It must authenticate the initiating endpoint
	// end-to-end and, for routed paths, separately authenticate the router TLS peer
	// against Authorization.Claims.Router. ctx bounds the handshake only; the
	// returned session remains alive until Close. Child TCP connections use it.
	Open(context.Context, Authorization) (ForwardingSession, error)
}

// ForwardingSession multiplexes authorized child TCP streams over one
// authenticated parent session. Close must terminate every child stream.
type ForwardingSession interface {
	OpenChild(context.Context) (net.Conn, error)
	Close() error
}

// PermissionAuthorizer must check the exact local-forward or remote-forward
// grant in Local Core. It must not fall back to terminal or mesh permissions.
type PermissionAuthorizer interface {
	AuthorizePortForward(context.Context, Claims) error
}

type ListenerAuthorizer interface {
	AuthorizePortForwardListener(context.Context, Claims) error
}

// PeerTrustChecker reads the persisted endpoint-device trust store. Errors are
// treated as loss of trust so an unreadable store cannot keep a session alive.
type PeerTrustChecker interface {
	IsTrusted(context.Context, string) (bool, error)
}

type ManagerLimits struct {
	MaxForwards              int
	MaxForwardsPerDevice     int
	MaxConnections           int
	MaxConnectionsPerDevice  int
	MaxConnectionsPerForward int
	MaxDuration              time.Duration
	IdleTimeout              time.Duration
	DialTimeout              time.Duration
}

type ManagerConfig struct {
	LocalDeviceID          mesh.DeviceID
	Verifier               Verifier
	ReplayPath             string
	AuthorizationPublicKey ed25519.PublicKey
	TrustChecker           PeerTrustChecker
	RouterTrustChecker     PeerTrustChecker
	TrustPollInterval      time.Duration
	PermissionAuthorizer   PermissionAuthorizer
	Connector              Connector
	ListenerAuthorizer     ListenerAuthorizer
	Audit                  AuditWriter
	Limits                 ManagerLimits
	Listen                 func(string, string) (net.Listener, error)
	Now                    func() time.Time
}

type ForwardInfo struct {
	ID                 string    `json:"id"`
	Direction          Direction `json:"direction"`
	ListenerAddress    string    `json:"listener_address"`
	DestinationAddress string    `json:"destination_address"`
	DestinationPort    uint16    `json:"destination_port"`
	ExpiresAt          time.Time `json:"expires_at"`
	ActiveConnections  int       `json:"active_connections"`
}

type Manager struct {
	ctx                  context.Context
	cancel               context.CancelFunc
	localID              mesh.DeviceID
	verifier             Verifier
	trustChecker         PeerTrustChecker
	routerTrustChecker   PeerTrustChecker
	trustPollInterval    time.Duration
	trustWatcherDone     chan struct{}
	backgroundErr       error
	permissionAuthorizer PermissionAuthorizer
	connector            Connector
	listenerAuthorizer   ListenerAuthorizer
	audit                AuditWriter
	limits               ManagerLimits
	listen               func(string, string) (net.Listener, error)
	now                  func() time.Time

	mu                sync.Mutex
	closed            bool
	forwards          map[string]*activeForward
	reservations      map[string]Claims
	forwardCounts     map[mesh.DeviceID]int
	deviceConnections map[mesh.DeviceID]int
	connections       int
	nextChild         uint64
	starts            sync.WaitGroup
}

type activeForward struct {
	claims          Claims
	session         ForwardingSession
	listener        net.Listener
	listenerAddress string
	ctx             context.Context
	cancel          context.CancelFunc
	done            chan struct{}
	stopDone        chan struct{}
	stopOnce        sync.Once
	stopErr         error
	children        map[uint64]*activeChild
}

type activeChild struct {
	id        uint64
	forwardID string
	devices   []mesh.DeviceID
	ctx       context.Context
	cancel    context.CancelFunc
	local     net.Conn
	remote    net.Conn
	done      chan struct{}
}

func NewManager(cfg ManagerConfig) (*Manager, error) {
	verifier := cfg.Verifier
	if verifier == nil && cfg.ReplayPath != "" && len(cfg.AuthorizationPublicKey) == ed25519.PublicKeySize {
		persistentVerifier, err := NewPersistentAuthorizationVerifier(cfg.ReplayPath, cfg.LocalDeviceID, cfg.AuthorizationPublicKey)
		if err != nil {
			return nil, ErrManagerConfig
		}
		verifier = persistentVerifier
	}
	if !deviceIDPattern.MatchString(string(cfg.LocalDeviceID)) || verifier == nil || cfg.PermissionAuthorizer == nil || cfg.Connector == nil || cfg.Audit == nil || !validManagerLimits(cfg.Limits) {
		return nil, ErrManagerConfig
	}
	listen := cfg.Listen
	if listen == nil {
		listen = net.Listen
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	pollInterval := cfg.TrustPollInterval
	if cfg.TrustChecker != nil || cfg.RouterTrustChecker != nil {
		if pollInterval == 0 {
			pollInterval = 250 * time.Millisecond
		}
		if pollInterval < 10*time.Millisecond || pollInterval > 5*time.Second {
			return nil, ErrManagerConfig
		}
	}
	managerCtx, cancel := context.WithCancel(context.Background())
	manager := &Manager{
		ctx:                  managerCtx,
		cancel:               cancel,
		localID:              cfg.LocalDeviceID,
		verifier:             verifier,
		trustChecker:         cfg.TrustChecker,
		routerTrustChecker:   cfg.RouterTrustChecker,
		trustPollInterval:    pollInterval,
		permissionAuthorizer: cfg.PermissionAuthorizer,
		connector:            cfg.Connector,
		listenerAuthorizer:   cfg.ListenerAuthorizer,
		audit:                cfg.Audit,
		limits:               cfg.Limits,
		listen:               listen,
		now:                  now,
		forwards:             make(map[string]*activeForward),
		reservations:         make(map[string]Claims),
		forwardCounts:        make(map[mesh.DeviceID]int),
		deviceConnections:    make(map[mesh.DeviceID]int),
	}
	if manager.trustChecker != nil || manager.routerTrustChecker != nil {
		manager.trustWatcherDone = make(chan struct{})
		go manager.watchTrust()
	}
	return manager, nil
}

func validManagerLimits(l ManagerLimits) bool {
	return l.MaxForwards >= 1 && l.MaxForwards <= 128 &&
		l.MaxForwardsPerDevice >= 1 && l.MaxForwardsPerDevice <= 32 &&
		l.MaxConnections >= 1 && l.MaxConnections <= 1024 &&
		l.MaxConnectionsPerDevice >= 1 && l.MaxConnectionsPerDevice <= 128 &&
		l.MaxConnectionsPerForward >= 1 && l.MaxConnectionsPerForward <= 64 &&
		l.MaxDuration >= time.Second && l.MaxDuration <= 24*time.Hour &&
		l.IdleTimeout >= 5*time.Second && l.IdleTimeout <= 15*time.Minute &&
		l.DialTimeout >= time.Second && l.DialTimeout <= 30*time.Second
}

func (m *Manager) Start(ctx context.Context, auth Authorization) (ForwardInfo, error) {
	if m == nil {
		return ForwardInfo{}, ErrManagerClosed
	}
	if ctx == nil {
		return ForwardInfo{}, ErrAuthorizationInvalid
	}
	startCtx, cancelStart := context.WithCancel(ctx)
	stopManagerCancel := context.AfterFunc(m.ctx, cancelStart)
	defer func() {
		stopManagerCancel()
		cancelStart()
	}()
	if err := startCtx.Err(); err != nil {
		return ForwardInfo{}, err
	}
	claims := cloneClaims(auth.Claims)
	if err := ValidateClaims(claims); err != nil {
		return ForwardInfo{}, err
	}
	if ListenerDevice(claims) != m.localID {
		return ForwardInfo{}, ErrWrongListenerDevice
	}
	if int(claims.Limits.MaxConnections) > m.limits.MaxConnectionsPerForward || time.Duration(claims.Limits.MaxDurationSeconds)*time.Second > m.limits.MaxDuration || time.Duration(claims.Limits.IdleTimeoutSeconds)*time.Second > m.limits.IdleTimeout {
		return ForwardInfo{}, ErrForwardLimit
	}
	if err := m.reserveForward(claims); err != nil {
		return ForwardInfo{}, err
	}
	defer m.starts.Done()
	reserved := true
	defer func() {
		if reserved {
			m.releaseForwardReservation(claims)
		}
	}()

	if err := ValidateRouteAuthorizationBinding(auth); err != nil {
		return ForwardInfo{}, err
	}
	peerID := remoteEndpointDevice(claims, m.localID)
	if peerID == "" {
		return ForwardInfo{}, ErrAuthorizationMismatch
	}
	if m.trustChecker == nil {
		return ForwardInfo{}, ErrPeerNotTrusted
	}
	trusted, trustErr := m.trustChecker.IsTrusted(startCtx, string(peerID))
	if trustErr != nil || !trusted {
		return ForwardInfo{}, errors.Join(ErrPeerNotTrusted, trustErr)
	}
	if claims.Router != "" {
		if m.routerTrustChecker == nil {
			return ForwardInfo{}, ErrRouterNotTrusted
		}
		routerTrusted, routerTrustErr := m.routerTrustChecker.IsTrusted(startCtx, string(claims.Router))
		if routerTrustErr != nil || !routerTrusted {
			return ForwardInfo{}, errors.Join(ErrRouterNotTrusted, routerTrustErr)
		}
	}
	verified, err := m.verifier.VerifyAndConsume(startCtx, auth)
	if err != nil {
		return ForwardInfo{}, err
	}
	if !sameClaims(claims, verified) {
		return ForwardInfo{}, ErrAuthorizationMismatch
	}
	if err := m.permissionAuthorizer.AuthorizePortForward(startCtx, claims); err != nil {
		if auditErr := m.record(claims, "port_forward.start", "denied", "permission_denied"); auditErr != nil {
			return ForwardInfo{}, auditErr
		}
		return ForwardInfo{}, err
	}
	if err := m.authorizeListener(startCtx, claims); err != nil {
		if auditErr := m.record(claims, "port_forward.start", "denied", "listener_policy_denied"); auditErr != nil {
			return ForwardInfo{}, auditErr
		}
		return ForwardInfo{}, err
	}
	if err := m.record(claims, "port_forward.start", "attempt", ""); err != nil {
		return ForwardInfo{}, err
	}

	if !m.hasReservation(claims.ForwardingID) {
		return ForwardInfo{}, ErrForwardRevoked
	}
	openCtx, cancelOpen := context.WithTimeout(startCtx, m.limits.DialTimeout)
	forwardSession, openErr := m.connector.Open(openCtx, cloneAuthorization(auth))
	openCtxErr := openCtx.Err()
	cancelOpen()
	if openErr == nil && openCtxErr != nil {
		openErr = openCtxErr
	}
	if openErr != nil || forwardSession == nil {
		if forwardSession != nil {
			_ = forwardSession.Close()
		}
		reason := "destination_session_open_failed"
		if auditErr := m.record(claims, "port_forward.start", "failed", reason); auditErr != nil {
			return ForwardInfo{}, auditErr
		}
		if openErr == nil {
			openErr = ErrManagerConfig
		}
		return ForwardInfo{}, fmt.Errorf("portforward: open destination session: %w", openErr)
	}
	sessionOwned := false
	defer func() {
		if !sessionOwned {
			_ = forwardSession.Close()
		}
	}()
	if !m.hasReservation(claims.ForwardingID) {
		return ForwardInfo{}, ErrForwardRevoked
	}

	address := net.JoinHostPort(claims.Listener.Address, strconv.Itoa(int(claims.Listener.Port)))
	listener, err := m.listen("tcp", address)
	if err == nil && (listener == nil || listener.Addr() == nil || !listenerMatchesPolicy(listener, claims)) {
		if listener != nil {
			_ = listener.Close()
		}
		err = ErrManagerConfig
	}
	if err != nil {
		_ = m.record(claims, "port_forward.start", "failed", "listener_bind_failed")
		return ForwardInfo{}, fmt.Errorf("portforward: bind listener: %w", err)
	}
	if err := startCtx.Err(); err != nil {
		_ = listener.Close()
		return ForwardInfo{}, err
	}

	now := m.now().UTC()
	deadline := now.Add(time.Duration(claims.Limits.MaxDurationSeconds) * time.Second)
	if authExpiry := time.UnixMilli(claims.ExpiresAtUnixMS); authExpiry.Before(deadline) {
		deadline = authExpiry
	}
	if managerDeadline := now.Add(m.limits.MaxDuration); managerDeadline.Before(deadline) {
		deadline = managerDeadline
	}
	forwardCtx, cancel := context.WithDeadline(m.ctx, deadline)
	f := &activeForward{
		claims:          claims,
		session:         forwardSession,
		listener:        listener,
		listenerAddress: listener.Addr().String(),
		ctx:             forwardCtx,
		cancel:          cancel,
		done:            make(chan struct{}),
		stopDone:        make(chan struct{}),
		children:        make(map[uint64]*activeChild),
	}
	m.mu.Lock()
	if err := startCtx.Err(); err != nil {
		m.mu.Unlock()
		cancel()
		_ = listener.Close()
		return ForwardInfo{}, err
	}
	if m.closed {
		m.mu.Unlock()
		cancel()
		_ = listener.Close()
		return ForwardInfo{}, ErrManagerClosed
	}
	if _, ok := m.reservations[claims.ForwardingID]; !ok {
		m.mu.Unlock()
		cancel()
		_ = listener.Close()
		return ForwardInfo{}, ErrForwardRevoked
	}
	if err := m.record(claims, "port_forward.started", "success", ""); err != nil {
		m.mu.Unlock()
		cancel()
		_ = listener.Close()
		return ForwardInfo{}, err
	}
	if err := ctx.Err(); err != nil {
		m.mu.Unlock()
		cancel()
		_ = listener.Close()
		return ForwardInfo{}, err
	}
	delete(m.reservations, claims.ForwardingID)
	m.forwards[claims.ForwardingID] = f
	m.mu.Unlock()
	sessionOwned = true
	reserved = false
	go m.acceptLoop(f)
	return m.info(f), nil
}

func (m *Manager) Stop(ctx context.Context, forwardingID string) error {
	return m.stop(ctx, forwardingID, "explicit_stop")
}

func (m *Manager) stop(ctx context.Context, forwardingID, reason string) error {
	if m == nil {
		return ErrManagerClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	f := m.forwards[forwardingID]
	m.mu.Unlock()
	if f == nil {
		return nil
	}
	err := m.terminate(f, reason)
	select {
	case <-f.done:
		return err
	case <-ctx.Done():
		return errors.Join(err, ctx.Err())
	}
}

func (m *Manager) RevokeDevice(ctx context.Context, deviceID mesh.DeviceID) (int, error) {
	if m == nil {
		return 0, ErrManagerClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !deviceIDPattern.MatchString(string(deviceID)) {
		return 0, ErrAuthorizationInvalid
	}

	m.mu.Lock()
	ids := make([]string, 0)
	for id, f := range m.forwards {
		if f.claims.InitiatingDevice == deviceID || f.claims.DestinationDevice == deviceID || f.claims.Router == deviceID {
			ids = append(ids, id)
		}
	}
	pending := make([]Claims, 0)
	for id, claims := range m.reservations {
		if claims.InitiatingDevice == deviceID || claims.DestinationDevice == deviceID || claims.Router == deviceID {
			delete(m.reservations, id)
			for _, device := range endpointDevices(claims) {
				decrement(m.forwardCounts, device)
			}
			pending = append(pending, claims)
		}
	}
	m.mu.Unlock()

	var errs []error
	for _, claims := range pending {
		if err := m.record(claims, "port_forward.revoked", "success", "device_revoked_before_start"); err != nil {
			errs = append(errs, err)
		}
	}
	for _, id := range ids {
		if err := m.stop(context.Background(), id, "device_revoked"); err != nil {
			errs = append(errs, err)
		}
	}
	return len(ids) + len(pending), errors.Join(errs...)
}

func (m *Manager) List() []ForwardInfo {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	forwards := make([]*activeForward, 0, len(m.forwards))
	for _, f := range m.forwards {
		forwards = append(forwards, f)
	}
	m.mu.Unlock()
	result := make([]ForwardInfo, 0, len(forwards))
	for _, f := range forwards {
		result = append(result, m.info(f))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	shouldCancel := !m.closed
	m.closed = true
	cancel := m.cancel
	watcherDone := m.trustWatcherDone
	m.mu.Unlock()
	if shouldCancel && cancel != nil {
		cancel()
	}
	m.starts.Wait()
	if watcherDone != nil {
		<-watcherDone
	}
	m.mu.Lock()
	ids := make([]string, 0, len(m.forwards))
	for id := range m.forwards {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	var errs []error
	for _, id := range ids {
		if err := m.stop(context.Background(), id, "manager_closed"); err != nil {
			errs = append(errs, err)
		}
	}
	m.mu.Lock()
	backgroundErr := m.backgroundErr
	m.mu.Unlock()
	errs = append(errs, backgroundErr)
	return errors.Join(errs...)
}

func remoteEndpointDevice(claims Claims, localID mesh.DeviceID) mesh.DeviceID {
	if claims.InitiatingDevice == localID {
		return claims.DestinationDevice
	}
	if claims.DestinationDevice == localID {
		return claims.InitiatingDevice
	}
	return ""
}

func (m *Manager) hasReservation(forwardingID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.reservations[forwardingID]
	return ok
}

func (m *Manager) referencedRouterDevices() []mesh.DeviceID {
	m.mu.Lock()
	routers := make(map[mesh.DeviceID]struct{}, len(m.forwards)+len(m.reservations))
	for _, forward := range m.forwards {
		if forward.claims.Router != "" {
			routers[forward.claims.Router] = struct{}{}
		}
	}
	for _, claims := range m.reservations {
		if claims.Router != "" {
			routers[claims.Router] = struct{}{}
		}
	}
	m.mu.Unlock()
	result := make([]mesh.DeviceID, 0, len(routers))
	for router := range routers {
		result = append(result, router)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func (m *Manager) referencedPeerDevices() []mesh.DeviceID {
	m.mu.Lock()
	peers := make(map[mesh.DeviceID]struct{}, len(m.forwards)+len(m.reservations))
	for _, forward := range m.forwards {
		if peer := remoteEndpointDevice(forward.claims, m.localID); peer != "" {
			peers[peer] = struct{}{}
		}
	}
	for _, claims := range m.reservations {
		if peer := remoteEndpointDevice(claims, m.localID); peer != "" {
			peers[peer] = struct{}{}
		}
	}
	m.mu.Unlock()
	result := make([]mesh.DeviceID, 0, len(peers))
	for peer := range peers {
		result = append(result, peer)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func (m *Manager) recordBackgroundError(err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	m.backgroundErr = errors.Join(m.backgroundErr, err)
	m.mu.Unlock()
}

func (m *Manager) watchTrust() {
	defer close(m.trustWatcherDone)
	ticker := time.NewTicker(m.trustPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if m.trustChecker != nil {
				for _, peerID := range m.referencedPeerDevices() {
					trusted, trustErr := m.trustChecker.IsTrusted(m.ctx, string(peerID))
					if m.ctx.Err() != nil {
						return
					}
					if trustErr != nil || !trusted {
						_, revokeErr := m.RevokeDevice(context.Background(), peerID)
						if trustErr != nil {
							m.recordBackgroundError(fmt.Errorf("portforward: peer trust check for %s failed: %w", peerID, trustErr))
						}
						if revokeErr != nil {
							m.recordBackgroundError(fmt.Errorf("portforward: revoke untrusted peer %s: %w", peerID, revokeErr))
						}
					}
				}
			}
			if m.routerTrustChecker != nil {
				for _, routerID := range m.referencedRouterDevices() {
					trusted, trustErr := m.routerTrustChecker.IsTrusted(m.ctx, string(routerID))
					if m.ctx.Err() != nil {
						return
					}
					if trustErr != nil || !trusted {
						_, revokeErr := m.RevokeDevice(context.Background(), routerID)
						if trustErr != nil {
							m.recordBackgroundError(fmt.Errorf("portforward: router trust check for %s failed: %w", routerID, trustErr))
						}
						if revokeErr != nil {
							m.recordBackgroundError(fmt.Errorf("portforward: revoke untrusted router %s: %w", routerID, revokeErr))
						}
					}
				}
			}
		}
	}
}

func (m *Manager) reserveForward(c Claims) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrManagerClosed
	}
	if _, ok := m.forwards[c.ForwardingID]; ok {
		return ErrForwardExists
	}
	if _, ok := m.reservations[c.ForwardingID]; ok {
		return ErrForwardExists
	}
	if len(m.forwards)+len(m.reservations) >= m.limits.MaxForwards {
		return ErrForwardLimit
	}
	devices := endpointDevices(c)
	for _, device := range devices {
		if m.forwardCounts[device] >= m.limits.MaxForwardsPerDevice {
			return ErrForwardLimit
		}
	}
	m.reservations[c.ForwardingID] = c
	m.starts.Add(1)
	for _, device := range devices {
		m.forwardCounts[device]++
	}
	return nil
}

func (m *Manager) releaseForwardReservation(c Claims) {
	m.mu.Lock()
	if _, ok := m.reservations[c.ForwardingID]; ok {
		delete(m.reservations, c.ForwardingID)
		for _, device := range endpointDevices(c) {
			decrement(m.forwardCounts, device)
		}
	}
	m.mu.Unlock()
}

func (m *Manager) authorizeListener(ctx context.Context, c Claims) error {
	ip, err := netip.ParseAddr(c.Listener.Address)
	if err != nil {
		return ErrAuthorizationInvalid
	}
	needsAdmin := c.Listener.Exposure != ExposureLoopback || c.Listener.Port < 1024
	if needsAdmin {
		if m.listenerAuthorizer == nil {
			return ErrListenerAdminRequired
		}
		if err := m.listenerAuthorizer.AuthorizePortForwardListener(ctx, c); err != nil {
			return fmt.Errorf("%w: %v", ErrListenerAdminRequired, err)
		}
	}
	if err := validateListenerExposure(ip, c.Listener.Exposure); err != nil {
		return err
	}
	return nil
}

func (m *Manager) acceptLoop(f *activeForward) {
	defer close(f.done)
	stopClose := context.AfterFunc(f.ctx, func() { _ = f.listener.Close() })
	defer stopClose()
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			reason := "listener_failed"
			if f.ctx.Err() != nil {
				reason = "expired_or_lifetime_limit"
			}
			_ = m.terminate(f, reason)
			return
		}
		child, ok := m.reserveChild(f, conn)
		if !ok {
			_ = conn.Close()
			continue
		}
		go m.handleChild(f, child)
	}
}

func (m *Manager) reserveChild(f *activeForward, local net.Conn) (*activeChild, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.forwards[f.claims.ForwardingID] != f || f.ctx.Err() != nil {
		return nil, false
	}
	if len(f.children) >= int(f.claims.Limits.MaxConnections) || len(f.children) >= m.limits.MaxConnectionsPerForward || m.connections >= m.limits.MaxConnections {
		return nil, false
	}
	devices := endpointDevices(f.claims)
	for _, device := range devices {
		if m.deviceConnections[device] >= m.limits.MaxConnectionsPerDevice {
			return nil, false
		}
	}
	m.nextChild++
	childCtx, cancel := context.WithCancel(f.ctx)
	child := &activeChild{id: m.nextChild, forwardID: f.claims.ForwardingID, devices: devices, ctx: childCtx, cancel: cancel, local: local, done: make(chan struct{})}
	f.children[child.id] = child
	m.connections++
	for _, device := range devices {
		m.deviceConnections[device]++
	}
	return child, true
}

func (m *Manager) handleChild(f *activeForward, child *activeChild) {
	defer func() {
		if err := m.releaseChild(f, child); err != nil {
			auditErr := m.record(f.claims, "port_forward.connection_cleanup", "failed", "connection_close_failed")
			m.recordBackgroundError(errors.Join(err, auditErr))
		}
		close(child.done)
	}()
	if err := m.record(f.claims, "port_forward.connection_opened", "attempt", ""); err != nil {
		go m.terminate(f, "audit_persistence_failed")
		return
	}
	dialCtx, cancel := context.WithTimeout(child.ctx, m.limits.DialTimeout)
	remote, err := f.session.OpenChild(dialCtx)
	dialErr := dialCtx.Err()
	cancel()
	if err == nil && dialErr != nil {
		err = dialErr
	}
	if err != nil {
		if remote != nil {
			_ = remote.Close()
		}
		if auditErr := m.record(f.claims, "port_forward.connection_opened", "failed", "destination_open_failed"); auditErr != nil {
			go m.terminate(f, "audit_persistence_failed")
		}
		return
	}
	m.mu.Lock()
	if child.ctx.Err() != nil || m.forwards[child.forwardID] != f {
		m.mu.Unlock()
		_ = remote.Close()
		return
	}
	child.remote = remote
	m.mu.Unlock()
	if err := m.record(f.claims, "port_forward.connection_opened", "success", ""); err != nil {
		go m.terminate(f, "audit_persistence_failed")
		return
	}
	idle := time.Duration(f.claims.Limits.IdleTimeoutSeconds) * time.Second
	if idle > m.limits.IdleTimeout {
		idle = m.limits.IdleTimeout
	}
	err = bridge(child.ctx, child.local, remote, idle)
	reason, outcome := "connection_closed", "success"
	if err != nil {
		reason, outcome = "connection_failed", "failed"
	}
	if err := m.record(f.claims, "port_forward.connection_closed", outcome, reason); err != nil {
		go m.terminate(f, "audit_persistence_failed")
	}
}

func (m *Manager) releaseChild(f *activeForward, child *activeChild) error {
	child.cancel()
	var closeErrs []error
	if err := child.local.Close(); err != nil && !expectedClosedConnError(err) {
		closeErrs = append(closeErrs, err)
	}
	if child.remote != nil {
		if err := child.remote.Close(); err != nil && !expectedClosedConnError(err) {
			closeErrs = append(closeErrs, err)
		}
	}
	m.mu.Lock()
	if _, ok := f.children[child.id]; ok {
		delete(f.children, child.id)
		if m.connections > 0 {
			m.connections--
		}
		for _, device := range child.devices {
			decrement(m.deviceConnections, device)
		}
	}
	m.mu.Unlock()
	return errors.Join(closeErrs...)
}

func (m *Manager) terminate(f *activeForward, reason string) error {
	f.stopOnce.Do(func() {
		m.mu.Lock()
		f.cancel()
		var cleanupErrs []error
		if err := f.listener.Close(); err != nil && !expectedClosedConnError(err) {
			cleanupErrs = append(cleanupErrs, err)
		}
		children := make([]*activeChild, 0, len(f.children))
		for _, child := range f.children {
			children = append(children, child)
			child.cancel()
			if err := child.local.Close(); err != nil && !expectedClosedConnError(err) {
				cleanupErrs = append(cleanupErrs, err)
			}
			if child.remote != nil {
				if err := child.remote.Close(); err != nil && !expectedClosedConnError(err) {
					cleanupErrs = append(cleanupErrs, err)
				}
			}
		}
		m.mu.Unlock()
		for _, child := range children {
			<-child.done
		}
		m.mu.Lock()
		if m.forwards[f.claims.ForwardingID] == f {
			delete(m.forwards, f.claims.ForwardingID)
			for _, device := range endpointDevices(f.claims) {
				decrement(m.forwardCounts, device)
			}
		}
		m.mu.Unlock()
		var sessionErr error
		if f.session != nil {
			sessionErr = f.session.Close()
		}
		outcome := "success"
		auditReason := reason
		if len(cleanupErrs) > 0 || sessionErr != nil {
			outcome = "failed"
			auditReason = "forward_cleanup_failed"
		}
		auditErr := m.record(f.claims, "port_forward.stopped", outcome, auditReason)
		f.stopErr = errors.Join(errors.Join(cleanupErrs...), sessionErr, auditErr)
		close(f.stopDone)
	})
	<-f.stopDone
	return f.stopErr
}

func (m *Manager) record(c Claims, eventType, outcome, reason string) error {
	return m.audit.Append(audit.Event{
		Type:         eventType,
		Outcome:      outcome,
		ActorID:      string(c.InitiatingDevice),
		PeerID:       string(c.DestinationDevice),
		Transport:    ProtocolTCP,
		Reason:       reason,
		ForwardingID: c.ForwardingID,
		Direction:    string(c.Direction),
		Destination:  net.JoinHostPort(c.DestinationAddress, strconv.Itoa(int(c.DestinationPort))),
	})
}

func (m *Manager) info(f *activeForward) ForwardInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	return ForwardInfo{
		ID:                 f.claims.ForwardingID,
		Direction:          f.claims.Direction,
		ListenerAddress:    f.listenerAddress,
		DestinationAddress: f.claims.DestinationAddress,
		DestinationPort:    f.claims.DestinationPort,
		ExpiresAt:          time.UnixMilli(f.claims.ExpiresAtUnixMS).UTC(),
		ActiveConnections:  len(f.children),
	}
}

func endpointDevices(c Claims) []mesh.DeviceID {
	devices := []mesh.DeviceID{c.InitiatingDevice, c.DestinationDevice}
	if c.Router != "" {
		devices = append(devices, c.Router)
	}
	unique := make([]mesh.DeviceID, 0, len(devices))
	seen := make(map[mesh.DeviceID]struct{}, len(devices))
	for _, device := range devices {
		if _, ok := seen[device]; !ok {
			seen[device] = struct{}{}
			unique = append(unique, device)
		}
	}
	return unique
}

func decrement(values map[mesh.DeviceID]int, key mesh.DeviceID) {
	if values[key] <= 1 {
		delete(values, key)
	} else {
		values[key]--
	}
}

func sameClaims(a, b Claims) bool {
	left, err1 := canonicalMessage("comparison", a)
	right, err2 := canonicalMessage("comparison", b)
	return err1 == nil && err2 == nil && string(left) == string(right)
}

func expectedClosedConnError(err error) bool {
	return err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}
func (c idleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}
func (c idleConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return c.Conn.Close()
}

func bridge(ctx context.Context, left, right net.Conn, idle time.Duration) error {
	l := idleConn{Conn: left, idle: idle}
	r := idleConn{Conn: right, idle: idle}
	var closeOnce sync.Once
	var closeErr error
	closeBoth := func() {
		closeOnce.Do(func() {
			var errs []error
			if err := left.Close(); err != nil && !expectedClosedConnError(err) {
				errs = append(errs, err)
			}
			if err := right.Close(); err != nil && !expectedClosedConnError(err) {
				errs = append(errs, err)
			}
			closeErr = errors.Join(errs...)
		})
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	results := make(chan error, 2)
	pump := func(dst, src idleConn) {
		_, err := io.Copy(dst, src)
		if err == nil {
			_ = dst.CloseWrite()
		} else {
			closeBoth()
		}
		results <- err
	}
	go pump(r, l)
	go pump(l, r)
	var first error
	select {
	case first = <-results:
	case <-ctx.Done():
		closeBoth()
		first = ctx.Err()
	}
	if first != nil && !errors.Is(first, io.EOF) {
		closeBoth()
	}
	select {
	case second := <-results:
		if first == nil {
			first = second
		}
	case <-ctx.Done():
		closeBoth()
		if first == nil {
			first = ctx.Err()
		}
	}
	closeBoth()
	if errors.Is(first, io.EOF) {
		first = nil
	}
	return errors.Join(first, closeErr)
}

func listenerMatchesPolicy(listener net.Listener, claims Claims) bool {
	actual, ok := listener.Addr().(*net.TCPAddr)
	if !ok || actual.Port != int(claims.Listener.Port) {
		return false
	}
	actualIP, ok := netip.AddrFromSlice(actual.IP)
	if !ok {
		return false
	}
	expectedIP, err := netip.ParseAddr(claims.Listener.Address)
	return err == nil && actualIP.Unmap() == expectedIP
}
