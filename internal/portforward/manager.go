package portforward

import (
	"context"
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
)

type AuditWriter interface{ Append(audit.Event) error }

type Connector interface {
	// Open must establish the authenticated WeDecent forwarding stream. The destination endpoint
	// must independently verify the same capability and resolve/dial only approved destination IPs.
	Open(context.Context, Authorization) (net.Conn, error)
}

// PermissionAuthorizer must check the exact local-forward or remote-forward
// grant in Local Core. It must not fall back to terminal or mesh permissions.
type PermissionAuthorizer interface {
	AuthorizePortForward(context.Context, Claims) error
}

type ListenerAuthorizer interface {
	AuthorizePortForwardListener(context.Context, Claims) error
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
	LocalDeviceID       mesh.DeviceID
	Verifier            Verifier
	PermissionAuthorizer PermissionAuthorizer
	Connector           Connector
	ListenerAuthorizer ListenerAuthorizer
	Audit              AuditWriter
	Limits             ManagerLimits
	Listen             func(string, string) (net.Listener, error)
	Now                func() time.Time
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
	localID              mesh.DeviceID
	verifier             Verifier
	permissionAuthorizer PermissionAuthorizer
	connector            Connector
	listenerAuthorizer ListenerAuthorizer
	audit              AuditWriter
	limits             ManagerLimits
	listen             func(string, string) (net.Listener, error)
	now                func() time.Time

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
	authorization   Authorization
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
	if !deviceIDPattern.MatchString(string(cfg.LocalDeviceID)) || cfg.Verifier == nil || cfg.PermissionAuthorizer == nil || cfg.Connector == nil || cfg.Audit == nil || !validManagerLimits(cfg.Limits) {
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
	return &Manager{
		localID:              cfg.LocalDeviceID,
		verifier:             cfg.Verifier,
		permissionAuthorizer: cfg.PermissionAuthorizer,
		connector:            cfg.Connector,
		listenerAuthorizer: cfg.ListenerAuthorizer,
		audit:              cfg.Audit,
		limits:             cfg.Limits,
		listen:             listen,
		now:                now,
		forwards:           make(map[string]*activeForward),
		reservations:       make(map[string]Claims),
		forwardCounts:      make(map[mesh.DeviceID]int),
		deviceConnections:  make(map[mesh.DeviceID]int),
	}, nil
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
	if err := ctx.Err(); err != nil {
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

	verified, err := m.verifier.VerifyAndConsume(ctx, auth)
	if err != nil {
		return ForwardInfo{}, err
	}
	if !sameClaims(claims, verified) {
		return ForwardInfo{}, ErrAuthorizationMismatch
	}
	if err := ValidateRouteAuthorizationBinding(auth); err != nil {
		return ForwardInfo{}, err
	}
	if err := m.permissionAuthorizer.AuthorizePortForward(ctx, claims); err != nil {
		if auditErr := m.record(claims, "port_forward.start", "denied", "permission_denied"); auditErr != nil {
			return ForwardInfo{}, auditErr
		}
		return ForwardInfo{}, err
	}
	if err := m.authorizeListener(ctx, claims); err != nil {
		if auditErr := m.record(claims, "port_forward.start", "denied", "listener_policy_denied"); auditErr != nil {
			return ForwardInfo{}, auditErr
		}
		return ForwardInfo{}, err
	}
	if err := m.record(claims, "port_forward.start", "attempt", ""); err != nil {
		return ForwardInfo{}, err
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
	if err := ctx.Err(); err != nil {
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
	forwardCtx, cancel := context.WithDeadline(context.Background(), deadline)
	f := &activeForward{
		claims:          claims,
		authorization:   cloneAuthorization(auth),
		listener:        listener,
		listenerAddress: listener.Addr().String(),
		ctx:             forwardCtx,
		cancel:          cancel,
		done:            make(chan struct{}),
		stopDone:        make(chan struct{}),
		children:        make(map[uint64]*activeChild),
	}
	m.mu.Lock()
	if err := ctx.Err(); err != nil {
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
	reserved = false
	go m.acceptLoop(f)
	return m.info(f), nil
}

func (m *Manager) Stop(ctx context.Context, forwardingID string) error {
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
	err := m.terminate(f, "explicit_stop")
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
		if err := m.Stop(context.Background(), id); err != nil {
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
	m.closed = true
	m.mu.Unlock()
	m.starts.Wait()
	m.mu.Lock()
	ids := make([]string, 0, len(m.forwards))
	for id := range m.forwards {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	var errs []error
	for _, id := range ids {
		if err := m.Stop(context.Background(), id); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
	defer func() { m.releaseChild(f, child); close(child.done) }()
	if err := m.record(f.claims, "port_forward.connection_opened", "attempt", ""); err != nil {
		go m.terminate(f, "audit_persistence_failed")
		return
	}
	dialCtx, cancel := context.WithTimeout(child.ctx, m.limits.DialTimeout)
	remote, err := m.connector.Open(dialCtx, cloneAuthorization(f.authorization))
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

func (m *Manager) releaseChild(f *activeForward, child *activeChild) {
	child.cancel()
	_ = child.local.Close()
	if child.remote != nil {
		_ = child.remote.Close()
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
}

func (m *Manager) terminate(f *activeForward, reason string) error {
	f.stopOnce.Do(func() {
		m.mu.Lock()
		f.cancel()
		_ = f.listener.Close()
		children := make([]*activeChild, 0, len(f.children))
		for _, child := range f.children {
			children = append(children, child)
			child.cancel()
			_ = child.local.Close()
			if child.remote != nil {
				_ = child.remote.Close()
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
		f.stopErr = m.record(f.claims, "port_forward.stopped", "success", reason)
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
	closeBoth := func() { _ = left.Close(); _ = right.Close() }
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
		return nil
	}
	return first
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
