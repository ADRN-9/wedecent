package coreapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/mesh"
)

var (
	ErrInvalidConnectionRequest = errors.New("invalid connection request")
	ErrConnectionNotFound       = errors.New("connection not found")
	ErrConnectionLimit          = errors.New("connection limit reached")
	ErrConnectionOperation      = errors.New("connection operation failed")
	ErrConnectionServiceClosed  = errors.New("connection service is closed")
)

const (
	DefaultMaxCoreConnections = 32
	maxConnectionIDAttempts   = 8
)

type ConnectionHandle interface {
	Close() error
}

// ObservableConnectionHandle lets a backend report that its underlying
// authenticated session ended independently of a local disconnect request.
// Done must be closed exactly once and must never carry secret/error detail.
type ObservableConnectionHandle interface {
	ConnectionHandle
	Done() <-chan struct{}
}

type OpenedConnection struct {
	Path   v1.ConnectionPath
	Route  *mesh.Route
	Handle ConnectionHandle
}

// ConnectionBackend establishes an already-authenticated application
// connection. It owns grant acquisition, path selection, dialing, TLS identity
// verification, and any route authorization required by the selected path.
// The Local Core manager deliberately does not duplicate those decisions.
type ConnectionBackend interface {
	Open(context.Context, string) (OpenedConnection, error)
}

type ConnectionServiceConfig struct {
	Backend   ConnectionBackend
	Network   *NetworkReadService
	MaxActive int
	Random    io.Reader
	Now       func() time.Time
}

type activeConnection struct {
	public       v1.Connection
	handle       ConnectionHandle
	closing      bool
	suppressDone bool
	token        *struct{}
}

type ConnectionService struct {
	backend ConnectionBackend
	network *NetworkReadService
	max     int
	random  io.Reader
	now     func() time.Time

	shutdownCtx context.Context
	shutdown    context.CancelFunc

	mu       sync.Mutex
	opening  int
	active   map[string]activeConnection
	reserved map[string]struct{}
	closed   bool
}

var _ v1.ConnectionService = (*ConnectionService)(nil)

func NewConnectionService(cfg ConnectionServiceConfig) (*ConnectionService, error) {
	if cfg.Backend == nil {
		return nil, errors.New("connection backend is required")
	}
	if cfg.Network == nil {
		return nil, errors.New("network status service is required")
	}
	maxActive := cfg.MaxActive
	if maxActive == 0 {
		maxActive = DefaultMaxCoreConnections
	}
	if maxActive < 1 || maxActive > 1024 {
		return nil, errors.New("connection limit must be between 1 and 1024")
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	shutdownCtx, shutdown := context.WithCancel(context.Background())
	return &ConnectionService{
		backend:     cfg.Backend,
		network:     cfg.Network,
		max:         maxActive,
		random:      random,
		now:         now,
		shutdownCtx: shutdownCtx,
		shutdown:    shutdown,
		active:      make(map[string]activeConnection),
		reserved:    make(map[string]struct{}),
	}, nil
}

func (s *ConnectionService) Connect(ctx context.Context, req v1.ConnectRequest) (v1.Connection, error) {
	if err := ctx.Err(); err != nil {
		return v1.Connection{}, err
	}
	if !validPublicID(req.DeviceID) {
		return v1.Connection{}, ErrInvalidConnectionRequest
	}
	if err := s.reserveOpening(); err != nil {
		return v1.Connection{}, err
	}

	connectionID, err := s.reserveConnectionID()
	if err != nil {
		s.releaseOpening()
		if errors.Is(err, ErrConnectionServiceClosed) {
			return v1.Connection{}, err
		}
		return v1.Connection{}, fmt.Errorf("%w: generate connection ID", ErrConnectionOperation)
	}
	reserved := true
	defer func() {
		if reserved {
			s.releaseOpeningAndID(connectionID)
		}
	}()

	requestCtx := ctx
	openCtx, cancelOpen := context.WithCancel(requestCtx)
	stopShutdownCancel := context.AfterFunc(s.shutdownCtx, cancelOpen)
	defer func() {
		stopShutdownCancel()
		cancelOpen()
	}()

	opened, err := s.backend.Open(openCtx, req.DeviceID)
	if err != nil {
		if requestErr := requestCtx.Err(); requestErr != nil {
			return v1.Connection{}, requestErr
		}
		if s.isClosed() {
			return v1.Connection{}, ErrConnectionServiceClosed
		}
		if openErr := openCtx.Err(); openErr != nil {
			return v1.Connection{}, openErr
		}
		return v1.Connection{}, fmt.Errorf("%w: open backend", ErrConnectionOperation)
	}
	if opened.Handle == nil || !validConnectionPath(opened.Path) {
		if opened.Handle != nil {
			_ = opened.Handle.Close()
		}
		return v1.Connection{}, fmt.Errorf("%w: backend returned invalid connection", ErrConnectionOperation)
	}
	if err := requestCtx.Err(); err != nil {
		_ = opened.Handle.Close()
		return v1.Connection{}, err
	}
	if s.isClosed() {
		_ = opened.Handle.Close()
		return v1.Connection{}, ErrConnectionServiceClosed
	}

	startedAt := s.now().UTC()
	public := v1.Connection{
		ID:        connectionID,
		DeviceID:  req.DeviceID,
		State:     v1.ConnectionStateConnected,
		Path:      opened.Path,
		StartedAt: startedAt,
	}
	if err := s.network.SetConnectionPath(ConnectionPathSnapshot{
		ConnectionID:  connectionID,
		DestinationID: req.DeviceID,
		Path:          opened.Path,
		Route:         opened.Route,
	}); err != nil {
		_ = opened.Handle.Close()
		return v1.Connection{}, fmt.Errorf("%w: publish path state", ErrConnectionOperation)
	}

	token := &struct{}{}
	s.mu.Lock()
	if s.closed {
		s.opening--
		delete(s.reserved, connectionID)
		s.mu.Unlock()
		reserved = false
		s.network.RemoveConnectionPath(connectionID)
		_ = opened.Handle.Close()
		return v1.Connection{}, ErrConnectionServiceClosed
	}
	s.opening--
	delete(s.reserved, connectionID)
	s.active[connectionID] = activeConnection{public: public, handle: opened.Handle, token: token}
	reserved = false
	s.mu.Unlock()

	if observable, ok := opened.Handle.(ObservableConnectionHandle); ok {
		if done := observable.Done(); done != nil {
			go s.watchRemoteClose(connectionID, token, done)
		}
	}
	return public, nil
}

func (s *ConnectionService) Disconnect(ctx context.Context, req v1.DisconnectRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validConnectionID(req.ConnectionID) {
		return ErrInvalidConnectionRequest
	}

	s.mu.Lock()
	active, ok := s.active[req.ConnectionID]
	if !ok || active.closing {
		s.mu.Unlock()
		return ErrConnectionNotFound
	}
	active.closing = true
	s.active[req.ConnectionID] = active
	s.mu.Unlock()

	// Observable path state is removed before closing the underlying handle so a
	// concurrent UI read can never report a connection after disconnect begins.
	s.network.RemoveConnectionPath(req.ConnectionID)
	if err := active.handle.Close(); err != nil {
		doneClosed := observableHandleDoneClosed(active.handle)
		s.mu.Lock()
		if current, stillActive := s.active[req.ConnectionID]; stillActive && current.token == active.token {
			current.closing = false
			// If this failed local close itself caused the one-shot Done signal,
			// suppress that signal so the existing retryable-close contract wins.
			// A Done signal that arrives later, after this point, is still treated
			// as a natural remote close and removes the entry.
			current.suppressDone = doneClosed
			s.active[req.ConnectionID] = current
		}
		s.mu.Unlock()
		return fmt.Errorf("%w: close backend", ErrConnectionOperation)
	}

	s.mu.Lock()
	if current, stillActive := s.active[req.ConnectionID]; stillActive && current.token == active.token {
		delete(s.active, req.ConnectionID)
	}
	s.mu.Unlock()
	return nil
}

// Close tears down every active connection, cancels in-flight backend opens,
// and prevents future connects. It is intended for Local Core process shutdown.
// Raw handle errors are not included in the returned error so transport details
// cannot escape into generic logs.
func (s *ConnectionService) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	active := s.active
	s.active = make(map[string]activeConnection)
	s.mu.Unlock()

	s.shutdown()

	failed := 0
	for id, connection := range active {
		s.network.RemoveConnectionPath(id)
		if err := connection.handle.Close(); err != nil {
			failed++
		}
	}
	if failed != 0 {
		return fmt.Errorf("%w: %d connection(s) failed to close", ErrConnectionOperation, failed)
	}
	return nil
}

func (s *ConnectionService) watchRemoteClose(connectionID string, token *struct{}, done <-chan struct{}) {
	<-done

	s.mu.Lock()
	current, ok := s.active[connectionID]
	if ok && current.token == token {
		switch {
		case current.closing:
			ok = false
		case current.suppressDone:
			current.suppressDone = false
			s.active[connectionID] = current
			ok = false
		default:
			delete(s.active, connectionID)
		}
	} else {
		ok = false
	}
	s.mu.Unlock()

	if ok {
		s.network.RemoveConnectionPath(connectionID)
	}
}

func observableHandleDoneClosed(handle ConnectionHandle) bool {
	observable, ok := handle.(ObservableConnectionHandle)
	if !ok {
		return false
	}
	done := observable.Done()
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func (s *ConnectionService) reserveOpening() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrConnectionServiceClosed
	}
	if len(s.active)+s.opening >= s.max {
		return ErrConnectionLimit
	}
	s.opening++
	return nil
}

func (s *ConnectionService) releaseOpening() {
	s.mu.Lock()
	if s.opening > 0 {
		s.opening--
	}
	s.mu.Unlock()
}

func (s *ConnectionService) releaseOpeningAndID(connectionID string) {
	s.mu.Lock()
	if s.opening > 0 {
		s.opening--
	}
	delete(s.reserved, connectionID)
	s.mu.Unlock()
}

func (s *ConnectionService) reserveConnectionID() (string, error) {
	for attempt := 0; attempt < maxConnectionIDAttempts; attempt++ {
		connectionID, err := s.newConnectionID()
		if err != nil {
			return "", err
		}

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return "", ErrConnectionServiceClosed
		}
		_, active := s.active[connectionID]
		_, reserved := s.reserved[connectionID]
		if !active && !reserved {
			s.reserved[connectionID] = struct{}{}
			s.mu.Unlock()
			return connectionID, nil
		}
		s.mu.Unlock()
	}
	return "", errors.New("connection ID collision limit reached")
}

func (s *ConnectionService) isClosed() bool {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	return closed
}

func (s *ConnectionService) newConnectionID() (string, error) {
	var raw [18]byte
	if _, err := io.ReadFull(s.random, raw[:]); err != nil {
		return "", err
	}
	return "conn_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
