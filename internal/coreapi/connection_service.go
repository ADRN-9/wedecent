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
	public  v1.Connection
	handle  ConnectionHandle
	closing bool
}

type ConnectionService struct {
	backend ConnectionBackend
	network *NetworkReadService
	max     int
	random  io.Reader
	now     func() time.Time

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
	return &ConnectionService{
		backend:  cfg.Backend,
		network:  cfg.Network,
		max:      maxActive,
		random:   random,
		now:      now,
		active:   make(map[string]activeConnection),
		reserved: make(map[string]struct{}),
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

	opened, err := s.backend.Open(ctx, req.DeviceID)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return v1.Connection{}, ctxErr
		}
		if s.isClosed() {
			return v1.Connection{}, ErrConnectionServiceClosed
		}
		return v1.Connection{}, fmt.Errorf("%w: open backend", ErrConnectionOperation)
	}
	if opened.Handle == nil || !validConnectionPath(opened.Path) {
		if opened.Handle != nil {
			_ = opened.Handle.Close()
		}
		return v1.Connection{}, fmt.Errorf("%w: backend returned invalid connection", ErrConnectionOperation)
	}
	if err := ctx.Err(); err != nil {
		_ = opened.Handle.Close()
		return v1.Connection{}, err
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
	s.active[connectionID] = activeConnection{public: public, handle: opened.Handle}
	reserved = false
	s.mu.Unlock()
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
		s.mu.Lock()
		if current, stillActive := s.active[req.ConnectionID]; stillActive {
			current.closing = false
			s.active[req.ConnectionID] = current
		}
		s.mu.Unlock()
		return fmt.Errorf("%w: close backend", ErrConnectionOperation)
	}

	s.mu.Lock()
	delete(s.active, req.ConnectionID)
	s.mu.Unlock()
	return nil
}

// Close tears down every active connection and prevents future connects. It is
// intended for Local Core process shutdown. Raw handle errors are not included
// in the returned error so transport details cannot escape into generic logs.
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
