package coreapi

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"wedecent.com/wedecent/internal/account"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/trust"
)

var ErrDeviceNotFound = errors.New("device not found")

type ReadService struct {
	deviceID   string
	deviceName string
	devices    *trust.Store

	accountMu sync.RWMutex
	signedIn  bool
	userID    string
	email     string
}

func NewReadService(id *identity.Identity, session *account.Session, devices *trust.Store) (*ReadService, error) {
	if id == nil {
		return nil, errors.New("identity is required")
	}
	if strings.TrimSpace(id.ID) == "" {
		return nil, errors.New("identity device ID is required")
	}
	if devices == nil {
		return nil, errors.New("device trust store is required")
	}

	s := &ReadService{
		deviceID:   id.ID,
		deviceName: id.Name,
		devices:    devices,
	}
	if err := s.SetAccountSession(session); err != nil {
		return nil, err
	}
	return s, nil
}

var (
	_ v1.StatusService = (*ReadService)(nil)
	_ v1.DeviceService = (*ReadService)(nil)
)

// SetAccountSession updates only the non-secret account identity exposed by
// GetStatus. Tokens are never retained by ReadService.
func (s *ReadService) SetAccountSession(session *account.Session) error {
	var signedIn bool
	var userID, email string
	if session != nil {
		userID = strings.TrimSpace(session.UserID)
		if userID == "" {
			return errors.New("account session user ID is required")
		}
		signedIn = true
		email = strings.TrimSpace(session.Email)
	}

	s.accountMu.Lock()
	s.signedIn = signedIn
	s.userID = userID
	s.email = email
	s.accountMu.Unlock()
	return nil
}

func (s *ReadService) GetStatus(ctx context.Context) (v1.Status, error) {
	if err := ctx.Err(); err != nil {
		return v1.Status{}, err
	}
	s.accountMu.RLock()
	signedIn, userID, email := s.signedIn, s.userID, s.email
	s.accountMu.RUnlock()
	return v1.Status{
		APIVersion: v1.Version,
		SignedIn:   signedIn,
		UserID:     userID,
		Email:      email,
		DeviceID:   s.deviceID,
		DeviceName: s.deviceName,
	}, nil
}

func (s *ReadService) ListDevices(ctx context.Context) ([]v1.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	peers := s.devices.List()
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].ID < peers[j].ID
	})

	devices := make([]v1.Device, 0, len(peers))
	for _, peer := range peers {
		devices = append(devices, deviceFromPeer(peer))
	}
	return devices, nil
}

func (s *ReadService) GetDevice(ctx context.Context, req v1.GetDeviceRequest) (v1.Device, error) {
	if err := ctx.Err(); err != nil {
		return v1.Device{}, err
	}
	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		return v1.Device{}, ErrDeviceNotFound
	}
	peer, ok := s.devices.Get(deviceID)
	if !ok {
		return v1.Device{}, ErrDeviceNotFound
	}
	return deviceFromPeer(peer), nil
}

func deviceFromPeer(peer trust.Peer) v1.Device {
	return v1.Device{
		ID:          peer.ID,
		Name:        peer.Name,
		Fingerprint: peer.Fingerprint,
		Endpoint:    peer.Endpoint,
	}
}
