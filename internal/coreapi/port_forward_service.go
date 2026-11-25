package coreapi

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/portforward"
)

var (
	ErrInvalidPortForwardRequest = errors.New("invalid port forwarding request")
	ErrPortForwardUnavailable    = errors.New("port forwarding is unavailable")
	ErrPortForwardLimit          = errors.New("port forwarding limit reached")
	ErrPortForwardNotFound       = errors.New("port forwarding not found")
	ErrPortForwardOperation      = errors.New("port forwarding operation failed")
)

var forwardingIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// PortForwardService exposes only signed-capability lifecycle operations. It
// deliberately has no caller-supplied dial address or listener configuration.
type PortForwardService struct {
	manager *portforward.Manager
}

var _ v1.PortForwardService = (*PortForwardService)(nil)

func NewPortForwardService(manager *portforward.Manager) (*PortForwardService, error) {
	if manager == nil {
		return nil, ErrPortForwardUnavailable
	}
	return &PortForwardService{manager: manager}, nil
}

func (s *PortForwardService) StartPortForward(ctx context.Context, req v1.PortForwardStartRequest) (v1.PortForwardStatus, error) {
	if ctx == nil || ctx.Err() != nil {
		if ctx == nil {
			return v1.PortForwardStatus{}, ErrInvalidPortForwardRequest
		}
		return v1.PortForwardStatus{}, ctx.Err()
	}
	if s == nil || s.manager == nil {
		return v1.PortForwardStatus{}, ErrPortForwardUnavailable
	}
	info, err := s.manager.Start(ctx, req.Authorization)
	if err != nil {
		return v1.PortForwardStatus{}, classifyPortForwardError(err)
	}
	return portForwardStatus(info), nil
}

func (s *PortForwardService) StopPortForward(ctx context.Context, req v1.PortForwardStopRequest) error {
	if ctx == nil || ctx.Err() != nil {
		if ctx == nil {
			return ErrInvalidPortForwardRequest
		}
		return ctx.Err()
	}
	if s == nil || s.manager == nil {
		return ErrPortForwardUnavailable
	}
	if !forwardingIDPattern.MatchString(req.ForwardingID) {
		return ErrInvalidPortForwardRequest
	}
	if err := s.manager.Stop(ctx, req.ForwardingID); err != nil {
		return classifyPortForwardError(err)
	}
	return nil
}

func (s *PortForwardService) GetPortForwardStatus(ctx context.Context, req v1.PortForwardStatusRequest) (v1.PortForwardStatus, error) {
	if ctx == nil || ctx.Err() != nil {
		if ctx == nil {
			return v1.PortForwardStatus{}, ErrInvalidPortForwardRequest
		}
		return v1.PortForwardStatus{}, ctx.Err()
	}
	if s == nil || s.manager == nil {
		return v1.PortForwardStatus{}, ErrPortForwardUnavailable
	}
	if !forwardingIDPattern.MatchString(req.ForwardingID) {
		return v1.PortForwardStatus{}, ErrInvalidPortForwardRequest
	}
	for _, forward := range s.manager.List() {
		if forward.ID == req.ForwardingID {
			return portForwardStatus(forward), nil
		}
	}
	return v1.PortForwardStatus{}, ErrPortForwardNotFound
}

func (s *PortForwardService) ListPortForwards(ctx context.Context) ([]v1.PortForwardStatus, error) {
	if ctx == nil || ctx.Err() != nil {
		if ctx == nil {
			return nil, ErrInvalidPortForwardRequest
		}
		return nil, ctx.Err()
	}
	if s == nil || s.manager == nil {
		return nil, ErrPortForwardUnavailable
	}
	forwards := s.manager.List()
	result := make([]v1.PortForwardStatus, 0, len(forwards))
	for _, forward := range forwards {
		result = append(result, portForwardStatus(forward))
	}
	return result, nil
}

func portForwardStatus(info portforward.ForwardInfo) v1.PortForwardStatus {
	return v1.PortForwardStatus{
		ID:                 info.ID,
		Direction:          info.Direction,
		ListenerAddress:    info.ListenerAddress,
		DestinationAddress: info.DestinationAddress,
		DestinationPort:    info.DestinationPort,
		ExpiresAt:          info.ExpiresAt,
		ActiveConnections:  info.ActiveConnections,
	}
}

func classifyPortForwardError(err error) error {
	switch {
	case errors.Is(err, portforward.ErrManagerClosed):
		return fmt.Errorf("%w: %v", ErrPortForwardUnavailable, err)
	case errors.Is(err, portforward.ErrForwardLimit):
		return fmt.Errorf("%w: %v", ErrPortForwardLimit, err)
	case errors.Is(err, portforward.ErrAuthorizationInvalid),
		errors.Is(err, portforward.ErrAuthorizationExpired),
		errors.Is(err, portforward.ErrAuthorizationNotYetValid):
		return fmt.Errorf("%w: %v", ErrInvalidPortForwardRequest, err)
	default:
		return fmt.Errorf("%w: %v", ErrPortForwardOperation, err)
	}
}
