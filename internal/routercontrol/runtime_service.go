// Package routercontrol exposes the narrow administrative surface needed to
// control the authoritative wd-agent router runtime without exposing trust,
// capability, replay, or session payload state.
package routercontrol

import (
	"context"
	"errors"
	"fmt"

	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/meshruntime"
)

// RuntimeService maps the stable Local Core router contract directly onto the
// meshruntime.Runtime instance that actually enforces forwarding.
type RuntimeService struct {
	runtime *meshruntime.Runtime
}

var _ v1.RouterService = (*RuntimeService)(nil)

func NewRuntimeService(runtime *meshruntime.Runtime) (*RuntimeService, error) {
	if runtime == nil || runtime.Router == nil {
		return nil, coreapi.ErrRouterUnavailable
	}
	return &RuntimeService{runtime: runtime}, nil
}

func (s *RuntimeService) GetRouterPolicy(ctx context.Context) (v1.RouterPolicy, error) {
	if err := ctx.Err(); err != nil {
		return v1.RouterPolicy{}, err
	}
	state, err := s.routerState()
	if err != nil {
		return v1.RouterPolicy{}, err
	}
	return toV1Policy(state.Policy), nil
}

func (s *RuntimeService) SetRouterPolicy(
	ctx context.Context,
	req v1.SetRouterPolicyRequest,
) (v1.RouterPolicy, error) {
	if err := ctx.Err(); err != nil {
		return v1.RouterPolicy{}, err
	}
	if s == nil || s.runtime == nil {
		return v1.RouterPolicy{}, coreapi.ErrRouterUnavailable
	}

	state, err := s.runtime.SetRouterPolicy(fromV1Policy(req.Policy))
	if err != nil {
		switch {
		case errors.Is(err, meshruntime.ErrInvalidRouterPolicy),
			errors.Is(err, meshruntime.ErrUnsupportedPolicy):
			return v1.RouterPolicy{}, fmt.Errorf("%w: %v", coreapi.ErrInvalidRouterPolicy, err)
		case errors.Is(err, meshruntime.ErrConfig):
			return v1.RouterPolicy{}, coreapi.ErrRouterUnavailable
		default:
			return v1.RouterPolicy{}, fmt.Errorf("%w: %v", coreapi.ErrRouterOperation, err)
		}
	}
	return toV1Policy(state.Policy), nil
}

func (s *RuntimeService) GetRouterStats(ctx context.Context) (v1.RouterStats, error) {
	if err := ctx.Err(); err != nil {
		return v1.RouterStats{}, err
	}
	state, err := s.routerState()
	if err != nil {
		return v1.RouterStats{}, err
	}
	return v1.RouterStats{
		ActiveSessions:    state.Stats.ActiveSessions,
		BytesForwarded:    state.Stats.BytesForwarded,
		SessionsForwarded: state.Stats.SessionsForwarded,
	}, nil
}

func (s *RuntimeService) routerState() (meshruntime.RouterState, error) {
	if s == nil || s.runtime == nil {
		return meshruntime.RouterState{}, coreapi.ErrRouterUnavailable
	}
	state, err := s.runtime.RouterState()
	if err != nil {
		if errors.Is(err, meshruntime.ErrConfig) {
			return meshruntime.RouterState{}, coreapi.ErrRouterUnavailable
		}
		return meshruntime.RouterState{}, fmt.Errorf("%w: %v", coreapi.ErrRouterOperation, err)
	}
	return state, nil
}

func toV1Policy(policy mesh.RouterPolicy) v1.RouterPolicy {
	return v1.RouterPolicy{
		Enabled:                 policy.Enabled,
		TrustedDevicesOnly:      policy.TrustedDevicesOnly,
		OrganizationOnly:        policy.OrganizationOnly,
		PublicRouting:           policy.PublicRouting,
		MaxSessions:             policy.MaxSessions,
		MaxBandwidthBytesPerSec: policy.MaxBandwidthBytesPerSec,
		AllowOnBattery:          policy.AllowOnBattery,
		AllowMetered:            policy.AllowMetered,
		LANOnly:                 policy.LANOnly,
	}
}

func fromV1Policy(policy v1.RouterPolicy) mesh.RouterPolicy {
	return mesh.RouterPolicy{
		Enabled:                 policy.Enabled,
		TrustedDevicesOnly:      policy.TrustedDevicesOnly,
		OrganizationOnly:        policy.OrganizationOnly,
		PublicRouting:           policy.PublicRouting,
		MaxSessions:             policy.MaxSessions,
		MaxBandwidthBytesPerSec: policy.MaxBandwidthBytesPerSec,
		AllowOnBattery:          policy.AllowOnBattery,
		AllowMetered:            policy.AllowMetered,
		LANOnly:                 policy.LANOnly,
	}
}
