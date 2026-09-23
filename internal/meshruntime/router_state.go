package meshruntime

import (
	"errors"
	"fmt"

	"wedecent.com/wedecent/internal/mesh"
)

var ErrInvalidRouterPolicy = errors.New("meshruntime: invalid router policy")

// RouterState is a defensive snapshot of the authoritative in-process router.
// It intentionally contains no trust-store entries, authorization material, or
// route payloads.
type RouterState struct {
	Policy mesh.RouterPolicy
	Stats  mesh.ForwarderStats
}

// RouterState returns the current policy and process-local forwarding counters
// from the same Forwarder instance that enforces routed sessions.
func (r *Runtime) RouterState() (RouterState, error) {
	if r == nil || r.Router == nil {
		return RouterState{}, ErrConfig
	}

	snapshot := r.Router.Snapshot()
	return RouterState{
		Policy: snapshot.Policy,
		Stats:  snapshot.Stats,
	}, nil
}

// SetRouterPolicy atomically changes policy for future routed sessions and
// returns the resulting authoritative state. Existing active tunnels are not
// terminated or re-authorized.
//
// Stage 3 only implements trusted-device admission, MaxSessions, and LANOnly.
// Resource-aware bandwidth, battery, metered-network, organization, and public
// routing fields remain unsupported and fail closed rather than being accepted
// as if they were enforced.
func (r *Runtime) SetRouterPolicy(policy mesh.RouterPolicy) (RouterState, error) {
	if r == nil || r.Router == nil {
		return RouterState{}, ErrConfig
	}
	if err := validateMutableRouterPolicy(policy); err != nil {
		return RouterState{}, err
	}
	if err := r.Router.SetPolicy(policy); err != nil {
		return RouterState{}, fmt.Errorf("%w: %v", ErrInvalidRouterPolicy, err)
	}
	return r.RouterState()
}

func validateMutableRouterPolicy(policy mesh.RouterPolicy) error {
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRouterPolicy, err)
	}
	if !policy.TrustedDevicesOnly ||
		policy.OrganizationOnly ||
		policy.PublicRouting ||
		policy.MaxBandwidthBytesPerSec != 0 ||
		policy.AllowOnBattery ||
		policy.AllowMetered {
		return ErrUnsupportedPolicy
	}
	return nil
}
