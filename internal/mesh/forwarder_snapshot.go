package mesh

import "errors"

var ErrForwarderUnavailable = errors.New("mesh: forwarding runtime is unavailable")

// ForwarderStats is a process-local snapshot of one forwarding runtime.
//
// SessionsForwarded counts sessions that reached opaque byte forwarding after
// authorization and destination-link verification. BytesForwarded is the
// saturated sum of bytes observed in both directions when those forwarding
// operations return. Neither counter is persisted across process restarts.
type ForwarderStats struct {
	ActiveSessions    int
	BytesForwarded    uint64
	SessionsForwarded uint64
}

// ForwarderSnapshot copies the current router policy together with current
// process-local forwarding counters.
type ForwarderSnapshot struct {
	Policy RouterPolicy
	Stats  ForwarderStats
}

// SetPolicy validates and atomically replaces the policy used by future routed
// operations. Existing active tunnels keep the policy snapshot under which they
// were admitted and are not terminated by this method.
func (f *Forwarder) SetPolicy(policy RouterPolicy) error {
	if f == nil {
		return ErrForwarderUnavailable
	}
	if err := policy.Validate(); err != nil {
		return err
	}

	f.mu.Lock()
	f.Policy = policy
	f.mu.Unlock()
	return nil
}

func (f *Forwarder) policySnapshot() RouterPolicy {
	if f == nil {
		return RouterPolicy{}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Policy
}

// Snapshot returns a defensive value copy of the forwarding runtime state.
func (f *Forwarder) Snapshot() ForwarderSnapshot {
	if f == nil {
		return ForwarderSnapshot{}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	return ForwarderSnapshot{
		Policy: f.Policy,
		Stats: ForwarderStats{
			ActiveSessions:    f.active,
			BytesForwarded:    f.bytesForwarded,
			SessionsForwarded: f.sessionsForwarded,
		},
	}
}
