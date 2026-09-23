package mesh

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

// ForwarderSnapshot copies the immutable router policy together with current
// process-local forwarding counters. Forwarder policy remains construction-time
// state in the current runtime and must not be mutated concurrently.
type ForwarderSnapshot struct {
	Policy RouterPolicy
	Stats  ForwarderStats
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
