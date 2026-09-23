package meshruntime

import "wedecent.com/wedecent/internal/mesh"

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
