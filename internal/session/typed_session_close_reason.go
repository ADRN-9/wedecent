package session

import "sync"

type typedSessionCloseReason struct {
	mu    sync.RWMutex
	value string
}

func newTypedSessionCloseReason(initial string) *typedSessionCloseReason {
	return &typedSessionCloseReason{value: initial}
}

func (r *typedSessionCloseReason) set(value string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.value = value
	r.mu.Unlock()
}

func (r *typedSessionCloseReason) valueOr(fallback string) string {
	if r == nil {
		return fallback
	}
	r.mu.RLock()
	value := r.value
	r.mu.RUnlock()
	if value != "" {
		return value
	}
	return fallback
}

// Revocation's immutable reason wins over a concurrently completed terminal read.
func resolveTypedSessionCloseReason(active *activeTerminalSession, fallback *typedSessionCloseReason) string {
	fallbackReason := fallback.valueOr("connection_ended")
	if active != nil {
		if reason := active.reasonOr(""); reason != "" {
			return reason
		}
	}
	return fallbackReason
}
