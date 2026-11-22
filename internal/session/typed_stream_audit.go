package session

import (
	"sync"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/protocol"
)

type typedTerminalAuditTracker struct {
	mu        sync.Mutex
	peerID    string
	sessionID string
	transport string
	open      map[uint32]struct{}
	record    func(audit.Event)
}

func newTypedTerminalAuditTracker(peerID, transport string, record func(audit.Event), sessionIDs ...string) *typedTerminalAuditTracker {
	sessionID := ""
	if len(sessionIDs) != 0 {
		sessionID = sessionIDs[0]
	}
	return &typedTerminalAuditTracker{
		peerID:    peerID,
		sessionID: sessionID,
		transport: transport,
		open:      make(map[uint32]struct{}),
		record:    record,
	}
}

func (t *typedTerminalAuditTracker) observeOutgoing(frame protocol.Frame) {
	if t == nil {
		return
	}
	if frame.Type == protocol.TypeStreamAccepted {
		t.opened(frame.StreamID)
	}
}

func (t *typedTerminalAuditTracker) opened(streamID uint32) {
	if streamID < protocol.MinTypedStreamID {
		return
	}
	t.mu.Lock()
	if _, exists := t.open[streamID]; exists {
		t.mu.Unlock()
		return
	}
	t.open[streamID] = struct{}{}
	t.mu.Unlock()
	t.emit(audit.Event{
		Type:      "terminal.stream_opened",
		Outcome:   "success",
		PeerID:    t.peerID,
		SessionID: t.sessionID,
		Transport: t.transport,
		StreamID:  streamID,
	})
}

func (t *typedTerminalAuditTracker) closed(streamID uint32, reason string, cleanupErr error) {
	t.mu.Lock()
	if _, exists := t.open[streamID]; !exists {
		t.mu.Unlock()
		return
	}
	delete(t.open, streamID)
	t.mu.Unlock()
	outcome := "success"
	if cleanupErr != nil {
		outcome = "failed"
	}
	t.emit(audit.Event{
		Type:      "terminal.stream_closed",
		Outcome:   outcome,
		PeerID:    t.peerID,
		SessionID: t.sessionID,
		Transport: t.transport,
		StreamID:  streamID,
		Reason:    reason,
	})
}

func (t *typedTerminalAuditTracker) closeAll(reason string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	ids := make([]uint32, 0, len(t.open))
	for id := range t.open {
		ids = append(ids, id)
	}
	t.mu.Unlock()
	for _, id := range ids {
		t.closed(id, reason, nil)
	}
}

func (t *typedTerminalAuditTracker) emit(event audit.Event) {
	if t.record != nil {
		t.record(event)
	}
}
