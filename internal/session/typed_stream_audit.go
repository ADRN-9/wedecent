package session

import (
	"sync"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/protocol"
)

type typedTerminalAuditTracker struct {
	mu        sync.Mutex
	peerID    string
	transport string
	open      map[uint32]struct{}
	record    func(audit.Event)
}

func newTypedTerminalAuditTracker(peerID, transport string, record func(audit.Event)) *typedTerminalAuditTracker {
	return &typedTerminalAuditTracker{
		peerID:    peerID,
		transport: transport,
		open:      make(map[uint32]struct{}),
		record:    record,
	}
}

func (t *typedTerminalAuditTracker) observeOutgoing(frame protocol.Frame) {
	if t == nil {
		return
	}
	switch frame.Type {
	case protocol.TypeStreamAccepted:
		t.opened(frame.StreamID)
	case protocol.TypeStreamClose:
		reason := "stream_close"
		var message protocol.StreamClose
		if protocol.ParseTypedStreamJSON(frame.Payload, &message) == nil && protocol.ValidateStreamClose(frame.StreamID, message) == nil && message.Reason != "" {
			reason = message.Reason
		}
		t.closed(frame.StreamID, reason)
	case protocol.TypeStreamError:
		reason := "stream_error"
		var message protocol.StreamError
		if protocol.ParseTypedStreamJSON(frame.Payload, &message) == nil && protocol.ValidateStreamError(frame.StreamID, message) == nil && message.Code != "" {
			reason = message.Code
		}
		t.closed(frame.StreamID, reason)
	}
}

func (t *typedTerminalAuditTracker) observeIncoming(frame protocol.Frame) {
	if t == nil {
		return
	}
	switch frame.Type {
	case protocol.TypeStreamClose:
		t.closed(frame.StreamID, "peer_close")
	case protocol.TypeStreamError:
		t.closed(frame.StreamID, "peer_error")
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
		Transport: t.transport,
		StreamID:  streamID,
	})
}

func (t *typedTerminalAuditTracker) closed(streamID uint32, reason string) {
	t.mu.Lock()
	if _, exists := t.open[streamID]; !exists {
		t.mu.Unlock()
		return
	}
	delete(t.open, streamID)
	t.mu.Unlock()
	t.emit(audit.Event{
		Type:      "terminal.stream_closed",
		Outcome:   "success",
		PeerID:    t.peerID,
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
	t.open = make(map[uint32]struct{})
	t.mu.Unlock()
	for _, id := range ids {
		t.emit(audit.Event{
			Type:      "terminal.stream_closed",
			Outcome:   "success",
			PeerID:    t.peerID,
			Transport: t.transport,
			StreamID:  id,
			Reason:    reason,
		})
	}
}

func (t *typedTerminalAuditTracker) emit(event audit.Event) {
	if t.record != nil {
		t.record(event)
	}
}
