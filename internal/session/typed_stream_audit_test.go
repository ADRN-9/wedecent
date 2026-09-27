package session

import (
	"testing"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/protocol"
)

func TestTypedTerminalAuditTrackerRecordsLifecycleOnce(t *testing.T) {
	var events []audit.Event
	tracker := newTypedTerminalAuditTracker("wd_peer", "direct", func(event audit.Event) {
		events = append(events, event)
	})

	acceptedPayload, err := protocol.JSON(protocol.StreamAccepted{InitialWindow: typedTerminalReceiveWindow})
	if err != nil {
		t.Fatal(err)
	}
	accepted := protocol.Frame{Type: protocol.TypeStreamAccepted, StreamID: 2, Payload: acceptedPayload}
	tracker.observeOutgoing(accepted)
	tracker.observeOutgoing(accepted)

	closePayload, err := protocol.JSON(protocol.StreamClose{Reason: "process_exit"})
	if err != nil {
		t.Fatal(err)
	}
	tracker.observeOutgoing(protocol.Frame{Type: protocol.TypeStreamClose, StreamID: 2, Payload: closePayload})
	tracker.observeIncoming(protocol.Frame{Type: protocol.TypeStreamClose, StreamID: 2})

	if len(events) != 2 {
		t.Fatalf("events = %#v", events)
	}
	if events[0].Type != "terminal.stream_opened" || events[0].Outcome != "success" || events[0].PeerID != "wd_peer" || events[0].Transport != "direct" || events[0].StreamID != 2 {
		t.Fatalf("open event = %#v", events[0])
	}
	if events[1].Type != "terminal.stream_closed" || events[1].Outcome != "success" || events[1].StreamID != 2 || events[1].Reason != "process_exit" {
		t.Fatalf("close event = %#v", events[1])
	}
}

func TestTypedTerminalAuditTrackerParentCleanupAndPreacceptError(t *testing.T) {
	var events []audit.Event
	tracker := newTypedTerminalAuditTracker("wd_peer", "relay", func(event audit.Event) {
		events = append(events, event)
	})

	errorPayload, err := protocol.JSON(protocol.StreamError{Code: "pty_start_failed", Message: "terminal stream could not start"})
	if err != nil {
		t.Fatal(err)
	}
	tracker.observeOutgoing(protocol.Frame{Type: protocol.TypeStreamError, StreamID: 2, Payload: errorPayload})
	if len(events) != 0 {
		t.Fatalf("preaccept error created lifecycle audit: %#v", events)
	}

	for _, id := range []uint32{3, 4} {
		acceptedPayload, err := protocol.JSON(protocol.StreamAccepted{InitialWindow: typedTerminalReceiveWindow})
		if err != nil {
			t.Fatal(err)
		}
		tracker.observeOutgoing(protocol.Frame{Type: protocol.TypeStreamAccepted, StreamID: id, Payload: acceptedPayload})
	}
	tracker.closeAll("peer_disconnect")
	tracker.closeAll("duplicate_cleanup")

	if len(events) != 4 {
		t.Fatalf("events = %#v", events)
	}
	closed := map[uint32]string{}
	for _, event := range events {
		if event.Type == "terminal.stream_closed" {
			closed[event.StreamID] = event.Reason
		}
	}
	if len(closed) != 2 || closed[3] != "peer_disconnect" || closed[4] != "peer_disconnect" {
		t.Fatalf("closed events = %#v", closed)
	}
}
