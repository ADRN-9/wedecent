package session

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/protocol"
)

func TestTypedFileServerPeerCloseStopsDownloadWithoutLateFrames(t *testing.T) {
	runtime, root := newTestFileRuntime(t, false, true)
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	sink := newFileFrameSink()
	server := newTypedFileServer(runtime, "client-1", newTypedParentStreamRegistry(), sink.write)
	open := protocol.FileDownloadOpen{Path: "file.txt"}
	if err := server.Handle(context.Background(), fileStreamOpenFrame(t, 30, protocol.StreamKindFileDownload, open, 1)); err != nil {
		t.Fatal(err)
	}
	if frame := sink.next(t); frame.Type != protocol.TypeStreamAccepted {
		t.Fatalf("open response = %#v", frame)
	}
	if frame := sink.next(t); frame.Type != protocol.TypeStreamData || string(frame.Payload) != "h" {
		t.Fatalf("first data frame = %#v", frame)
	}
	if err := server.Handle(context.Background(), streamCloseFrame(t, 30)); err != nil {
		t.Fatal(err)
	}
	if frame := sink.next(t); frame.Type != protocol.TypeStreamClose || frame.StreamID != 30 {
		t.Fatalf("close acknowledgment = %#v", frame)
	}
	select {
	case frame := <-sink.frames:
		t.Fatalf("late frame after peer close: %#v", frame)
	case <-time.After(100 * time.Millisecond):
	}
}
