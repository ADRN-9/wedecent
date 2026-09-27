package session

import (
	"context"
	"os"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/protocol"
)

func TestTypedFileDownloadWaitsForPeerCloseAcknowledgement(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(root+"/download.bin", []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenFileTransferStore(root, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	runtime := &FileTransferRuntime{
		Store: store,
		Authorizer: StaticFileTransferAuthorizer{
			AllowDownload: true,
		},
	}
	registry := newTypedParentStreamRegistry()
	frames := make(chan protocol.Frame, 8)
	server := newTypedFileServer(runtime, "peer", registry, func(frame protocol.Frame) error {
		frames <- frame
		return nil
	})
	defer server.CloseAll()

	metadata, err := protocol.JSON(protocol.FileDownloadOpen{Path: "download.bin"})
	if err != nil {
		t.Fatal(err)
	}
	open, err := protocol.JSON(protocol.StreamOpen{
		Kind:          protocol.StreamKindFileDownload,
		Metadata:      metadata,
		InitialWindow: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	const streamID = uint32(2)
	if err := server.Handle(context.Background(), protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: streamID, Payload: open}); err != nil {
		t.Fatal(err)
	}

	waitFrameType := func(want protocol.Type) protocol.Frame {
		t.Helper()
		deadline := time.After(2 * time.Second)
		for {
			select {
			case frame := <-frames:
				if frame.Type == want {
					return frame
				}
			case <-deadline:
				t.Fatalf("timed out waiting for frame type %d", want)
			}
		}
	}
	_ = waitFrameType(protocol.TypeStreamAccepted)
	_ = waitFrameType(protocol.TypeStreamData)
	closeFrame := waitFrameType(protocol.TypeStreamClose)
	var closeMessage protocol.StreamClose
	if err := protocol.ParseTypedStreamJSON(closeFrame.Payload, &closeMessage); err != nil {
		t.Fatal(err)
	}
	if closeMessage.Reason != "download_complete" {
		t.Fatalf("unexpected close reason %q", closeMessage.Reason)
	}
	if !registry.isOpen(streamID, protocol.StreamKindFileDownload) {
		t.Fatal("completed download closed before peer acknowledgement")
	}

	// A consumer can release final receive credit before it processes the
	// download-complete control frame. The server must still accept that credit.
	update, _ := protocol.JSON(protocol.StreamWindowUpdate{Bytes: 1})
	if err := server.Handle(context.Background(), protocol.Frame{Type: protocol.TypeStreamWindowUpdate, StreamID: streamID, Payload: update}); err != nil {
		t.Fatalf("final credit update after download close announcement failed: %v", err)
	}

	ack, _ := protocol.JSON(protocol.StreamClose{Reason: "peer_close"})
	if err := server.Handle(context.Background(), protocol.Frame{Type: protocol.TypeStreamClose, StreamID: streamID, Payload: ack}); err != nil {
		t.Fatal(err)
	}
	if registry.isOpen(streamID, protocol.StreamKindFileDownload) {
		t.Fatal("download remained open after peer close acknowledgement")
	}
}
