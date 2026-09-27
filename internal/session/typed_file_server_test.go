package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/protocol"
)

type fileFrameSink struct {
	frames chan protocol.Frame
}

func newFileFrameSink() *fileFrameSink {
	return &fileFrameSink{frames: make(chan protocol.Frame, 64)}
}

func (s *fileFrameSink) write(frame protocol.Frame) error {
	s.frames <- frame
	return nil
}

func (s *fileFrameSink) next(t *testing.T) protocol.Frame {
	t.Helper()
	select {
	case frame := <-s.frames:
		return frame
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for file stream frame")
		return protocol.Frame{}
	}
}

func newTestFileRuntime(t *testing.T, allowUpload, allowDownload bool) (*FileTransferRuntime, string) {
	t.Helper()
	root := t.TempDir()
	store, err := OpenFileTransferStore(root, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return &FileTransferRuntime{
		Store: store,
		Authorizer: StaticFileTransferAuthorizer{
			AllowUpload:   allowUpload,
			AllowDownload: allowDownload,
		},
	}, root
}

func fileStreamOpenFrame(t *testing.T, id uint32, kind protocol.StreamKind, metadata any, initialWindow uint32) protocol.Frame {
	t.Helper()
	meta, err := protocol.JSON(metadata)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.JSON(protocol.StreamOpen{Kind: kind, Metadata: meta, InitialWindow: initialWindow})
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: id, Payload: payload}
}

func streamCloseFrame(t *testing.T, id uint32) protocol.Frame {
	t.Helper()
	payload, err := protocol.JSON(protocol.StreamClose{Reason: "complete"})
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Frame{Type: protocol.TypeStreamClose, StreamID: id, Payload: payload}
}

func TestTypedFileServerUploadCommit(t *testing.T) {
	runtime, root := newTestFileRuntime(t, true, false)
	if err := os.Mkdir(filepath.Join(root, "incoming"), 0o700); err != nil {
		t.Fatal(err)
	}
	sink := newFileFrameSink()
	registry := newTypedParentStreamRegistry()
	server := newTypedFileServer(runtime, "client-1", registry, sink.write)

	content := []byte("hello")
	digest := sha256.Sum256(content)
	size := uint64(len(content))
	open := protocol.FileUploadOpen{
		Path: "incoming/file.txt", ExpectedSize: &size,
		SHA256: hex.EncodeToString(digest[:]), Existing: protocol.FileExistingFail,
	}
	if err := server.Handle(context.Background(), fileStreamOpenFrame(t, 2, protocol.StreamKindFileUpload, open, 1)); err != nil {
		t.Fatal(err)
	}
	if frame := sink.next(t); frame.Type != protocol.TypeStreamAccepted || frame.StreamID != 2 {
		t.Fatalf("open response = %#v", frame)
	}
	if err := server.Handle(context.Background(), protocol.Frame{Type: protocol.TypeStreamData, StreamID: 2, Payload: content}); err != nil {
		t.Fatal(err)
	}
	if frame := sink.next(t); frame.Type != protocol.TypeStreamWindowUpdate || frame.StreamID != 2 {
		t.Fatalf("data response = %#v", frame)
	}
	if err := server.Handle(context.Background(), streamCloseFrame(t, 2)); err != nil {
		t.Fatal(err)
	}
	if frame := sink.next(t); frame.Type != protocol.TypeStreamClose || frame.StreamID != 2 {
		t.Fatalf("close response = %#v", frame)
	}
	got, err := os.ReadFile(filepath.Join(root, "incoming", "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatalf("uploaded content = %q", got)
	}
}

func TestTypedFileServerAuthorizationDenialIsChildScopedAndConsumesID(t *testing.T) {
	runtime, root := newTestFileRuntime(t, false, false)
	if err := os.Mkdir(filepath.Join(root, "incoming"), 0o700); err != nil {
		t.Fatal(err)
	}
	sink := newFileFrameSink()
	registry := newTypedParentStreamRegistry()
	server := newTypedFileServer(runtime, "client-1", registry, sink.write)
	open := protocol.FileUploadOpen{Path: "incoming/denied.txt", Existing: protocol.FileExistingFail}
	if err := server.Handle(context.Background(), fileStreamOpenFrame(t, 3, protocol.StreamKindFileUpload, open, 1)); err != nil {
		t.Fatalf("authorization denial became parent error: %v", err)
	}
	frame := sink.next(t)
	if frame.Type != protocol.TypeStreamError || frame.StreamID != 3 {
		t.Fatalf("denial response = %#v", frame)
	}
	var streamErr protocol.StreamError
	if err := protocol.ParseTypedStreamJSON(frame.Payload, &streamErr); err != nil {
		t.Fatal(err)
	}
	if streamErr.Code != "authorization_denied" {
		t.Fatalf("denial code = %q", streamErr.Code)
	}
	if _, err := os.Stat(filepath.Join(root, "incoming", "denied.txt")); !os.IsNotExist(err) {
		t.Fatalf("denied upload created destination: %v", err)
	}
	if err := registry.reserve(3, protocol.StreamKindTerminal); !errors.Is(err, errTypedStreamDuplicate) {
		t.Fatalf("denied stream ID was reusable: %v", err)
	}
}

func TestTypedFileServerDownloadHonorsFlowControl(t *testing.T) {
	runtime, root := newTestFileRuntime(t, false, true)
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	sink := newFileFrameSink()
	server := newTypedFileServer(runtime, "client-1", newTypedParentStreamRegistry(), sink.write)
	open := protocol.FileDownloadOpen{Path: "file.txt"}
	if err := server.Handle(context.Background(), fileStreamOpenFrame(t, 4, protocol.StreamKindFileDownload, open, 2)); err != nil {
		t.Fatal(err)
	}
	if frame := sink.next(t); frame.Type != protocol.TypeStreamAccepted {
		t.Fatalf("open response = %#v", frame)
	}
	first := sink.next(t)
	if first.Type != protocol.TypeStreamData || string(first.Payload) != "he" {
		t.Fatalf("first download chunk = %#v", first)
	}
	select {
	case frame := <-sink.frames:
		t.Fatalf("download exceeded opener credit: %#v", frame)
	case <-time.After(50 * time.Millisecond):
	}
	payload, _ := protocol.JSON(protocol.StreamWindowUpdate{Bytes: 3})
	if err := server.Handle(context.Background(), protocol.Frame{Type: protocol.TypeStreamWindowUpdate, StreamID: 4, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	second := sink.next(t)
	if second.Type != protocol.TypeStreamData || string(second.Payload) != "llo" {
		t.Fatalf("second download chunk = %#v", second)
	}
	if frame := sink.next(t); frame.Type != protocol.TypeStreamClose || frame.StreamID != 4 {
		t.Fatalf("download completion = %#v", frame)
	}
}

func TestTypedFileServerParentCleanupCancelsUpload(t *testing.T) {
	runtime, root := newTestFileRuntime(t, true, false)
	if err := os.Mkdir(filepath.Join(root, "incoming"), 0o700); err != nil {
		t.Fatal(err)
	}
	sink := newFileFrameSink()
	server := newTypedFileServer(runtime, "client-1", newTypedParentStreamRegistry(), sink.write)
	open := protocol.FileUploadOpen{Path: "incoming/partial.txt", Existing: protocol.FileExistingFail}
	if err := server.Handle(context.Background(), fileStreamOpenFrame(t, 5, protocol.StreamKindFileUpload, open, 1)); err != nil {
		t.Fatal(err)
	}
	_ = sink.next(t)
	if err := server.Handle(context.Background(), protocol.Frame{Type: protocol.TypeStreamData, StreamID: 5, Payload: []byte("partial")}); err != nil {
		t.Fatal(err)
	}
	_ = sink.next(t)
	server.CloseAll()
	if _, err := os.Stat(filepath.Join(root, "incoming", "partial.txt")); !os.IsNotExist(err) {
		t.Fatalf("partial upload was published: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "incoming"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".wedecent-upload-") {
			t.Fatalf("staging file survived parent cleanup: %q", entry.Name())
		}
	}
}

func TestTypedFileServerSharedRegistryRejectsCrossKindCollision(t *testing.T) {
	runtime, root := newTestFileRuntime(t, true, false)
	if err := os.Mkdir(filepath.Join(root, "incoming"), 0o700); err != nil {
		t.Fatal(err)
	}
	registry := newTypedParentStreamRegistry()
	if err := registry.reserve(6, protocol.StreamKindTerminal); err != nil {
		t.Fatal(err)
	}
	if err := registry.accept(6, protocol.StreamKindTerminal); err != nil {
		t.Fatal(err)
	}
	server := newTypedFileServer(runtime, "client-1", registry, newFileFrameSink().write)
	open := protocol.FileUploadOpen{Path: "incoming/file.txt", Existing: protocol.FileExistingFail}
	err := server.Handle(context.Background(), fileStreamOpenFrame(t, 6, protocol.StreamKindFileUpload, open, 1))
	if err == nil || !errors.Is(err, errTypedStreamProtocol) {
		t.Fatalf("cross-kind StreamID collision accepted: %v", err)
	}
}

func TestTypedFileServerConcurrentLimitIsChildScoped(t *testing.T) {
	runtime, root := newTestFileRuntime(t, true, false)
	if err := os.Mkdir(filepath.Join(root, "incoming"), 0o700); err != nil {
		t.Fatal(err)
	}
	sink := newFileFrameSink()
	server := newTypedFileServer(runtime, "client-1", newTypedParentStreamRegistry(), sink.write)
	for i := 0; i < maxFileStreamsPerConnection; i++ {
		id := uint32(10 + i)
		open := protocol.FileUploadOpen{Path: "incoming/file-" + string(rune('a'+i)), Existing: protocol.FileExistingFail}
		if err := server.Handle(context.Background(), fileStreamOpenFrame(t, id, protocol.StreamKindFileUpload, open, 1)); err != nil {
			t.Fatal(err)
		}
		if frame := sink.next(t); frame.Type != protocol.TypeStreamAccepted {
			t.Fatalf("stream %d response = %#v", id, frame)
		}
	}
	open := protocol.FileUploadOpen{Path: "incoming/overflow", Existing: protocol.FileExistingFail}
	if err := server.Handle(context.Background(), fileStreamOpenFrame(t, 20, protocol.StreamKindFileUpload, open, 1)); err != nil {
		t.Fatalf("resource limit became parent error: %v", err)
	}
	frame := sink.next(t)
	if frame.Type != protocol.TypeStreamError {
		t.Fatalf("limit response = %#v", frame)
	}
	var streamErr protocol.StreamError
	if err := protocol.ParseTypedStreamJSON(frame.Payload, &streamErr); err != nil {
		t.Fatal(err)
	}
	if streamErr.Code != "resource_limit" {
		t.Fatalf("limit code = %q", streamErr.Code)
	}
	server.CloseAll()
}

func TestTypedParentStreamRegistryConcurrentKinds(t *testing.T) {
	registry := newTypedParentStreamRegistry()
	var wg sync.WaitGroup
	errCh := make(chan error, 128)
	for i := 0; i < 128; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			kind := protocol.StreamKindFileUpload
			if i%2 == 0 {
				kind = protocol.StreamKindTerminal
			}
			id := uint32(protocol.MinTypedStreamID) + uint32(i)
			if err := registry.reserve(id, kind); err != nil {
				errCh <- err
				return
			}
			if err := registry.accept(id, kind); err != nil {
				errCh <- err
				return
			}
			if err := registry.close(id, kind); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}
