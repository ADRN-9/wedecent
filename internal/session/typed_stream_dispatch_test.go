package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"wedecent.com/wedecent/internal/protocol"
)

func TestRouteTypedApplicationFrameLeavesLegacyFramesAlone(t *testing.T) {
	handled, err := routeTypedApplicationFrame(context.Background(), nil, nil, nil, nil, protocol.Frame{Type: protocol.TypeData, StreamID: terminalStreamID})
	if err != nil {
		t.Fatal(err)
	}
	if handled {
		t.Fatal("legacy frame was classified as typed")
	}
}

func TestRouteTypedApplicationFrameRequiresTypedNegotiation(t *testing.T) {
	handled, err := routeTypedApplicationFrame(context.Background(), nil, newTypedParentStreamRegistry(), nil, nil, protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2})
	if !handled || !errors.Is(err, errTypedStreamProtocol) {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
}

func TestRouteTypedApplicationFrameRejectsFileWithoutFileCapability(t *testing.T) {
	runtime, root := newTestFileRuntime(t, true, false)
	if err := os.Mkdir(filepath.Join(root, "incoming"), 0o700); err != nil {
		t.Fatal(err)
	}
	registry := newTypedParentStreamRegistry()
	fileSink := newFileFrameSink()
	fileServer := newTypedFileServer(runtime, "client-1", registry, fileSink.write)
	open := protocol.FileUploadOpen{Path: "incoming/file.txt", Existing: protocol.FileExistingFail}

	handled, err := routeTypedApplicationFrame(
		context.Background(),
		[]protocol.Capability{protocol.CapabilityTypedStreamsV1},
		registry,
		nil,
		fileServer,
		fileStreamOpenFrame(t, 2, protocol.StreamKindFileUpload, open, 1),
	)
	if !handled || !errors.Is(err, errTypedStreamProtocol) {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	if _, err := os.Stat(filepath.Join(root, "incoming", "file.txt")); !os.IsNotExist(err) {
		t.Fatalf("unnegotiated file stream touched destination: %v", err)
	}
	select {
	case frame := <-fileSink.frames:
		t.Fatalf("unnegotiated file stream emitted frame: %#v", frame)
	default:
	}
}

func TestRouteTypedApplicationFrameRoutesFileByRegistryKind(t *testing.T) {
	runtime, root := newTestFileRuntime(t, true, false)
	if err := os.Mkdir(filepath.Join(root, "incoming"), 0o700); err != nil {
		t.Fatal(err)
	}
	registry := newTypedParentStreamRegistry()
	fileSink := newFileFrameSink()
	fileServer := newTypedFileServer(runtime, "client-1", registry, fileSink.write)
	caps := []protocol.Capability{protocol.CapabilityTypedStreamsV1, protocol.CapabilityFileTransferV1}
	open := protocol.FileUploadOpen{Path: "incoming/file.txt", Existing: protocol.FileExistingFail}

	handled, err := routeTypedApplicationFrame(context.Background(), caps, registry, nil, fileServer, fileStreamOpenFrame(t, 3, protocol.StreamKindFileUpload, open, 1))
	if err != nil || !handled {
		t.Fatalf("open handled=%v err=%v", handled, err)
	}
	if frame := fileSink.next(t); frame.Type != protocol.TypeStreamAccepted || frame.StreamID != 3 {
		t.Fatalf("file open response = %#v", frame)
	}

	handled, err = routeTypedApplicationFrame(context.Background(), caps, registry, nil, fileServer, protocol.Frame{Type: protocol.TypeStreamData, StreamID: 3, Payload: []byte("x")})
	if err != nil || !handled {
		t.Fatalf("data handled=%v err=%v", handled, err)
	}
	if frame := fileSink.next(t); frame.Type != protocol.TypeStreamWindowUpdate || frame.StreamID != 3 {
		t.Fatalf("file data response = %#v", frame)
	}

	handled, err = routeTypedApplicationFrame(context.Background(), caps, registry, nil, fileServer, streamCloseFrame(t, 3))
	if err != nil || !handled {
		t.Fatalf("close handled=%v err=%v", handled, err)
	}
	if frame := fileSink.next(t); frame.Type != protocol.TypeStreamClose || frame.StreamID != 3 {
		t.Fatalf("file close response = %#v", frame)
	}
	select {
	case frame := <-fileSink.frames:
		t.Fatalf("duplicate file close response = %#v", frame)
	default:
	}
}

func TestRouteTypedApplicationFrameRoutesTerminalWithFileCapabilityPresent(t *testing.T) {
	registry := newTypedParentStreamRegistry()
	sink := &typedFrameSink{}
	terminalServer := newTypedTerminalServerWithStarterAndRegistry(
		"/bin/sh",
		sink.write,
		func(string, uint16, uint16, string) (typedTerminalPTY, error) { return newFakeTypedPTY(), nil },
		registry,
	)
	caps := []protocol.Capability{protocol.CapabilityTypedStreamsV1, protocol.CapabilityFileTransferV1}

	handled, err := routeTypedApplicationFrame(context.Background(), caps, registry, terminalServer, nil, protocol.Frame{
		Type:     protocol.TypeStreamOpen,
		StreamID: 4,
		Payload:  typedOpenPayload(t, 64<<10),
	})
	if err != nil || !handled {
		t.Fatalf("terminal open handled=%v err=%v", handled, err)
	}
	frames := sink.snapshot()
	if len(frames) != 1 || frames[0].Type != protocol.TypeStreamAccepted || frames[0].StreamID != 4 {
		t.Fatalf("terminal frames = %#v", frames)
	}
	terminalServer.CloseAll()
}

func TestRouteTypedApplicationFrameRejectsUnknownOrClosedStream(t *testing.T) {
	registry := newTypedParentStreamRegistry()
	caps := []protocol.Capability{protocol.CapabilityTypedStreamsV1, protocol.CapabilityFileTransferV1}
	frame := protocol.Frame{Type: protocol.TypeStreamData, StreamID: 9, Payload: []byte("x")}
	if handled, err := routeTypedApplicationFrame(context.Background(), caps, registry, nil, nil, frame); !handled || !errors.Is(err, errTypedStreamProtocol) {
		t.Fatalf("unknown stream handled=%v err=%v", handled, err)
	}
	if err := registry.reserve(9, protocol.StreamKindFileUpload); err != nil {
		t.Fatal(err)
	}
	if err := registry.accept(9, protocol.StreamKindFileUpload); err != nil {
		t.Fatal(err)
	}
	if err := registry.close(9, protocol.StreamKindFileUpload); err != nil {
		t.Fatal(err)
	}
	if handled, err := routeTypedApplicationFrame(context.Background(), caps, registry, nil, nil, frame); !handled || !errors.Is(err, errTypedStreamProtocol) {
		t.Fatalf("closed stream handled=%v err=%v", handled, err)
	}
}
