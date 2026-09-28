package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/protocol"
)

type managedFileTestAuthorizer struct {
	mu            sync.Mutex
	allowUpload   bool
	allowDownload bool
}

func (a *managedFileTestAuthorizer) AuthorizeFileTransfer(ctx context.Context, req FileTransferAuthorizationRequest) error {
	a.mu.Lock()
	allowUpload := a.allowUpload
	allowDownload := a.allowDownload
	a.mu.Unlock()
	return (StaticFileTransferAuthorizer{
		AllowUpload:   allowUpload,
		AllowDownload: allowDownload,
	}).AuthorizeFileTransfer(ctx, req)
}

func (a *managedFileTestAuthorizer) set(upload, download bool) {
	a.mu.Lock()
	a.allowUpload = upload
	a.allowDownload = download
	a.mu.Unlock()
}

func TestParseManagedMultiplexCapabilities(t *testing.T) {
	jsonPayload := func(capabilities ...protocol.Capability) []byte {
		t.Helper()
		payload, err := protocol.JSON(protocol.SessionAccepted{Capabilities: capabilities})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	tests := []struct {
		name    string
		data    []byte
		typed   bool
		file    bool
		wantErr bool
	}{
		{name: "legacy"},
		{name: "typed", data: jsonPayload(protocol.CapabilityTypedStreamsV1), typed: true},
		{name: "typed file", data: jsonPayload(protocol.CapabilityTypedStreamsV1, protocol.CapabilityFileTransferV1), typed: true, file: true},
		{name: "file only", data: jsonPayload(protocol.CapabilityFileTransferV1), wantErr: true},
		{name: "reversed", data: jsonPayload(protocol.CapabilityFileTransferV1, protocol.CapabilityTypedStreamsV1), wantErr: true},
		{name: "duplicate", data: jsonPayload(protocol.CapabilityTypedStreamsV1, protocol.CapabilityTypedStreamsV1), wantErr: true},
		{name: "unknown", data: jsonPayload(protocol.Capability("future-v1")), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typed, file, err := parseManagedMultiplexCapabilities(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected capability error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if typed != tt.typed || file != tt.file {
				t.Fatalf("capabilities = typed:%t file:%t, want typed:%t file:%t", typed, file, tt.typed, tt.file)
			}
		})
	}
}

func TestManagedFileTransferLiveUploadDownloadAndTerminalSibling(t *testing.T) {
	root := t.TempDir()
	downloadData := bytes.Repeat([]byte("0123456789abcdef"), 20*1024) // 320 KiB, crosses the 256 KiB receive window.
	if err := os.WriteFile(root+"/download.bin", downloadData, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenFileTransferStore(root, 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runtime := &FileTransferRuntime{
		Store: store,
		Authorizer: StaticFileTransferAuthorizer{
			AllowUpload: true, AllowDownload: true,
		},
	}

	clientID, serverID, peer := managedSessionTestIdentities(t, "tcp://ignored.test:7443")
	clientSide, serverSide := net.Pipe()
	dialer := &managedTestDialer{conn: clientSide}
	started := make(chan *liveMuxPTY, 4)
	serverErr := make(chan error, 1)
	go serveManagedFileTestParent(serverSide, serverID, clientID.ID, runtime, started, serverErr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := &Client{Identity: clientID, Dialer: dialer, ConnectionGrant: "header.payload.signature"}
	managed, err := client.OpenManagedMultiplexSession(ctx, peer, 80, 24, "xterm-256color")
	if err != nil {
		t.Fatal(err)
	}
	defer managed.Close()
	if !managed.FileTransferAvailable() {
		t.Fatal("file transfer was not negotiated")
	}
	_ = waitLiveMuxPTYStarted(t, started)

	wantUpload := bytes.Repeat([]byte("upload-data-"), 9000)
	size := uint64(len(wantUpload))
	digest := sha256.Sum256(wantUpload)
	upload, err := managed.OpenFileUpload(ctx, protocol.FileUploadOpen{
		Path: "upload.bin", ExpectedSize: &size,
		SHA256: hex.EncodeToString(digest[:]), Existing: protocol.FileExistingFail,
	})
	if err != nil {
		t.Fatal(err)
	}
	uploadData := append([]byte(nil), wantUpload...)
	for len(uploadData) != 0 {
		n := 17000
		if n > len(uploadData) {
			n = len(uploadData)
		}
		if err := upload.Write(ctx, uploadData[:n]); err != nil {
			t.Fatal(err)
		}
		uploadData = uploadData[n:]
	}
	if err := upload.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(root + "/upload.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, wantUpload) {
		t.Fatal("committed upload differs from source")
	}

	download, err := managed.OpenFileDownload(ctx, protocol.FileDownloadOpen{Path: "download.bin"})
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	for {
		chunk, done, err := download.Read(ctx, 23<<10)
		if err != nil {
			t.Fatal(err)
		}
		got.Write(chunk)
		if done {
			break
		}
	}
	if !bytes.Equal(got.Bytes(), downloadData) {
		t.Fatalf("download length/content mismatch: got %d want %d", got.Len(), len(downloadData))
	}

	if _, err := managed.ProbeLatency(ctx); err != nil {
		t.Fatalf("terminal parent did not survive file operations: %v", err)
	}
	if err := managed.Close(); err != nil {
		t.Fatal(err)
	}
	waitManagedFileServer(t, serverErr)
}

func TestManagedFileTransferDenialAndCancelStayChildScoped(t *testing.T) {
	root := t.TempDir()
	store, err := OpenFileTransferStore(root, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authorizer := &managedFileTestAuthorizer{allowDownload: true}
	runtime := &FileTransferRuntime{Store: store, Authorizer: authorizer}

	clientID, serverID, peer := managedSessionTestIdentities(t, "tcp://ignored.test:7443")
	clientSide, serverSide := net.Pipe()
	started := make(chan *liveMuxPTY, 2)
	serverErr := make(chan error, 1)
	go serveManagedFileTestParent(serverSide, serverID, clientID.ID, runtime, started, serverErr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	managed, err := (&Client{Identity: clientID, Dialer: &managedTestDialer{conn: clientSide}, ConnectionGrant: "header.payload.signature"}).OpenManagedMultiplexSession(ctx, peer, 80, 24, "xterm")
	if err != nil {
		t.Fatal(err)
	}
	defer managed.Close()
	_ = waitLiveMuxPTYStarted(t, started)

	_, err = managed.OpenFileUpload(ctx, protocol.FileUploadOpen{Path: "denied.bin", Existing: protocol.FileExistingFail})
	var streamErr *ManagedFileStreamError
	if !errors.As(err, &streamErr) || streamErr.Code != "authorization_denied" {
		t.Fatalf("denied upload error = %v", err)
	}
	if _, err := managed.ProbeLatency(ctx); err != nil {
		t.Fatalf("parent did not survive denied file child: %v", err)
	}

	authorizer.set(true, true)
	upload, err := managed.OpenFileUpload(ctx, protocol.FileUploadOpen{Path: "cancel.bin", Existing: protocol.FileExistingFail})
	if err != nil {
		t.Fatal(err)
	}
	if err := upload.Write(ctx, []byte("partial")); err != nil {
		t.Fatal(err)
	}
	if err := upload.Cancel(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := managed.ProbeLatency(ctx); err != nil {
		t.Fatalf("parent did not survive cancelled file child: %v", err)
	}
	if _, err := os.Stat(root + "/cancel.bin"); !os.IsNotExist(err) {
		t.Fatalf("cancelled upload destination exists: %v", err)
	}
	waitForNoUploadStages(t, root)

	if err := managed.Close(); err != nil {
		t.Fatal(err)
	}
	waitManagedFileServer(t, serverErr)
}

func serveManagedFileTestParent(raw net.Conn, serverID *identity.Identity, peerID string, runtime *FileTransferRuntime, started chan<- *liveMuxPTY, serverErr chan<- error) {
	conn := tls.Server(raw, identity.ServerTLS(serverID))
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if err := conn.HandshakeContext(context.Background()); err != nil {
		serverErr <- err
		return
	}
	first, err := protocol.ReadFrame(conn)
	if err != nil {
		serverErr <- err
		return
	}
	if first.Type != protocol.TypeOpenAuthorizedSession {
		serverErr <- errors.New("managed file client did not use authorized session open")
		return
	}
	var open protocol.OpenAuthorizedSession
	if err := protocol.ParseJSON(first.Payload, &open); err != nil {
		serverErr <- err
		return
	}
	if len(open.Capabilities) != 2 || open.Capabilities[0] != protocol.CapabilityTypedStreamsV1 || open.Capabilities[1] != protocol.CapabilityFileTransferV1 {
		serverErr <- errors.New("managed file client did not request the exact file capability set")
		return
	}
	capabilities := []protocol.Capability{protocol.CapabilityTypedStreamsV1, protocol.CapabilityFileTransferV1}
	accepted, err := sessionAcceptedFrame(capabilities)
	if err != nil {
		serverErr <- err
		return
	}
	var writeMu sync.Mutex
	writeFrame := func(frame protocol.Frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return protocol.WriteFrame(conn, frame)
	}
	if err := writeFrame(accepted); err != nil {
		serverErr <- err
		return
	}

	registry := newTypedParentStreamRegistry()
	terminalServer := newTypedTerminalServerWithStarter("/bin/sh", writeFrame, func(_ string, cols, rows uint16, _ string) (typedTerminalPTY, error) {
		pty := newLiveMuxPTY(cols, rows)
		started <- pty
		return pty, nil
	})
	terminalServer.states = newTypedTerminalStreamSetWithRegistry(registry)
	fileServer := newTypedFileServer(runtime, peerID, registry, writeFrame)
	defer terminalServer.CloseAll()
	defer fileServer.CloseAll()

	for {
		frame, err := protocol.ReadFrame(conn)
		if err != nil {
			if isExpectedLiveMuxCloseError(err) {
				serverErr <- nil
			} else {
				serverErr <- err
			}
			return
		}
		handled, err := routeTypedApplicationFrame(context.Background(), capabilities, registry, terminalServer, fileServer, frame)
		if handled {
			if err != nil {
				serverErr <- err
				return
			}
			continue
		}
		switch frame.Type {
		case protocol.TypePing:
			if err := writeFrame(protocol.Frame{Type: protocol.TypePong}); err != nil {
				serverErr <- err
				return
			}
		case protocol.TypeClose:
			serverErr <- nil
			return
		default:
			serverErr <- errors.New("unexpected frame in managed file test server")
			return
		}
	}
}

func waitForNoUploadStages(t *testing.T, root string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".wedecent-upload-") {
				found = true
				break
			}
		}
		if !found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("cancelled upload staging file was not removed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitManagedFileServer(t *testing.T, serverErr <-chan error) {
	t.Helper()
	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("managed file test server did not stop")
	}
}
