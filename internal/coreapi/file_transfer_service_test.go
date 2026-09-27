package coreapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/protocol"
)

const testFileConnectionID = "conn_AAAAAAAAAAAAAAAAAAAAAAAA"

type testConnectionTokenHolder struct {
	pad   byte
	token struct{}
}

type fakeFileParent struct {
	mu        sync.Mutex
	available bool
	done      chan struct{}
	upload    *fakeUploadHandle
	download  *fakeDownloadHandle
	uploads   int
	downloads int
}

func (p *fakeFileParent) Close() error                { return nil }
func (p *fakeFileParent) Done() <-chan struct{}       { return p.done }
func (p *fakeFileParent) FileTransferAvailable() bool { return p.available }
func (p *fakeFileParent) OpenFileUpload(_ context.Context, _ protocol.FileUploadOpen) (FileUploadHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.uploads++
	if p.upload == nil {
		p.upload = &fakeUploadHandle{done: make(chan struct{})}
	}
	return p.upload, nil
}
func (p *fakeFileParent) OpenFileDownload(_ context.Context, _ protocol.FileDownloadOpen) (FileDownloadHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.downloads++
	if p.download == nil {
		p.download = &fakeDownloadHandle{done: make(chan struct{})}
	}
	return p.download, nil
}

type fakeUploadHandle struct {
	mu      sync.Mutex
	done    chan struct{}
	writes  [][]byte
	commits int
	cancels int
}

func (h *fakeUploadHandle) Done() <-chan struct{} { return h.done }
func (h *fakeUploadHandle) Write(_ context.Context, data []byte) error {
	h.mu.Lock()
	h.writes = append(h.writes, append([]byte(nil), data...))
	h.mu.Unlock()
	return nil
}
func (h *fakeUploadHandle) Commit(context.Context) error {
	h.mu.Lock()
	h.commits++
	h.mu.Unlock()
	return nil
}
func (h *fakeUploadHandle) Cancel(context.Context) error {
	h.mu.Lock()
	h.cancels++
	h.mu.Unlock()
	return nil
}

type fakeDownloadHandle struct {
	mu      sync.Mutex
	done    chan struct{}
	data    []byte
	cancels int
	overrun bool
}

func (h *fakeDownloadHandle) Done() <-chan struct{} { return h.done }
func (h *fakeDownloadHandle) Read(_ context.Context, max int) ([]byte, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.overrun {
		return make([]byte, max+1), false, nil
	}
	if len(h.data) == 0 {
		return nil, true, nil
	}
	n := max
	if n > len(h.data) {
		n = len(h.data)
	}
	out := append([]byte(nil), h.data[:n]...)
	h.data = h.data[n:]
	return out, len(h.data) == 0, nil
}
func (h *fakeDownloadHandle) Cancel(context.Context) error {
	h.mu.Lock()
	h.cancels++
	h.mu.Unlock()
	return nil
}

func newFileServiceForTest(t *testing.T, parent *fakeFileParent, max int, random io.Reader) (*FileTransferService, *ConnectionService, *struct{}) {
	t.Helper()
	holder := &testConnectionTokenHolder{pad: 1}
	token := &holder.token
	connections := &ConnectionService{
		active: map[string]activeConnection{
			testFileConnectionID: {handle: parent, token: token},
		},
	}
	service, err := NewFileTransferService(FileTransferServiceConfig{Connections: connections, MaxActive: max, Random: random})
	if err != nil {
		t.Fatal(err)
	}
	return service, connections, token
}

func TestFileTransferServiceUploadCommitIsOpaqueBoundedAndOneShot(t *testing.T) {
	parent := &fakeFileParent{available: true, done: make(chan struct{}), upload: &fakeUploadHandle{done: make(chan struct{})}}
	service, _, _ := newFileServiceForTest(t, parent, 4, bytes.NewReader(bytes.Repeat([]byte{1}, 128)))

	size := uint64(3)
	op, err := service.OpenFileUpload(context.Background(), v1.FileUploadOpenRequest{
		ConnectionID: testFileConnectionID,
		Path:         "dir/file.txt",
		ExpectedSize: &size,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !validFileTransferID(op.ID) || op.Direction != v1.FileTransferDirectionUpload || op.ConnectionID != testFileConnectionID {
		t.Fatalf("unexpected operation: %+v", op)
	}
	if err := service.WriteFileUpload(context.Background(), v1.FileUploadWriteRequest{ConnectionID: testFileConnectionID, OperationID: op.ID, Data: []byte("abc")}); err != nil {
		t.Fatal(err)
	}
	if err := service.WriteFileUpload(context.Background(), v1.FileUploadWriteRequest{ConnectionID: testFileConnectionID, OperationID: op.ID, Data: make([]byte, v1.MaxFileTransferChunkBytes+1)}); !errors.Is(err, ErrInvalidFileTransferRequest) {
		t.Fatalf("oversized upload write error = %v", err)
	}
	if err := service.CommitFileUpload(context.Background(), v1.FileUploadCommitRequest{ConnectionID: testFileConnectionID, OperationID: op.ID}); err != nil {
		t.Fatal(err)
	}
	if err := service.CommitFileUpload(context.Background(), v1.FileUploadCommitRequest{ConnectionID: testFileConnectionID, OperationID: op.ID}); !errors.Is(err, ErrFileTransferNotFound) {
		t.Fatalf("second commit error = %v", err)
	}
	parent.upload.mu.Lock()
	commits := parent.upload.commits
	writes := append([][]byte(nil), parent.upload.writes...)
	parent.upload.mu.Unlock()
	if commits != 1 || len(writes) != 1 || string(writes[0]) != "abc" {
		t.Fatalf("upload calls = commits:%d writes:%q", commits, writes)
	}
}

func TestFileTransferServiceValidatesPathAvailabilityAndConnectionToken(t *testing.T) {
	parent := &fakeFileParent{available: false, done: make(chan struct{}), upload: &fakeUploadHandle{done: make(chan struct{})}}
	service, connections, token := newFileServiceForTest(t, parent, 4, bytes.NewReader(bytes.Repeat([]byte{2}, 128)))

	_, err := service.OpenFileUpload(context.Background(), v1.FileUploadOpenRequest{ConnectionID: testFileConnectionID, Path: "../escape", ExpectedSize: nil})
	if !errors.Is(err, ErrInvalidFileTransferRequest) {
		t.Fatalf("invalid path error = %v", err)
	}
	_, err = service.OpenFileDownload(context.Background(), v1.FileDownloadOpenRequest{ConnectionID: testFileConnectionID, Path: "safe.txt"})
	if !errors.Is(err, ErrFileTransferUnavailable) {
		t.Fatalf("unavailable error = %v", err)
	}

	parent.available = true
	op, err := service.OpenFileUpload(context.Background(), v1.FileUploadOpenRequest{ConnectionID: testFileConnectionID, Path: "safe.txt"})
	if err != nil {
		t.Fatal(err)
	}
	connections.mu.Lock()
	active := connections.active[testFileConnectionID]
	replacement := &testConnectionTokenHolder{pad: 1}
	active.token = &replacement.token
	connections.active[testFileConnectionID] = active
	connections.mu.Unlock()
	if active.token == token {
		t.Fatal("test failed to replace connection token")
	}
	if err := service.WriteFileUpload(context.Background(), v1.FileUploadWriteRequest{ConnectionID: testFileConnectionID, OperationID: op.ID, Data: []byte("x")}); !errors.Is(err, ErrFileTransferNotFound) {
		t.Fatalf("stale operation error = %v", err)
	}
}

func TestFileTransferServiceDownloadBoundsCompletionAndCancel(t *testing.T) {
	download := &fakeDownloadHandle{done: make(chan struct{}), data: []byte("abcdef")}
	parent := &fakeFileParent{available: true, done: make(chan struct{}), download: download}
	service, _, _ := newFileServiceForTest(t, parent, 4, bytes.NewReader(bytes.Repeat([]byte{3}, 128)))

	op, err := service.OpenFileDownload(context.Background(), v1.FileDownloadOpenRequest{ConnectionID: testFileConnectionID, Path: "safe.bin"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.ReadFileDownload(context.Background(), v1.FileDownloadReadRequest{ConnectionID: testFileConnectionID, OperationID: op.ID, MaxBytes: 3})
	if err != nil || string(got.Data) != "abc" || got.Done {
		t.Fatalf("first read = %+v, %v", got, err)
	}
	got, err = service.ReadFileDownload(context.Background(), v1.FileDownloadReadRequest{ConnectionID: testFileConnectionID, OperationID: op.ID, MaxBytes: 3})
	if err != nil || string(got.Data) != "def" || !got.Done {
		t.Fatalf("second read = %+v, %v", got, err)
	}
	if _, err := service.ReadFileDownload(context.Background(), v1.FileDownloadReadRequest{ConnectionID: testFileConnectionID, OperationID: op.ID, MaxBytes: 3}); !errors.Is(err, ErrFileTransferNotFound) {
		t.Fatalf("read after completion error = %v", err)
	}

	parent.download = &fakeDownloadHandle{done: make(chan struct{}), data: []byte("more")}
	op, err = service.OpenFileDownload(context.Background(), v1.FileDownloadOpenRequest{ConnectionID: testFileConnectionID, Path: "other.bin"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CancelFileTransfer(context.Background(), v1.FileTransferCancelRequest{ConnectionID: testFileConnectionID, OperationID: op.ID}); err != nil {
		t.Fatal(err)
	}
	parent.download.mu.Lock()
	cancels := parent.download.cancels
	parent.download.mu.Unlock()
	if cancels != 1 {
		t.Fatalf("download cancels = %d", cancels)
	}
}

func TestFileTransferServiceRejectsBackendDownloadOverrun(t *testing.T) {
	parent := &fakeFileParent{available: true, done: make(chan struct{}), download: &fakeDownloadHandle{done: make(chan struct{}), overrun: true}}
	service, _, _ := newFileServiceForTest(t, parent, 2, bytes.NewReader(bytes.Repeat([]byte{4}, 128)))
	op, err := service.OpenFileDownload(context.Background(), v1.FileDownloadOpenRequest{ConnectionID: testFileConnectionID, Path: "safe.bin"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.ReadFileDownload(context.Background(), v1.FileDownloadReadRequest{ConnectionID: testFileConnectionID, OperationID: op.ID, MaxBytes: 8})
	if !errors.Is(err, ErrFileTransferOperation) {
		t.Fatalf("overrun error = %v", err)
	}
}

type barrierReader struct {
	mu      sync.Mutex
	arrived int
	release chan struct{}
	seq     byte
}

func newBarrierReader() *barrierReader { return &barrierReader{release: make(chan struct{})} }
func (r *barrierReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	r.arrived++
	arrived := r.arrived
	r.seq++
	value := r.seq
	if arrived == 2 {
		close(r.release)
	}
	r.mu.Unlock()
	<-r.release
	for i := range p {
		p[i] = value
	}
	return len(p), nil
}

func TestFileTransferServiceParallelReservationHonorsLimit(t *testing.T) {
	parent := &fakeFileParent{available: true, done: make(chan struct{})}
	reader := newBarrierReader()
	service, _, _ := newFileServiceForTest(t, parent, 1, reader)

	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			<-start
			_, err := service.OpenFileUpload(context.Background(), v1.FileUploadOpenRequest{ConnectionID: testFileConnectionID, Path: "file" + string(rune('a'+i))})
			results <- err
		}(i)
	}
	close(start)

	var success, limited int
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			switch {
			case err == nil:
				success++
			case errors.Is(err, ErrFileTransferLimit):
				limited++
			default:
				t.Fatalf("parallel open error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("parallel opens deadlocked")
		}
	}
	if success != 1 || limited != 1 {
		t.Fatalf("parallel results success=%d limited=%d", success, limited)
	}
	parent.mu.Lock()
	opens := parent.uploads
	parent.mu.Unlock()
	if opens != 1 {
		t.Fatalf("remote upload opens = %d, want 1", opens)
	}
}
