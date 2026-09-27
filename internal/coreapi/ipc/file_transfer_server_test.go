package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"wedecent.com/wedecent/internal/coreapi"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeFileTransferService struct {
	status    v1.FileTransferStatus
	operation v1.FileTransferOperation
	download  v1.FileDownloadReadResult
	err       error
	written   []byte
}

func (f *fakeFileTransferService) GetFileTransferStatus(context.Context, v1.FileTransferStatusRequest) (v1.FileTransferStatus, error) {
	return f.status, f.err
}
func (f *fakeFileTransferService) OpenFileUpload(context.Context, v1.FileUploadOpenRequest) (v1.FileTransferOperation, error) {
	return f.operation, f.err
}
func (f *fakeFileTransferService) WriteFileUpload(_ context.Context, req v1.FileUploadWriteRequest) error {
	f.written = append([]byte(nil), req.Data...)
	return f.err
}
func (f *fakeFileTransferService) CommitFileUpload(context.Context, v1.FileUploadCommitRequest) error {
	return f.err
}
func (f *fakeFileTransferService) OpenFileDownload(context.Context, v1.FileDownloadOpenRequest) (v1.FileTransferOperation, error) {
	return f.operation, f.err
}
func (f *fakeFileTransferService) ReadFileDownload(context.Context, v1.FileDownloadReadRequest) (v1.FileDownloadReadResult, error) {
	return f.download, f.err
}
func (f *fakeFileTransferService) CancelFileTransfer(context.Context, v1.FileTransferCancelRequest) error {
	return f.err
}

func newFileIPCServer(t *testing.T, files v1.FileTransferService) *Server {
	t.Helper()
	read := &fakeReadService{}
	server, err := NewServerWithServices(Services{Status: read, Devices: read, FileTransfer: files})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestFileTransferIPCUnavailableSurfaceIsMethodNotFound(t *testing.T) {
	server := newFileIPCServer(t, nil)
	params, err := json.Marshal(v1.FileTransferStatusRequest{ConnectionID: "conn_AAAAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{Version: v1.Version, ID: "file-1", Method: v1.MethodFileTransferStatus, Params: params})
	if response.Error == nil || response.Error.Code != ErrorMethodNotFound {
		t.Fatalf("response = %#v", response)
	}
}

func TestFileTransferIPCStrictParamsAndUploadDelegation(t *testing.T) {
	files := &fakeFileTransferService{}
	server := newFileIPCServer(t, files)

	bad := serve(t, server, Request{
		Version: v1.Version,
		ID:      "file-2",
		Method:  v1.MethodFileUploadOpen,
		Params:  json.RawMessage(`{"connection_id":"conn_AAAAAAAAAAAAAAAAAAAAAAAA","path":"safe.txt","extra":true}`),
	})
	if bad.Error == nil || bad.Error.Code != ErrorInvalidParams {
		t.Fatalf("strict params response = %#v", bad)
	}

	params, err := json.Marshal(v1.FileUploadWriteRequest{
		ConnectionID: "conn_AAAAAAAAAAAAAAAAAAAAAAAA",
		OperationID:  "file_AAAAAAAAAAAAAAAAAAAAAAAA",
		Data:         []byte("abc"),
	})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{Version: v1.Version, ID: "file-3", Method: v1.MethodFileUploadWrite, Params: params})
	if response.Error != nil {
		t.Fatalf("response error = %#v", response.Error)
	}
	if string(files.written) != "abc" {
		t.Fatalf("written = %q", files.written)
	}
}

func TestFileTransferIPCMapsSanitizedErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code string
	}{
		{name: "invalid", err: coreapi.ErrInvalidFileTransferRequest, code: ErrorInvalidParams},
		{name: "unavailable", err: coreapi.ErrFileTransferUnavailable, code: ErrorFileTransferUnavailable},
		{name: "limit", err: coreapi.ErrFileTransferLimit, code: ErrorFileTransferLimit},
		{name: "not-found", err: coreapi.ErrFileTransferNotFound, code: ErrorFileTransferNotFound},
		{name: "operation", err: coreapi.ErrFileTransferOperation, code: ErrorFileTransferFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := &fakeFileTransferService{err: tt.err}
			server := newFileIPCServer(t, files)
			params, err := json.Marshal(v1.FileTransferStatusRequest{ConnectionID: "conn_AAAAAAAAAAAAAAAAAAAAAAAA"})
			if err != nil {
				t.Fatal(err)
			}
			response := serve(t, server, Request{Version: v1.Version, ID: "file-4", Method: v1.MethodFileTransferStatus, Params: params})
			if response.Error == nil || response.Error.Code != tt.code {
				t.Fatalf("response = %#v", response)
			}
		})
	}
}

func TestFileTransferIPCDoesNotLeakBackendError(t *testing.T) {
	files := &fakeFileTransferService{err: errors.New("secret-file-path-and-token")}
	server := newFileIPCServer(t, files)
	params, err := json.Marshal(v1.FileTransferStatusRequest{ConnectionID: "conn_AAAAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, server, Request{Version: v1.Version, ID: "file-5", Method: v1.MethodFileTransferStatus, Params: params})
	if response.Error == nil || response.Error.Code != ErrorInternal || response.Error.Message != "internal error" {
		t.Fatalf("response = %#v", response)
	}
}
