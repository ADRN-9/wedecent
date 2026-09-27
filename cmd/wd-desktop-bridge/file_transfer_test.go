package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeFileCoreSource struct {
	*fakeCoreSource
	status        v1.FileTransferStatus
	uploadOpenReq v1.FileUploadOpenRequest
	uploadWrite   v1.FileUploadWriteRequest
	uploadCommit  v1.FileUploadCommitRequest
	downloadOpen  v1.FileDownloadOpenRequest
	downloadRead  v1.FileDownloadReadRequest
	cancelReq     v1.FileTransferCancelRequest
	uploadOp      v1.FileTransferOperation
	downloadOp    v1.FileTransferOperation
	readResult    v1.FileDownloadReadResult
}

func (f *fakeFileCoreSource) GetFileTransferStatus(context.Context, v1.FileTransferStatusRequest) (v1.FileTransferStatus, error) {
	return f.status, nil
}
func (f *fakeFileCoreSource) OpenFileUpload(_ context.Context, req v1.FileUploadOpenRequest) (v1.FileTransferOperation, error) {
	f.uploadOpenReq = req
	return f.uploadOp, nil
}
func (f *fakeFileCoreSource) WriteFileUpload(_ context.Context, req v1.FileUploadWriteRequest) error {
	f.uploadWrite = req
	return nil
}
func (f *fakeFileCoreSource) CommitFileUpload(_ context.Context, req v1.FileUploadCommitRequest) error {
	f.uploadCommit = req
	return nil
}
func (f *fakeFileCoreSource) OpenFileDownload(_ context.Context, req v1.FileDownloadOpenRequest) (v1.FileTransferOperation, error) {
	f.downloadOpen = req
	return f.downloadOp, nil
}
func (f *fakeFileCoreSource) ReadFileDownload(_ context.Context, req v1.FileDownloadReadRequest) (v1.FileDownloadReadResult, error) {
	f.downloadRead = req
	return f.readResult, nil
}
func (f *fakeFileCoreSource) CancelFileTransfer(_ context.Context, req v1.FileTransferCancelRequest) error {
	f.cancelReq = req
	return nil
}

func TestServeFileTransferOperationsAreFixedAndBounded(t *testing.T) {
	const connectionID = "conn_AAAAAAAAAAAAAAAAAAAAAAAA"
	const uploadID = "file_AAAAAAAAAAAAAAAAAAAAAAAA"
	const downloadID = "file_BBBBBBBBBBBBBBBBBBBBBBBB"
	source := &fakeFileCoreSource{
		fakeCoreSource: &fakeCoreSource{},
		status:         v1.FileTransferStatus{Available: true},
		uploadOp:       v1.FileTransferOperation{ID: uploadID, ConnectionID: connectionID, Direction: v1.FileTransferDirectionUpload},
		downloadOp:     v1.FileTransferOperation{ID: downloadID, ConnectionID: connectionID, Direction: v1.FileTransferDirectionDownload},
		readResult:     v1.FileDownloadReadResult{Data: []byte("payload"), Done: true},
	}

	input := strings.Join([]string{
		`{"op":"file-status","request":{"connection_id":"` + connectionID + `"}}`,
		`{"op":"file-upload-open","request":{"connection_id":"` + connectionID + `","path":"dir/file.txt","expected_size":7}}`,
		`{"op":"file-upload-write","request":{"connection_id":"` + connectionID + `","operation_id":"` + uploadID + `","data":"cGF5bG9hZA=="}}`,
		`{"op":"file-upload-commit","request":{"connection_id":"` + connectionID + `","operation_id":"` + uploadID + `"}}`,
		`{"op":"file-download-open","request":{"connection_id":"` + connectionID + `","path":"dir/file.txt"}}`,
		`{"op":"file-download-read","request":{"connection_id":"` + connectionID + `","operation_id":"` + downloadID + `","max_bytes":32768}}`,
		`{"op":"file-cancel","request":{"connection_id":"` + connectionID + `","operation_id":"` + downloadID + `"}}`,
	}, "\n") + "\n"

	var out bytes.Buffer
	if err := run([]string{"serve"}, strings.NewReader(input), &out, source); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 7 {
		t.Fatalf("response lines=%d output=%q", len(lines), out.String())
	}
	for i, line := range lines {
		if !strings.Contains(line, `"ok":true`) {
			t.Fatalf("response[%d]=%q", i, line)
		}
	}
	if source.uploadOpenReq.Path != "dir/file.txt" || source.uploadOpenReq.ExpectedSize == nil || *source.uploadOpenReq.ExpectedSize != 7 {
		t.Fatalf("upload open=%+v", source.uploadOpenReq)
	}
	if string(source.uploadWrite.Data) != "payload" || source.uploadCommit.OperationID != uploadID {
		t.Fatalf("upload write=%+v commit=%+v", source.uploadWrite, source.uploadCommit)
	}
	if source.downloadRead.MaxBytes != v1.MaxFileTransferChunkBytes || source.cancelReq.OperationID != downloadID {
		t.Fatalf("download read=%+v cancel=%+v", source.downloadRead, source.cancelReq)
	}
	if !strings.Contains(lines[5], base64.StdEncoding.EncodeToString([]byte("payload"))) {
		t.Fatalf("download response=%q", lines[5])
	}
}

func TestServeFileTransferRejectsUnknownFieldsWithoutCoreCall(t *testing.T) {
	source := &fakeFileCoreSource{fakeCoreSource: &fakeCoreSource{}}
	input := `{"op":"file-upload-open","request":{"connection_id":"conn_AAAAAAAAAAAAAAAAAAAAAAAA","path":"file.txt","endpoint":"tcp://forbidden"}}` + "\n"
	var out bytes.Buffer
	if err := run([]string{"serve"}, strings.NewReader(input), &out, source); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"ok":false`) || !strings.Contains(out.String(), "Invalid desktop terminal request") {
		t.Fatalf("response=%q", out.String())
	}
	if source.uploadOpenReq.ConnectionID != "" {
		t.Fatalf("unexpected core call=%+v", source.uploadOpenReq)
	}
}

func TestPublicErrorSanitizesFileTransferValidation(t *testing.T) {
	got := publicError(fmt.Errorf("%w: secret path", desktopbridge.ErrInvalidFileTransferBridgeRequest))
	if got != "Invalid desktop file transfer request" || strings.Contains(got, "secret") {
		t.Fatalf("publicError=%q", got)
	}
}
