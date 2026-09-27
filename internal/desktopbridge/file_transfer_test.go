package desktopbridge

import (
	"context"
	"errors"
	"testing"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeFileTransferSource struct {
	status        v1.FileTransferStatus
	statusReq     v1.FileTransferStatusRequest
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

func (f *fakeFileTransferSource) GetFileTransferStatus(_ context.Context, req v1.FileTransferStatusRequest) (v1.FileTransferStatus, error) {
	f.statusReq = req
	return f.status, nil
}
func (f *fakeFileTransferSource) OpenFileUpload(_ context.Context, req v1.FileUploadOpenRequest) (v1.FileTransferOperation, error) {
	f.uploadOpenReq = req
	return f.uploadOp, nil
}
func (f *fakeFileTransferSource) WriteFileUpload(_ context.Context, req v1.FileUploadWriteRequest) error {
	f.uploadWrite = req
	return nil
}
func (f *fakeFileTransferSource) CommitFileUpload(_ context.Context, req v1.FileUploadCommitRequest) error {
	f.uploadCommit = req
	return nil
}
func (f *fakeFileTransferSource) OpenFileDownload(_ context.Context, req v1.FileDownloadOpenRequest) (v1.FileTransferOperation, error) {
	f.downloadOpen = req
	return f.downloadOp, nil
}
func (f *fakeFileTransferSource) ReadFileDownload(_ context.Context, req v1.FileDownloadReadRequest) (v1.FileDownloadReadResult, error) {
	f.downloadRead = req
	return f.readResult, nil
}
func (f *fakeFileTransferSource) CancelFileTransfer(_ context.Context, req v1.FileTransferCancelRequest) error {
	f.cancelReq = req
	return nil
}

func TestDesktopFileTransferRoundTripValidation(t *testing.T) {
	const connectionID = "conn_AAAAAAAAAAAAAAAAAAAAAAAA"
	const uploadID = "file_AAAAAAAAAAAAAAAAAAAAAAAA"
	const downloadID = "file_BBBBBBBBBBBBBBBBBBBBBBBB"
	source := &fakeFileTransferSource{
		status:     v1.FileTransferStatus{Available: true},
		uploadOp:   v1.FileTransferOperation{ID: uploadID, ConnectionID: connectionID, Direction: v1.FileTransferDirectionUpload},
		downloadOp: v1.FileTransferOperation{ID: downloadID, ConnectionID: connectionID, Direction: v1.FileTransferDirectionDownload},
		readResult: v1.FileDownloadReadResult{Data: []byte("abc"), Done: true},
	}

	status, err := GetFileTransferStatus(context.Background(), source, connectionID)
	if err != nil || !status.Available || source.statusReq.ConnectionID != connectionID {
		t.Fatalf("status=%+v req=%+v err=%v", status, source.statusReq, err)
	}

	size := uint64(3)
	upload, err := OpenFileUpload(context.Background(), source, connectionID, "dir/file.txt", &size, "")
	if err != nil || upload.ID != uploadID || source.uploadOpenReq.Path != "dir/file.txt" || source.uploadOpenReq.ExpectedSize == nil || *source.uploadOpenReq.ExpectedSize != size {
		t.Fatalf("upload=%+v req=%+v err=%v", upload, source.uploadOpenReq, err)
	}
	if err := WriteFileUpload(context.Background(), source, connectionID, uploadID, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if string(source.uploadWrite.Data) != "abc" {
		t.Fatalf("upload data=%q", source.uploadWrite.Data)
	}
	if err := CommitFileUpload(context.Background(), source, connectionID, uploadID); err != nil || source.uploadCommit.OperationID != uploadID {
		t.Fatalf("commit=%+v err=%v", source.uploadCommit, err)
	}

	download, err := OpenFileDownload(context.Background(), source, connectionID, "dir/file.txt")
	if err != nil || download.ID != downloadID {
		t.Fatalf("download=%+v err=%v", download, err)
	}
	read, err := ReadFileDownload(context.Background(), source, connectionID, downloadID, 8)
	if err != nil || string(read.Data) != "abc" || !read.Done || source.downloadRead.MaxBytes != 8 {
		t.Fatalf("read=%+v req=%+v err=%v", read, source.downloadRead, err)
	}
	if err := CancelFileTransfer(context.Background(), source, connectionID, downloadID); err != nil || source.cancelReq.OperationID != downloadID {
		t.Fatalf("cancel=%+v err=%v", source.cancelReq, err)
	}
}

func TestDesktopFileTransferRejectsMalformedInputsAndCoreIdentity(t *testing.T) {
	const connectionID = "conn_AAAAAAAAAAAAAAAAAAAAAAAA"
	const operationID = "file_AAAAAAAAAAAAAAAAAAAAAAAA"
	source := &fakeFileTransferSource{
		uploadOp: v1.FileTransferOperation{ID: operationID, ConnectionID: "conn_other", Direction: v1.FileTransferDirectionUpload},
	}

	if _, err := OpenFileUpload(context.Background(), source, connectionID, "safe.txt", nil, ""); !errors.Is(err, ErrInvalidFileTransferBridgeRequest) {
		t.Fatalf("mismatched operation error=%v", err)
	}
	for _, path := range []string{"", "bad\x00path"} {
		if _, err := OpenFileDownload(context.Background(), source, connectionID, path); !errors.Is(err, ErrInvalidFileTransferBridgeRequest) {
			t.Fatalf("path %q error=%v", path, err)
		}
	}
	if err := WriteFileUpload(context.Background(), source, connectionID, operationID, nil); !errors.Is(err, ErrInvalidFileTransferBridgeRequest) {
		t.Fatalf("empty write error=%v", err)
	}
	if _, err := ReadFileDownload(context.Background(), source, connectionID, operationID, v1.MaxFileTransferChunkBytes+1); !errors.Is(err, ErrInvalidFileTransferBridgeRequest) {
		t.Fatalf("oversized read error=%v", err)
	}
}
