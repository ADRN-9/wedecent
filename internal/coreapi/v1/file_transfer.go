package v1

import "context"

const (
	MaxFileTransferChunkBytes = 32 << 10

	MethodFileTransferStatus = "file_transfer.status"
	MethodFileUploadOpen     = "file_upload.open"
	MethodFileUploadWrite    = "file_upload.write"
	MethodFileUploadCommit   = "file_upload.commit"
	MethodFileDownloadOpen   = "file_download.open"
	MethodFileDownloadRead   = "file_download.read"
	MethodFileTransferCancel = "file_transfer.cancel"
)

type FileTransferDirection string

const (
	FileTransferDirectionUpload   FileTransferDirection = "upload"
	FileTransferDirectionDownload FileTransferDirection = "download"
)

// FileTransferOperation identifies a Core-owned logical file operation. ID is
// local to Core and is intentionally unrelated to the wire-level typed stream
// ID used on the authenticated parent session.
type FileTransferOperation struct {
	ID           string                `json:"id"`
	ConnectionID string                `json:"connection_id"`
	Direction    FileTransferDirection `json:"direction"`
}

type FileTransferStatusRequest struct {
	ConnectionID string `json:"connection_id"`
}

type FileTransferStatus struct {
	Available bool `json:"available"`
}

type FileUploadOpenRequest struct {
	ConnectionID string  `json:"connection_id"`
	Path         string  `json:"path"`
	ExpectedSize *uint64 `json:"expected_size,omitempty"`
	SHA256       string  `json:"sha256,omitempty"`
}

type FileUploadWriteRequest struct {
	ConnectionID string `json:"connection_id"`
	OperationID  string `json:"operation_id"`
	Data         []byte `json:"data"`
}

type FileUploadCommitRequest struct {
	ConnectionID string `json:"connection_id"`
	OperationID  string `json:"operation_id"`
}

type FileDownloadOpenRequest struct {
	ConnectionID string `json:"connection_id"`
	Path         string `json:"path"`
}

type FileDownloadReadRequest struct {
	ConnectionID string `json:"connection_id"`
	OperationID  string `json:"operation_id"`
	MaxBytes     int    `json:"max_bytes,omitempty"`
}

type FileDownloadReadResult struct {
	Data []byte `json:"data,omitempty"`
	Done bool   `json:"done"`
}

type FileTransferCancelRequest struct {
	ConnectionID string `json:"connection_id"`
	OperationID  string `json:"operation_id"`
}

type FileTransferService interface {
	GetFileTransferStatus(context.Context, FileTransferStatusRequest) (FileTransferStatus, error)
	OpenFileUpload(context.Context, FileUploadOpenRequest) (FileTransferOperation, error)
	WriteFileUpload(context.Context, FileUploadWriteRequest) error
	CommitFileUpload(context.Context, FileUploadCommitRequest) error
	OpenFileDownload(context.Context, FileDownloadOpenRequest) (FileTransferOperation, error)
	ReadFileDownload(context.Context, FileDownloadReadRequest) (FileDownloadReadResult, error)
	CancelFileTransfer(context.Context, FileTransferCancelRequest) error
}
