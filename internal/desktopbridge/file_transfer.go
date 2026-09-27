package desktopbridge

import (
	"context"
	"errors"
	"fmt"
	"strings"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

const MaxDesktopRemotePathBytes = 4096

var ErrInvalidFileTransferBridgeRequest = errors.New("desktop file transfer bridge: invalid request")

type FileTransferSource interface {
	v1.FileTransferService
}

type FileTransferStatusSummary struct {
	Available bool `json:"available"`
}

type FileTransferOperationSummary struct {
	ID           string                   `json:"id"`
	ConnectionID string                   `json:"connection_id"`
	Direction    v1.FileTransferDirection `json:"direction"`
}

type FileDownloadReadSummary struct {
	Data []byte `json:"data,omitempty"`
	Done bool   `json:"done"`
}

func GetFileTransferStatus(ctx context.Context, source FileTransferSource, connectionID string) (FileTransferStatusSummary, error) {
	if err := validateFileTransferConnectionID(connectionID); err != nil {
		return FileTransferStatusSummary{}, err
	}
	status, err := source.GetFileTransferStatus(ctx, v1.FileTransferStatusRequest{ConnectionID: connectionID})
	if err != nil {
		return FileTransferStatusSummary{}, err
	}
	return FileTransferStatusSummary{Available: status.Available}, nil
}

func OpenFileUpload(ctx context.Context, source FileTransferSource, connectionID, remotePath string, expectedSize *uint64, sha256 string) (FileTransferOperationSummary, error) {
	if err := validateFileTransferConnectionID(connectionID); err != nil {
		return FileTransferOperationSummary{}, err
	}
	if err := validateRemotePath(remotePath); err != nil {
		return FileTransferOperationSummary{}, err
	}
	sha256 = strings.TrimSpace(sha256)
	if sha256 != "" && len(sha256) != 64 {
		return FileTransferOperationSummary{}, fmt.Errorf("%w: invalid SHA-256 length", ErrInvalidFileTransferBridgeRequest)
	}
	operation, err := source.OpenFileUpload(ctx, v1.FileUploadOpenRequest{
		ConnectionID: connectionID,
		Path:         remotePath,
		ExpectedSize: cloneUint64(expectedSize),
		SHA256:       sha256,
	})
	if err != nil {
		return FileTransferOperationSummary{}, err
	}
	return sanitizeFileOperation(operation, connectionID, v1.FileTransferDirectionUpload)
}

func WriteFileUpload(ctx context.Context, source FileTransferSource, connectionID, operationID string, data []byte) error {
	if err := validateFileTransferIDs(connectionID, operationID); err != nil {
		return err
	}
	if len(data) == 0 || len(data) > v1.MaxFileTransferChunkBytes {
		return fmt.Errorf("%w: upload write must contain 1..%d bytes", ErrInvalidFileTransferBridgeRequest, v1.MaxFileTransferChunkBytes)
	}
	return source.WriteFileUpload(ctx, v1.FileUploadWriteRequest{
		ConnectionID: connectionID,
		OperationID:  operationID,
		Data:         data,
	})
}

func CommitFileUpload(ctx context.Context, source FileTransferSource, connectionID, operationID string) error {
	if err := validateFileTransferIDs(connectionID, operationID); err != nil {
		return err
	}
	return source.CommitFileUpload(ctx, v1.FileUploadCommitRequest{ConnectionID: connectionID, OperationID: operationID})
}

func OpenFileDownload(ctx context.Context, source FileTransferSource, connectionID, remotePath string) (FileTransferOperationSummary, error) {
	if err := validateFileTransferConnectionID(connectionID); err != nil {
		return FileTransferOperationSummary{}, err
	}
	if err := validateRemotePath(remotePath); err != nil {
		return FileTransferOperationSummary{}, err
	}
	operation, err := source.OpenFileDownload(ctx, v1.FileDownloadOpenRequest{ConnectionID: connectionID, Path: remotePath})
	if err != nil {
		return FileTransferOperationSummary{}, err
	}
	return sanitizeFileOperation(operation, connectionID, v1.FileTransferDirectionDownload)
}

func ReadFileDownload(ctx context.Context, source FileTransferSource, connectionID, operationID string, maxBytes int) (FileDownloadReadSummary, error) {
	if err := validateFileTransferIDs(connectionID, operationID); err != nil {
		return FileDownloadReadSummary{}, err
	}
	if maxBytes < 1 || maxBytes > v1.MaxFileTransferChunkBytes {
		return FileDownloadReadSummary{}, fmt.Errorf("%w: invalid download read bound", ErrInvalidFileTransferBridgeRequest)
	}
	result, err := source.ReadFileDownload(ctx, v1.FileDownloadReadRequest{
		ConnectionID: connectionID,
		OperationID:  operationID,
		MaxBytes:     maxBytes,
	})
	if err != nil {
		return FileDownloadReadSummary{}, err
	}
	if len(result.Data) > maxBytes || len(result.Data) > v1.MaxFileTransferChunkBytes {
		return FileDownloadReadSummary{}, fmt.Errorf("%w: oversized download output", ErrInvalidFileTransferBridgeRequest)
	}
	return FileDownloadReadSummary{Data: result.Data, Done: result.Done}, nil
}

func CancelFileTransfer(ctx context.Context, source FileTransferSource, connectionID, operationID string) error {
	if err := validateFileTransferIDs(connectionID, operationID); err != nil {
		return err
	}
	return source.CancelFileTransfer(ctx, v1.FileTransferCancelRequest{ConnectionID: connectionID, OperationID: operationID})
}

func sanitizeFileOperation(operation v1.FileTransferOperation, connectionID string, direction v1.FileTransferDirection) (FileTransferOperationSummary, error) {
	if operation.ConnectionID != connectionID || operation.Direction != direction {
		return FileTransferOperationSummary{}, fmt.Errorf("%w: mismatched file operation from Local Core", ErrInvalidFileTransferBridgeRequest)
	}
	if err := validatePublicID(operation.ID); err != nil {
		return FileTransferOperationSummary{}, fmt.Errorf("%w: invalid file operation id from Local Core", ErrInvalidFileTransferBridgeRequest)
	}
	return FileTransferOperationSummary{
		ID:           operation.ID,
		ConnectionID: operation.ConnectionID,
		Direction:    operation.Direction,
	}, nil
}

func validateFileTransferConnectionID(connectionID string) error {
	if err := validatePublicID(connectionID); err != nil {
		return fmt.Errorf("%w: invalid connection id", ErrInvalidFileTransferBridgeRequest)
	}
	return nil
}

func validateFileTransferIDs(connectionID, operationID string) error {
	if err := validateFileTransferConnectionID(connectionID); err != nil {
		return err
	}
	if err := validatePublicID(operationID); err != nil {
		return fmt.Errorf("%w: invalid operation id", ErrInvalidFileTransferBridgeRequest)
	}
	return nil
}

func validateRemotePath(path string) error {
	if len(path) == 0 || len(path) > MaxDesktopRemotePathBytes {
		return fmt.Errorf("%w: invalid remote path length", ErrInvalidFileTransferBridgeRequest)
	}
	for i := 0; i < len(path); i++ {
		if path[i] < 0x20 || path[i] == 0x7f {
			return fmt.Errorf("%w: invalid remote path", ErrInvalidFileTransferBridgeRequest)
		}
	}
	return nil
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
