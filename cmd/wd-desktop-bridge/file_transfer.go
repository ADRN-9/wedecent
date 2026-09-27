package main

import (
	"bytes"
	"context"
	"errors"

	"wedecent.com/wedecent/internal/desktopbridge"
)

type fileConnectionRequest struct {
	ConnectionID string `json:"connection_id"`
}

type fileUploadOpenRequest struct {
	ConnectionID string  `json:"connection_id"`
	Path         string  `json:"path"`
	ExpectedSize *uint64 `json:"expected_size,omitempty"`
	SHA256       string  `json:"sha256,omitempty"`
}

type fileOperationRequest struct {
	ConnectionID string `json:"connection_id"`
	OperationID  string `json:"operation_id"`
}

type fileUploadWriteRequest struct {
	ConnectionID string `json:"connection_id"`
	OperationID  string `json:"operation_id"`
	Data         []byte `json:"data"`
}

type fileDownloadOpenRequest struct {
	ConnectionID string `json:"connection_id"`
	Path         string `json:"path"`
}

type fileDownloadReadRequest struct {
	ConnectionID string `json:"connection_id"`
	OperationID  string `json:"operation_id"`
	MaxBytes     int    `json:"max_bytes"`
}

func handleFileTransferServeRequest(ctx context.Context, op string, raw []byte, source coreSource) (any, bool, error) {
	files, ok := source.(desktopbridge.FileTransferSource)
	if !ok {
		switch op {
		case "file-status", "file-upload-open", "file-upload-write", "file-upload-commit", "file-download-open", "file-download-read", "file-cancel":
			return nil, true, errors.New("file transfer is unavailable")
		default:
			return nil, false, nil
		}
	}

	switch op {
	case "file-status":
		var req fileConnectionRequest
		if err := decodeRequest(bytes.NewReader(raw), &req); err != nil {
			return nil, true, err
		}
		result, err := desktopbridge.GetFileTransferStatus(ctx, files, req.ConnectionID)
		return result, true, err
	case "file-upload-open":
		var req fileUploadOpenRequest
		if err := decodeRequest(bytes.NewReader(raw), &req); err != nil {
			return nil, true, err
		}
		result, err := desktopbridge.OpenFileUpload(ctx, files, req.ConnectionID, req.Path, req.ExpectedSize, req.SHA256)
		return result, true, err
	case "file-upload-write":
		var req fileUploadWriteRequest
		if err := decodeRequest(bytes.NewReader(raw), &req); err != nil {
			return nil, true, err
		}
		err := desktopbridge.WriteFileUpload(ctx, files, req.ConnectionID, req.OperationID, req.Data)
		wipeBytes(req.Data)
		if err != nil {
			return nil, true, err
		}
		return okResponse{OK: true}, true, nil
	case "file-upload-commit":
		var req fileOperationRequest
		if err := decodeRequest(bytes.NewReader(raw), &req); err != nil {
			return nil, true, err
		}
		if err := desktopbridge.CommitFileUpload(ctx, files, req.ConnectionID, req.OperationID); err != nil {
			return nil, true, err
		}
		return okResponse{OK: true}, true, nil
	case "file-download-open":
		var req fileDownloadOpenRequest
		if err := decodeRequest(bytes.NewReader(raw), &req); err != nil {
			return nil, true, err
		}
		result, err := desktopbridge.OpenFileDownload(ctx, files, req.ConnectionID, req.Path)
		return result, true, err
	case "file-download-read":
		var req fileDownloadReadRequest
		if err := decodeRequest(bytes.NewReader(raw), &req); err != nil {
			return nil, true, err
		}
		result, err := desktopbridge.ReadFileDownload(ctx, files, req.ConnectionID, req.OperationID, req.MaxBytes)
		return result, true, err
	case "file-cancel":
		var req fileOperationRequest
		if err := decodeRequest(bytes.NewReader(raw), &req); err != nil {
			return nil, true, err
		}
		if err := desktopbridge.CancelFileTransfer(ctx, files, req.ConnectionID, req.OperationID); err != nil {
			return nil, true, err
		}
		return okResponse{OK: true}, true, nil
	default:
		return nil, false, nil
	}
}

func wipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
