package ipc

import (
	"context"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

func (s *Server) handleFileTransfer(ctx context.Context, req Request, response Response) (Response, bool) {
	switch req.Method {
	case v1.MethodFileTransferStatus,
		v1.MethodFileUploadOpen,
		v1.MethodFileUploadWrite,
		v1.MethodFileUploadCommit,
		v1.MethodFileDownloadOpen,
		v1.MethodFileDownloadRead,
		v1.MethodFileTransferCancel:
	default:
		return Response{}, false
	}
	if s.files == nil {
		if req.Method == v1.MethodFileUploadWrite {
			wipe(req.Params)
		}
		return errorResponse(response, ErrorMethodNotFound, "method not found"), true
	}

	var result any
	var err error
	switch req.Method {
	case v1.MethodFileTransferStatus:
		var params v1.FileTransferStatusRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		result, err = s.files.GetFileTransferStatus(ctx, params)
	case v1.MethodFileUploadOpen:
		var params v1.FileUploadOpenRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		result, err = s.files.OpenFileUpload(ctx, params)
	case v1.MethodFileUploadWrite:
		var params v1.FileUploadWriteRequest
		decodeErr := DecodeParams(req.Params, &params)
		wipe(req.Params)
		if decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		err = s.files.WriteFileUpload(ctx, params)
		wipe(params.Data)
	case v1.MethodFileUploadCommit:
		var params v1.FileUploadCommitRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		err = s.files.CommitFileUpload(ctx, params)
	case v1.MethodFileDownloadOpen:
		var params v1.FileDownloadOpenRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		result, err = s.files.OpenFileDownload(ctx, params)
	case v1.MethodFileDownloadRead:
		var params v1.FileDownloadReadRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		result, err = s.files.ReadFileDownload(ctx, params)
	case v1.MethodFileTransferCancel:
		var params v1.FileTransferCancelRequest
		if decodeErr := DecodeParams(req.Params, &params); decodeErr != nil {
			return errorResponse(response, ErrorInvalidParams, "invalid request parameters"), true
		}
		err = s.files.CancelFileTransfer(ctx, params)
	}
	return s.finish(response, result, err), true
}
