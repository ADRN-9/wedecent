package session

import (
	"context"
	"errors"
	"strings"

	"wedecent.com/wedecent/internal/protocol"
)

type FileTransferDirection string

const (
	FileTransferUpload   FileTransferDirection = "upload"
	FileTransferDownload FileTransferDirection = "download"
)

// FileTransferAuthorizationRequest identifies one privileged file operation.
// PeerID is the already-authenticated endpoint identity from the parent TLS
// session. Path has already passed the strict protocol-level canonical path
// validation but is still policy input, not authorization evidence.
type FileTransferAuthorizationRequest struct {
	PeerID    string
	Direction FileTransferDirection
	Path      string
}

// FileTransferAuthorizer is deliberately separate from DirectAuthorizer. A
// successful connection/terminal grant never implies file-operation access.
type FileTransferAuthorizer interface {
	AuthorizeFileTransfer(context.Context, FileTransferAuthorizationRequest) error
}

// StaticFileTransferAuthorizer is the minimal operator policy used by future
// standalone agent configuration. It is intentionally direction-specific and
// deny-by-default. Managed/RBAC deployments can provide a different
// FileTransferAuthorizer without weakening the session boundary.
type StaticFileTransferAuthorizer struct {
	AllowUpload   bool
	AllowDownload bool
}

func (a StaticFileTransferAuthorizer) AuthorizeFileTransfer(ctx context.Context, req FileTransferAuthorizationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(req.PeerID) == "" {
		return errors.New("authenticated peer identity is required")
	}
	switch req.Direction {
	case FileTransferUpload:
		if !a.AllowUpload {
			return errors.New("file upload is not authorized")
		}
		if err := protocol.ValidateFileUploadOpen(protocol.FileUploadOpen{Path: req.Path, Existing: protocol.FileExistingFail}); err != nil {
			return err
		}
	case FileTransferDownload:
		if !a.AllowDownload {
			return errors.New("file download is not authorized")
		}
		if err := protocol.ValidateFileDownloadOpen(protocol.FileDownloadOpen{Path: req.Path}); err != nil {
			return err
		}
	default:
		return errors.New("file transfer direction is invalid")
	}
	return nil
}

// FileTransferRuntime groups the filesystem capability with its independent
// operation authorizer. The runtime is ready only when both are present; nil or
// incomplete configuration must never cause file-transfer capability
// negotiation.
type FileTransferRuntime struct {
	Store      *FileTransferStore
	Authorizer FileTransferAuthorizer
}

func (r *FileTransferRuntime) Ready() bool {
	return r != nil && r.Store != nil && r.Authorizer != nil
}

func (r *FileTransferRuntime) Authorize(ctx context.Context, peerID string, direction FileTransferDirection, path string) error {
	if !r.Ready() {
		return errors.New("file transfer is not configured")
	}
	return r.Authorizer.AuthorizeFileTransfer(ctx, FileTransferAuthorizationRequest{
		PeerID:    peerID,
		Direction: direction,
		Path:      path,
	})
}
