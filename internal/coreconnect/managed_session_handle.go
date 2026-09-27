package coreconnect

import (
	"context"

	"wedecent.com/wedecent/internal/coreapi"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/session"
)

// managedSessionHandle keeps session implementation types behind the Core
// connection boundary while preserving the existing terminal interfaces.
type managedSessionHandle struct {
	*session.ManagedMultiplexSession
}

var _ coreapi.FileTransferConnectionHandle = (*managedSessionHandle)(nil)
var _ coreapi.MultiplexTerminalConnectionHandle = (*managedSessionHandle)(nil)

func (h *managedSessionHandle) OpenFileUpload(ctx context.Context, metadata protocol.FileUploadOpen) (coreapi.FileUploadHandle, error) {
	return h.ManagedMultiplexSession.OpenFileUpload(ctx, metadata)
}

func (h *managedSessionHandle) OpenFileDownload(ctx context.Context, metadata protocol.FileDownloadOpen) (coreapi.FileDownloadHandle, error) {
	return h.ManagedMultiplexSession.OpenFileDownload(ctx, metadata)
}
