package client

import (
	"context"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

var _ v1.FileTransferService = (*Client)(nil)

func (c *Client) GetFileTransferStatus(ctx context.Context, req v1.FileTransferStatusRequest) (v1.FileTransferStatus, error) {
	var out v1.FileTransferStatus
	err := c.call(ctx, v1.MethodFileTransferStatus, req, &out)
	return out, err
}

func (c *Client) OpenFileUpload(ctx context.Context, req v1.FileUploadOpenRequest) (v1.FileTransferOperation, error) {
	var out v1.FileTransferOperation
	err := c.call(ctx, v1.MethodFileUploadOpen, req, &out)
	return out, err
}

func (c *Client) WriteFileUpload(ctx context.Context, req v1.FileUploadWriteRequest) error {
	return c.call(ctx, v1.MethodFileUploadWrite, req, nil)
}

func (c *Client) CommitFileUpload(ctx context.Context, req v1.FileUploadCommitRequest) error {
	return c.call(ctx, v1.MethodFileUploadCommit, req, nil)
}

func (c *Client) OpenFileDownload(ctx context.Context, req v1.FileDownloadOpenRequest) (v1.FileTransferOperation, error) {
	var out v1.FileTransferOperation
	err := c.call(ctx, v1.MethodFileDownloadOpen, req, &out)
	return out, err
}

func (c *Client) ReadFileDownload(ctx context.Context, req v1.FileDownloadReadRequest) (v1.FileDownloadReadResult, error) {
	var out v1.FileDownloadReadResult
	err := c.call(ctx, v1.MethodFileDownloadRead, req, &out)
	return out, err
}

func (c *Client) CancelFileTransfer(ctx context.Context, req v1.FileTransferCancelRequest) error {
	return c.call(ctx, v1.MethodFileTransferCancel, req, nil)
}
