package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"wedecent.com/wedecent/internal/session"
)

func (cfg serveConfig) fileTransferConfigured() bool {
	return strings.TrimSpace(cfg.FileTransferRoot) != "" ||
		cfg.FileTransferAllowUpload ||
		cfg.FileTransferAllowDownload ||
		cfg.FileTransferMaxBytes != 0
}

func (cfg serveConfig) validateFileTransfer() error {
	if !cfg.fileTransferConfigured() {
		return nil
	}
	root := strings.TrimSpace(cfg.FileTransferRoot)
	if root == "" {
		return errors.New("--file-root is required when file transfer is configured")
	}
	if !filepath.IsAbs(root) {
		return errors.New("--file-root must be an absolute path")
	}
	if !cfg.FileTransferAllowUpload && !cfg.FileTransferAllowDownload {
		return errors.New("file transfer requires --file-upload and/or --file-download")
	}
	if cfg.FileTransferMaxBytes == 0 || cfg.FileTransferMaxBytes > session.MaxFileTransferStoreBytes {
		return fmt.Errorf("--file-max-bytes must be between 1 and %d", session.MaxFileTransferStoreBytes)
	}
	return nil
}

func openAgentFileTransferRuntime(cfg serveConfig) (*session.FileTransferRuntime, error) {
	if !cfg.fileTransferConfigured() {
		return nil, nil
	}
	if err := cfg.validateFileTransfer(); err != nil {
		return nil, err
	}
	store, err := session.OpenFileTransferStore(strings.TrimSpace(cfg.FileTransferRoot), cfg.FileTransferMaxBytes)
	if err != nil {
		return nil, fmt.Errorf("open file transfer root: %w", err)
	}
	return &session.FileTransferRuntime{
		Store: store,
		Authorizer: session.StaticFileTransferAuthorizer{
			AllowUpload:   cfg.FileTransferAllowUpload,
			AllowDownload: cfg.FileTransferAllowDownload,
		},
	}, nil
}
