package coreapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/protocol"
)

var (
	ErrInvalidFileTransferRequest = errors.New("invalid file transfer request")
	ErrFileTransferUnavailable    = errors.New("file transfer is unavailable")
	ErrFileTransferLimit          = errors.New("file transfer operation limit reached")
	ErrFileTransferNotFound       = errors.New("file transfer operation not found")
	ErrFileTransferOperation      = errors.New("file transfer operation failed")
)

const (
	defaultMaxCoreFileTransfers = 16
	fileTransferIDPrefix        = "file_"
	fileTransferIDRawBytes      = 18
)

type FileUploadHandle interface {
	Write(context.Context, []byte) error
	Commit(context.Context) error
	Cancel(context.Context) error
	Done() <-chan struct{}
}

type FileDownloadHandle interface {
	Read(context.Context, int) ([]byte, bool, error)
	Cancel(context.Context) error
	Done() <-chan struct{}
}

type FileTransferConnectionHandle interface {
	ObservableConnectionHandle
	FileTransferAvailable() bool
	OpenFileUpload(context.Context, protocol.FileUploadOpen) (FileUploadHandle, error)
	OpenFileDownload(context.Context, protocol.FileDownloadOpen) (FileDownloadHandle, error)
}

type FileTransferServiceConfig struct {
	Connections *ConnectionService
	MaxActive   int
	Random      io.Reader
}

type fileTransferEntry struct {
	connectionID string
	token        *struct{}
	direction    v1.FileTransferDirection
	upload       FileUploadHandle
	download     FileDownloadHandle
}

type FileTransferService struct {
	connections *ConnectionService
	max         int
	random      io.Reader

	mu       sync.Mutex
	ops      map[string]fileTransferEntry
	reserved map[string]struct{}
}

var _ v1.FileTransferService = (*FileTransferService)(nil)

func NewFileTransferService(cfg FileTransferServiceConfig) (*FileTransferService, error) {
	if cfg.Connections == nil {
		return nil, errors.New("file transfer service: connection service is required")
	}
	maxActive := cfg.MaxActive
	if maxActive == 0 {
		maxActive = defaultMaxCoreFileTransfers
	}
	if maxActive < 1 || maxActive > 256 {
		return nil, errors.New("file transfer service: operation limit must be between 1 and 256")
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	return &FileTransferService{
		connections: cfg.Connections,
		max:         maxActive,
		random:      random,
		ops:         make(map[string]fileTransferEntry),
		reserved:    make(map[string]struct{}),
	}, nil
}

func (s *FileTransferService) GetFileTransferStatus(ctx context.Context, req v1.FileTransferStatusRequest) (v1.FileTransferStatus, error) {
	if err := ctx.Err(); err != nil {
		return v1.FileTransferStatus{}, err
	}
	parent, _, _, err := s.activeFileParent(req.ConnectionID)
	if err != nil {
		return v1.FileTransferStatus{}, err
	}
	return v1.FileTransferStatus{Available: parent.FileTransferAvailable()}, nil
}

func (s *FileTransferService) OpenFileUpload(ctx context.Context, req v1.FileUploadOpenRequest) (v1.FileTransferOperation, error) {
	if err := ctx.Err(); err != nil {
		return v1.FileTransferOperation{}, err
	}
	metadata := protocol.FileUploadOpen{
		Path:         req.Path,
		ExpectedSize: cloneUint64(req.ExpectedSize),
		SHA256:       strings.TrimSpace(req.SHA256),
		Existing:     protocol.FileExistingFail,
	}
	if !validConnectionID(req.ConnectionID) || protocol.ValidateFileUploadOpen(metadata) != nil {
		return v1.FileTransferOperation{}, ErrInvalidFileTransferRequest
	}
	parent, token, done, err := s.activeFileParent(req.ConnectionID)
	if err != nil {
		return v1.FileTransferOperation{}, err
	}
	if !parent.FileTransferAvailable() {
		return v1.FileTransferOperation{}, ErrFileTransferUnavailable
	}
	operationID, err := s.reserveOperationID()
	if err != nil {
		return v1.FileTransferOperation{}, err
	}
	reserved := true
	defer func() {
		if reserved {
			s.releaseOperationID(operationID)
		}
	}()

	upload, err := parent.OpenFileUpload(ctx, metadata)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return v1.FileTransferOperation{}, ctxErr
		}
		return v1.FileTransferOperation{}, fmt.Errorf("%w: open upload", ErrFileTransferOperation)
	}
	if upload == nil || upload.Done() == nil {
		if upload != nil {
			_ = upload.Cancel(context.Background())
		}
		return v1.FileTransferOperation{}, fmt.Errorf("%w: invalid upload handle", ErrFileTransferOperation)
	}
	if !s.connectionTokenCurrent(req.ConnectionID, token) {
		_ = upload.Cancel(context.Background())
		return v1.FileTransferOperation{}, ErrConnectionNotFound
	}

	entry := fileTransferEntry{connectionID: req.ConnectionID, token: token, direction: v1.FileTransferDirectionUpload, upload: upload}
	if err := s.activateOperation(operationID, entry); err != nil {
		_ = upload.Cancel(context.Background())
		return v1.FileTransferOperation{}, err
	}
	reserved = false
	go s.watchOperation(operationID, token, upload.Done(), done)
	return v1.FileTransferOperation{ID: operationID, ConnectionID: req.ConnectionID, Direction: v1.FileTransferDirectionUpload}, nil
}

func (s *FileTransferService) WriteFileUpload(ctx context.Context, req v1.FileUploadWriteRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(req.Data) < 1 || len(req.Data) > v1.MaxFileTransferChunkBytes {
		return ErrInvalidFileTransferRequest
	}
	entry, err := s.operation(req.ConnectionID, req.OperationID, v1.FileTransferDirectionUpload)
	if err != nil {
		return err
	}
	if entry.upload == nil {
		return ErrFileTransferNotFound
	}
	data := append([]byte(nil), req.Data...)
	if err := entry.upload.Write(ctx, data); err != nil {
		wipeBytes(data)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: write upload", ErrFileTransferOperation)
	}
	wipeBytes(data)
	return nil
}

func (s *FileTransferService) CommitFileUpload(ctx context.Context, req v1.FileUploadCommitRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entry, err := s.takeOperation(req.ConnectionID, req.OperationID, v1.FileTransferDirectionUpload)
	if err != nil {
		return err
	}
	if entry.upload == nil {
		return ErrFileTransferNotFound
	}
	// Commit is intentionally removed from Core ownership before the mutating
	// call. If the result is ambiguous, callers cannot replay the commit through
	// the same operation ID.
	if err := entry.upload.Commit(ctx); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: commit upload", ErrFileTransferOperation)
	}
	return nil
}

func (s *FileTransferService) OpenFileDownload(ctx context.Context, req v1.FileDownloadOpenRequest) (v1.FileTransferOperation, error) {
	if err := ctx.Err(); err != nil {
		return v1.FileTransferOperation{}, err
	}
	metadata := protocol.FileDownloadOpen{Path: req.Path}
	if !validConnectionID(req.ConnectionID) || protocol.ValidateFileDownloadOpen(metadata) != nil {
		return v1.FileTransferOperation{}, ErrInvalidFileTransferRequest
	}
	parent, token, done, err := s.activeFileParent(req.ConnectionID)
	if err != nil {
		return v1.FileTransferOperation{}, err
	}
	if !parent.FileTransferAvailable() {
		return v1.FileTransferOperation{}, ErrFileTransferUnavailable
	}
	operationID, err := s.reserveOperationID()
	if err != nil {
		return v1.FileTransferOperation{}, err
	}
	reserved := true
	defer func() {
		if reserved {
			s.releaseOperationID(operationID)
		}
	}()

	download, err := parent.OpenFileDownload(ctx, metadata)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return v1.FileTransferOperation{}, ctxErr
		}
		return v1.FileTransferOperation{}, fmt.Errorf("%w: open download", ErrFileTransferOperation)
	}
	if download == nil || download.Done() == nil {
		if download != nil {
			_ = download.Cancel(context.Background())
		}
		return v1.FileTransferOperation{}, fmt.Errorf("%w: invalid download handle", ErrFileTransferOperation)
	}
	if !s.connectionTokenCurrent(req.ConnectionID, token) {
		_ = download.Cancel(context.Background())
		return v1.FileTransferOperation{}, ErrConnectionNotFound
	}

	entry := fileTransferEntry{connectionID: req.ConnectionID, token: token, direction: v1.FileTransferDirectionDownload, download: download}
	if err := s.activateOperation(operationID, entry); err != nil {
		_ = download.Cancel(context.Background())
		return v1.FileTransferOperation{}, err
	}
	reserved = false
	go s.watchOperation(operationID, token, download.Done(), done)
	return v1.FileTransferOperation{ID: operationID, ConnectionID: req.ConnectionID, Direction: v1.FileTransferDirectionDownload}, nil
}

func (s *FileTransferService) ReadFileDownload(ctx context.Context, req v1.FileDownloadReadRequest) (v1.FileDownloadReadResult, error) {
	if err := ctx.Err(); err != nil {
		return v1.FileDownloadReadResult{}, err
	}
	maxBytes := req.MaxBytes
	if maxBytes == 0 {
		maxBytes = v1.MaxFileTransferChunkBytes
	}
	if maxBytes < 1 || maxBytes > v1.MaxFileTransferChunkBytes {
		return v1.FileDownloadReadResult{}, ErrInvalidFileTransferRequest
	}
	entry, err := s.operation(req.ConnectionID, req.OperationID, v1.FileTransferDirectionDownload)
	if err != nil {
		return v1.FileDownloadReadResult{}, err
	}
	if entry.download == nil {
		return v1.FileDownloadReadResult{}, ErrFileTransferNotFound
	}
	data, done, err := entry.download.Read(ctx, maxBytes)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return v1.FileDownloadReadResult{}, ctxErr
		}
		return v1.FileDownloadReadResult{}, fmt.Errorf("%w: read download", ErrFileTransferOperation)
	}
	if len(data) > maxBytes || len(data) > v1.MaxFileTransferChunkBytes {
		wipeBytes(data)
		return v1.FileDownloadReadResult{}, fmt.Errorf("%w: backend exceeded download bound", ErrFileTransferOperation)
	}
	if done {
		s.removeOperation(req.OperationID, entry.token)
	}
	return v1.FileDownloadReadResult{Data: data, Done: done}, nil
}

func (s *FileTransferService) CancelFileTransfer(ctx context.Context, req v1.FileTransferCancelRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entry, err := s.takeOperationAnyDirection(req.ConnectionID, req.OperationID)
	if err != nil {
		return err
	}
	var cancelErr error
	switch entry.direction {
	case v1.FileTransferDirectionUpload:
		cancelErr = entry.upload.Cancel(ctx)
	case v1.FileTransferDirectionDownload:
		cancelErr = entry.download.Cancel(ctx)
	default:
		return ErrFileTransferNotFound
	}
	if cancelErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: cancel transfer", ErrFileTransferOperation)
	}
	return nil
}

func (s *FileTransferService) activeFileParent(connectionID string) (FileTransferConnectionHandle, *struct{}, <-chan struct{}, error) {
	if !validConnectionID(connectionID) {
		return nil, nil, nil, ErrInvalidFileTransferRequest
	}
	s.connections.mu.Lock()
	defer s.connections.mu.Unlock()
	if s.connections.closed {
		return nil, nil, nil, ErrConnectionServiceClosed
	}
	active, ok := s.connections.active[connectionID]
	if !ok || active.closing {
		return nil, nil, nil, ErrConnectionNotFound
	}
	parent, ok := active.handle.(FileTransferConnectionHandle)
	if !ok {
		return nil, nil, nil, ErrFileTransferUnavailable
	}
	done := parent.Done()
	if done == nil {
		return nil, nil, nil, ErrFileTransferUnavailable
	}
	return parent, active.token, done, nil
}

func (s *FileTransferService) connectionTokenCurrent(connectionID string, token *struct{}) bool {
	s.connections.mu.Lock()
	defer s.connections.mu.Unlock()
	active, ok := s.connections.active[connectionID]
	return ok && !active.closing && active.token == token
}

func (s *FileTransferService) reserveOperationID() (string, error) {
	for attempt := 0; attempt < maxConnectionIDAttempts; attempt++ {
		s.mu.Lock()
		if len(s.ops)+len(s.reserved) >= s.max {
			s.mu.Unlock()
			return "", ErrFileTransferLimit
		}
		s.mu.Unlock()
		operationID, err := s.newOperationID()
		if err != nil {
			return "", fmt.Errorf("%w: generate operation ID", ErrFileTransferOperation)
		}
		s.mu.Lock()
		_, active := s.ops[operationID]
		_, reserved := s.reserved[operationID]
		if !active && !reserved {
			s.reserved[operationID] = struct{}{}
			s.mu.Unlock()
			return operationID, nil
		}
		s.mu.Unlock()
	}
	return "", fmt.Errorf("%w: operation ID collision limit reached", ErrFileTransferOperation)
}

func (s *FileTransferService) activateOperation(operationID string, entry fileTransferEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.reserved[operationID]; !ok {
		return fmt.Errorf("%w: operation reservation lost", ErrFileTransferOperation)
	}
	delete(s.reserved, operationID)
	s.ops[operationID] = entry
	return nil
}

func (s *FileTransferService) releaseOperationID(operationID string) {
	s.mu.Lock()
	delete(s.reserved, operationID)
	s.mu.Unlock()
}

func (s *FileTransferService) operation(connectionID, operationID string, direction v1.FileTransferDirection) (fileTransferEntry, error) {
	if !validConnectionID(connectionID) || !validFileTransferID(operationID) {
		return fileTransferEntry{}, ErrInvalidFileTransferRequest
	}
	s.mu.Lock()
	entry, ok := s.ops[operationID]
	s.mu.Unlock()
	if !ok || entry.connectionID != connectionID || entry.direction != direction || !s.connectionTokenCurrent(connectionID, entry.token) {
		return fileTransferEntry{}, ErrFileTransferNotFound
	}
	return entry, nil
}

func (s *FileTransferService) takeOperation(connectionID, operationID string, direction v1.FileTransferDirection) (fileTransferEntry, error) {
	entry, err := s.operation(connectionID, operationID, direction)
	if err != nil {
		return fileTransferEntry{}, err
	}
	s.removeOperation(operationID, entry.token)
	return entry, nil
}

func (s *FileTransferService) takeOperationAnyDirection(connectionID, operationID string) (fileTransferEntry, error) {
	if !validConnectionID(connectionID) || !validFileTransferID(operationID) {
		return fileTransferEntry{}, ErrInvalidFileTransferRequest
	}
	s.mu.Lock()
	entry, ok := s.ops[operationID]
	s.mu.Unlock()
	if !ok || entry.connectionID != connectionID || !s.connectionTokenCurrent(connectionID, entry.token) {
		return fileTransferEntry{}, ErrFileTransferNotFound
	}
	s.removeOperation(operationID, entry.token)
	return entry, nil
}

func (s *FileTransferService) removeOperation(operationID string, token *struct{}) {
	s.mu.Lock()
	if current, ok := s.ops[operationID]; ok && current.token == token {
		delete(s.ops, operationID)
	}
	s.mu.Unlock()
}

func (s *FileTransferService) watchOperation(operationID string, token *struct{}, childDone, parentDone <-chan struct{}) {
	select {
	case <-childDone:
	case <-parentDone:
	}
	s.removeOperation(operationID, token)
}

func (s *FileTransferService) newOperationID() (string, error) {
	var raw [fileTransferIDRawBytes]byte
	if _, err := io.ReadFull(s.random, raw[:]); err != nil {
		return "", err
	}
	return fileTransferIDPrefix + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func validFileTransferID(value string) bool {
	if !strings.HasPrefix(value, fileTransferIDPrefix) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, fileTransferIDPrefix))
	return err == nil && len(raw) == fileTransferIDRawBytes
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func wipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
