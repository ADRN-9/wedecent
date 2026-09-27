package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/protocol"
)

const (
	typedFileReceiveWindow       uint32 = 256 << 10
	maxFileStreamsPerConnection        = 4
	fileAuthorizationTimeout           = 15 * time.Second
)

var errTypedFileStreamRejected = errors.New("typed file stream rejection already sent")

type typedFileFrameWriter func(protocol.Frame) error

type typedFileChild struct {
	kind     protocol.StreamKind
	upload   *FileUpload
	download *FileDownload

	mu         sync.Mutex
	sendCredit typedStreamCredit
	recvCredit typedStreamCredit
	remaining  uint64
	creditCh   chan struct{}
	done       chan struct{}
	closeOnce  sync.Once
}

type typedFileServer struct {
	runtime  *FileTransferRuntime
	peerID   string
	registry *typedParentStreamRegistry
	write    typedFileFrameWriter

	mu      sync.Mutex
	writeMu sync.Mutex
	streams map[uint32]*typedFileChild
	active  int
}

func newTypedFileServer(runtime *FileTransferRuntime, peerID string, registry *typedParentStreamRegistry, write typedFileFrameWriter) *typedFileServer {
	if registry == nil {
		registry = newTypedParentStreamRegistry()
	}
	return &typedFileServer{
		runtime: runtime, peerID: peerID, registry: registry, write: write,
		streams: make(map[uint32]*typedFileChild),
	}
}

func (s *typedFileServer) Handle(ctx context.Context, frame protocol.Frame) error {
	switch frame.Type {
	case protocol.TypeStreamOpen:
		return s.open(ctx, frame)
	case protocol.TypeStreamData:
		return s.data(frame)
	case protocol.TypeStreamWindowUpdate:
		return s.windowUpdate(frame)
	case protocol.TypeStreamClose:
		return s.peerClose(frame)
	case protocol.TypeStreamError:
		return s.peerError(frame)
	case protocol.TypeStreamAccepted, protocol.TypeStreamResize:
		return fmt.Errorf("%w: frame type %d is invalid for file streams", errTypedStreamProtocol, frame.Type)
	default:
		return fmt.Errorf("%w: unexpected file stream frame type %d", errTypedStreamProtocol, frame.Type)
	}
}

func (s *typedFileServer) open(ctx context.Context, frame protocol.Frame) error {
	var envelope protocol.StreamOpen
	if err := protocol.ParseTypedStreamJSON(frame.Payload, &envelope); err != nil {
		return fmt.Errorf("%w: malformed file stream open", errTypedStreamProtocol)
	}
	switch envelope.Kind {
	case protocol.StreamKindFileUpload:
		metadata, err := protocol.ParseFileUploadStreamOpen(frame.StreamID, envelope)
		if err != nil {
			return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
		}
		return s.openUpload(ctx, frame.StreamID, metadata)
	case protocol.StreamKindFileDownload:
		metadata, err := protocol.ParseFileDownloadStreamOpen(frame.StreamID, envelope)
		if err != nil {
			return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
		}
		return s.openDownload(ctx, frame.StreamID, envelope, metadata)
	default:
		return fmt.Errorf("%w: unsupported file stream kind", errTypedStreamProtocol)
	}
}

func (s *typedFileServer) reserve(streamID uint32, kind protocol.StreamKind) error {
	if err := s.registry.reserve(streamID, kind); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	s.mu.Lock()
	if s.active >= maxFileStreamsPerConnection {
		s.mu.Unlock()
		_ = s.registry.close(streamID, kind)
		if err := s.sendStreamError(streamID, "resource_limit", "file stream limit reached"); err != nil {
			return err
		}
		return errTypedFileStreamRejected
	}
	s.active++
	s.mu.Unlock()
	return nil
}

func (s *typedFileServer) releaseReservation(streamID uint32, kind protocol.StreamKind) {
	_ = s.registry.close(streamID, kind)
	s.mu.Lock()
	if s.active > 0 {
		s.active--
	}
	s.mu.Unlock()
}

func (s *typedFileServer) authorize(ctx context.Context, direction FileTransferDirection, path string) error {
	if s.runtime == nil || !s.runtime.Ready() {
		return errors.New("file transfer runtime is unavailable")
	}
	authCtx, cancel := context.WithTimeout(ctx, fileAuthorizationTimeout)
	defer cancel()
	return s.runtime.Authorize(authCtx, s.peerID, direction, path)
}

func (s *typedFileServer) openUpload(ctx context.Context, streamID uint32, metadata protocol.FileUploadOpen) error {
	if err := s.reserve(streamID, protocol.StreamKindFileUpload); err != nil {
		if errors.Is(err, errTypedFileStreamRejected) {
			return nil
		}
		return err
	}
	if err := s.authorize(ctx, FileTransferUpload, metadata.Path); err != nil {
		s.releaseReservation(streamID, protocol.StreamKindFileUpload)
		return s.sendStreamError(streamID, "authorization_denied", "file upload is not authorized")
	}
	upload, err := s.runtime.Store.BeginUpload(metadata)
	if err != nil {
		s.releaseReservation(streamID, protocol.StreamKindFileUpload)
		return s.sendStreamError(streamID, "file_open_failed", "file upload could not start")
	}
	recvCredit, err := newTypedStreamCredit(typedFileReceiveWindow)
	if err != nil {
		_ = upload.Cancel()
		s.releaseReservation(streamID, protocol.StreamKindFileUpload)
		return err
	}
	child := &typedFileChild{kind: protocol.StreamKindFileUpload, upload: upload, recvCredit: recvCredit, creditCh: make(chan struct{}, 1), done: make(chan struct{})}
	if err := s.activate(streamID, child); err != nil {
		_ = upload.Cancel()
		s.releaseReservation(streamID, protocol.StreamKindFileUpload)
		return err
	}
	accepted := protocol.StreamAccepted{InitialWindow: typedFileReceiveWindow}
	payload, _ := protocol.JSON(accepted)
	if err := s.writeFrame(protocol.Frame{Type: protocol.TypeStreamAccepted, StreamID: streamID, Payload: payload}); err != nil {
		s.closeChild(streamID)
		return err
	}
	return nil
}

func (s *typedFileServer) openDownload(ctx context.Context, streamID uint32, envelope protocol.StreamOpen, metadata protocol.FileDownloadOpen) error {
	if err := s.reserve(streamID, protocol.StreamKindFileDownload); err != nil {
		if errors.Is(err, errTypedFileStreamRejected) {
			return nil
		}
		return err
	}
	if err := s.authorize(ctx, FileTransferDownload, metadata.Path); err != nil {
		s.releaseReservation(streamID, protocol.StreamKindFileDownload)
		return s.sendStreamError(streamID, "authorization_denied", "file download is not authorized")
	}
	download, size, err := s.runtime.Store.OpenDownload(metadata)
	if err != nil {
		s.releaseReservation(streamID, protocol.StreamKindFileDownload)
		return s.sendStreamError(streamID, "file_open_failed", "file download could not start")
	}
	sendCredit, err := newTypedStreamCredit(envelope.InitialWindow)
	if err != nil {
		_ = download.Close()
		s.releaseReservation(streamID, protocol.StreamKindFileDownload)
		return err
	}
	child := &typedFileChild{kind: protocol.StreamKindFileDownload, download: download, sendCredit: sendCredit, remaining: size, creditCh: make(chan struct{}, 1), done: make(chan struct{})}
	if err := s.activate(streamID, child); err != nil {
		_ = download.Close()
		s.releaseReservation(streamID, protocol.StreamKindFileDownload)
		return err
	}
	accepted := protocol.StreamAccepted{InitialWindow: 1}
	payload, _ := protocol.JSON(accepted)
	if err := s.writeFrame(protocol.Frame{Type: protocol.TypeStreamAccepted, StreamID: streamID, Payload: payload}); err != nil {
		s.closeChild(streamID)
		return err
	}
	go s.forwardDownload(streamID, child)
	return nil
}

func (s *typedFileServer) activate(streamID uint32, child *typedFileChild) error {
	s.mu.Lock()
	s.streams[streamID] = child
	s.mu.Unlock()
	if err := s.registry.accept(streamID, child.kind); err != nil {
		s.mu.Lock()
		delete(s.streams, streamID)
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *typedFileServer) data(frame protocol.Frame) error {
	if err := protocol.ValidateStreamData(frame.StreamID, frame.Payload); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	child, err := s.openChild(frame.StreamID)
	if err != nil {
		return err
	}
	if child.kind != protocol.StreamKindFileUpload || child.upload == nil {
		return fmt.Errorf("%w: data is only valid for file upload", errTypedStreamProtocol)
	}
	child.mu.Lock()
	if err := child.recvCredit.consume(uint32(len(frame.Payload))); err != nil {
		child.mu.Unlock()
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	child.mu.Unlock()
	n, err := child.upload.Write(frame.Payload)
	if err != nil || n != len(frame.Payload) {
		s.closeChild(frame.StreamID)
		return s.sendStreamError(frame.StreamID, "upload_write_failed", "file upload failed")
	}
	update := protocol.StreamWindowUpdate{Bytes: uint32(n)}
	payload, _ := protocol.JSON(update)
	if err := s.writeFrame(protocol.Frame{Type: protocol.TypeStreamWindowUpdate, StreamID: frame.StreamID, Payload: payload}); err != nil {
		s.closeChild(frame.StreamID)
		return err
	}
	child.mu.Lock()
	err = child.recvCredit.add(uint32(n))
	child.mu.Unlock()
	if err != nil {
		s.closeChild(frame.StreamID)
		return err
	}
	return nil
}

func (s *typedFileServer) windowUpdate(frame protocol.Frame) error {
	var update protocol.StreamWindowUpdate
	if err := protocol.ParseTypedStreamJSON(frame.Payload, &update); err != nil {
		return fmt.Errorf("%w: malformed file window update", errTypedStreamProtocol)
	}
	if err := protocol.ValidateStreamWindowUpdate(frame.StreamID, update); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	child, err := s.openChild(frame.StreamID)
	if err != nil {
		return err
	}
	if child.kind != protocol.StreamKindFileDownload || child.download == nil {
		return fmt.Errorf("%w: window update is only valid for file download", errTypedStreamProtocol)
	}
	child.mu.Lock()
	err = child.sendCredit.add(update.Bytes)
	child.mu.Unlock()
	if err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	select {
	case child.creditCh <- struct{}{}:
	default:
	}
	return nil
}

func (s *typedFileServer) peerClose(frame protocol.Frame) error {
	var closeMessage protocol.StreamClose
	if err := protocol.ParseTypedStreamJSON(frame.Payload, &closeMessage); err != nil {
		return fmt.Errorf("%w: malformed file stream close", errTypedStreamProtocol)
	}
	if err := protocol.ValidateStreamClose(frame.StreamID, closeMessage); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	child, err := s.openChild(frame.StreamID)
	if err != nil {
		return err
	}
	if child.kind == protocol.StreamKindFileUpload {
		if err := child.upload.Commit(); err != nil {
			s.closeChild(frame.StreamID)
			return s.sendStreamError(frame.StreamID, "upload_commit_failed", "file upload validation or commit failed")
		}
	}
	s.closeChild(frame.StreamID)
	return s.sendClose(frame.StreamID, "peer_close")
}

func (s *typedFileServer) peerError(frame protocol.Frame) error {
	var streamError protocol.StreamError
	if err := protocol.ParseTypedStreamJSON(frame.Payload, &streamError); err != nil {
		return fmt.Errorf("%w: malformed file stream error", errTypedStreamProtocol)
	}
	if err := protocol.ValidateStreamError(frame.StreamID, streamError); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	if _, err := s.openChild(frame.StreamID); err != nil {
		return err
	}
	s.closeChild(frame.StreamID)
	return nil
}

func (s *typedFileServer) openChild(streamID uint32) (*typedFileChild, error) {
	s.mu.Lock()
	child := s.streams[streamID]
	s.mu.Unlock()
	if child == nil || !s.registry.isOpen(streamID, child.kind) {
		return nil, fmt.Errorf("%w: file stream %d is not open", errTypedStreamProtocol, streamID)
	}
	return child, nil
}

func (s *typedFileServer) forwardDownload(streamID uint32, child *typedFileChild) {
	buf := make([]byte, protocol.MaxTypedStreamChunk)
	for {
		available := uint32(0)
		remaining := uint64(0)
		for available == 0 {
			child.mu.Lock()
			available = child.sendCredit.available()
			remaining = child.remaining
			child.mu.Unlock()
			if remaining == 0 {
				s.closeChild(streamID)
				_ = s.sendClose(streamID, "download_complete")
				return
			}
			if available == 0 {
				select {
				case <-child.creditCh:
				case <-child.done:
					return
				}
			}
		}
		limit := int(available)
		if uint64(limit) > remaining {
			limit = int(remaining)
		}
		if limit > len(buf) {
			limit = len(buf)
		}
		n, err := child.download.Read(buf[:limit])
		select {
		case <-child.done:
			return
		default:
		}
		if n > 0 {
			child.mu.Lock()
			creditErr := child.sendCredit.consume(uint32(n))
			if uint64(n) <= child.remaining {
				child.remaining -= uint64(n)
			}
			remaining = child.remaining
			child.mu.Unlock()
			if creditErr != nil {
				s.closeChild(streamID)
				return
			}
			payload := append([]byte(nil), buf[:n]...)
			if writeErr := s.writeFrame(protocol.Frame{Type: protocol.TypeStreamData, StreamID: streamID, Payload: payload}); writeErr != nil {
				s.closeChild(streamID)
				return
			}
			select {
			case <-child.done:
				return
			default:
			}
			if remaining == 0 && err == nil {
				s.closeChild(streamID)
				_ = s.sendClose(streamID, "download_complete")
				return
			}
		}
		if errors.Is(err, io.EOF) {
			s.closeChild(streamID)
			_ = s.sendClose(streamID, "download_complete")
			return
		}
		if err != nil {
			s.closeChild(streamID)
			_ = s.sendStreamError(streamID, "download_read_failed", "file download failed")
			return
		}
	}
}

func (s *typedFileServer) closeChild(streamID uint32) {
	s.mu.Lock()
	child := s.streams[streamID]
	if child != nil {
		delete(s.streams, streamID)
		if s.active > 0 {
			s.active--
		}
	}
	s.mu.Unlock()
	if child == nil {
		return
	}
	_ = s.registry.close(streamID, child.kind)
	child.closeOnce.Do(func() {
		close(child.done)
		if child.upload != nil {
			_ = child.upload.Cancel()
		}
		if child.download != nil {
			_ = child.download.Close()
		}
	})
}

func (s *typedFileServer) sendStreamError(streamID uint32, code, message string) error {
	streamError := protocol.StreamError{Code: code, Message: message}
	if err := protocol.ValidateStreamError(streamID, streamError); err != nil {
		return err
	}
	payload, err := protocol.JSON(streamError)
	if err != nil {
		return err
	}
	return s.writeFrame(protocol.Frame{Type: protocol.TypeStreamError, StreamID: streamID, Payload: payload})
}

func (s *typedFileServer) sendClose(streamID uint32, reason string) error {
	closeMessage := protocol.StreamClose{Reason: reason}
	if err := protocol.ValidateStreamClose(streamID, closeMessage); err != nil {
		return err
	}
	payload, err := protocol.JSON(closeMessage)
	if err != nil {
		return err
	}
	return s.writeFrame(protocol.Frame{Type: protocol.TypeStreamClose, StreamID: streamID, Payload: payload})
}

func (s *typedFileServer) writeFrame(frame protocol.Frame) error {
	if s.write == nil {
		return errors.New("typed file frame writer is unavailable")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.write(frame)
}

func (s *typedFileServer) CloseAll() {
	s.mu.Lock()
	ids := make([]uint32, 0, len(s.streams))
	for id := range s.streams {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.closeChild(id)
	}
}
