package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/trust"
)

const managedMuxMaxFileStreams = 4

// ManagedFileStreamError is a bounded peer-reported child error. It contains
// only the protocol error code/message supplied by the authenticated peer; file
// contents, credentials, and local filesystem details are never attached.
type ManagedFileStreamError struct {
	Code    string
	Message string
}

func (e *ManagedFileStreamError) Error() string {
	if e == nil {
		return "file stream failed"
	}
	if e.Message == "" {
		return "file stream failed: " + e.Code
	}
	return "file stream failed: " + e.Code + ": " + e.Message
}

type managedFileState struct {
	kind  protocol.StreamKind
	child *managedMuxChild

	mu          sync.Mutex
	terminalErr error
	closeReason string
}

func (s *managedFileState) setError(err error) {
	s.mu.Lock()
	if s.terminalErr == nil {
		s.terminalErr = err
	}
	s.mu.Unlock()
}

func (s *managedFileState) result() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminalErr
}

func (s *managedFileState) setCloseReason(reason string) {
	s.mu.Lock()
	s.closeReason = reason
	s.mu.Unlock()
}

// ManagedMultiplexSession owns one authenticated parent application session for
// terminal and, when separately negotiated, file-transfer children. It reuses
// the established terminal child implementation and writer lock; file children
// never create a second connection or trust path.
type ManagedMultiplexSession struct {
	terminal *ManagedMultiplexTerminal

	mu           sync.Mutex
	fileTransfer bool
	files        map[uint32]*managedFileState
}

// OpenManagedMultiplexSession requests typed terminal and file-transfer
// capabilities. Older peers may negotiate typed terminals only or return the
// legacy empty SessionAccepted payload; both remain supported without silently
// treating file transfer as available.
func (c *Client) OpenManagedMultiplexSession(ctx context.Context, peer trust.Peer, cols, rows uint16, term string) (*ManagedMultiplexSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	inBandAuthorization := !strings.HasPrefix(strings.ToLower(strings.TrimSpace(peer.Endpoint)), "wsrelay://")
	if inBandAuthorization {
		grant := strings.TrimSpace(c.ConnectionGrant)
		if grant == "" || len(grant) > 16*1024 || strings.ContainsAny(grant, "\r\n\t ") {
			return nil, errors.New("a valid connection grant is required for this transport")
		}
	}
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	raw, err := c.dial(ctx, peer.Endpoint)
	if err != nil {
		return nil, err
	}
	conn, err := tlsClientContext(ctx, raw, c.Identity, peer.Fingerprint)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	deadline := time.Now().Add(15 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	capabilities := []protocol.Capability{
		protocol.CapabilityTypedStreamsV1,
		protocol.CapabilityFileTransferV1,
	}
	frameType := protocol.TypeOpenSession
	var payload []byte
	if inBandAuthorization {
		frameType = protocol.TypeOpenAuthorizedSession
		payload, _ = protocol.JSON(protocol.OpenAuthorizedSession{
			Cols: cols, Rows: rows, Term: term,
			ConnectionGrant: strings.TrimSpace(c.ConnectionGrant),
			Capabilities:    capabilities,
		})
	} else {
		payload, _ = protocol.JSON(protocol.OpenSession{Cols: cols, Rows: rows, Term: term, Capabilities: capabilities})
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: frameType, Payload: payload}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	first, err := protocol.ReadFrame(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if first.Type == protocol.TypeError {
		_ = conn.Close()
		return nil, protocolError(first.Payload)
	}
	if first.Type != protocol.TypeSessionAccepted {
		_ = conn.Close()
		return nil, errors.New("session was not accepted")
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	typed, fileTransfer, err := parseManagedMultiplexCapabilities(first.Payload)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})

	terminal := &ManagedMultiplexTerminal{
		conn:       conn,
		typed:      typed,
		streams:    make(map[uint32]*managedMuxChild),
		nextStream: protocol.MinTypedStreamID,
		probePong:  make(chan struct{}, 1),
		done:       make(chan struct{}),
	}
	s := &ManagedMultiplexSession{
		terminal:     terminal,
		fileTransfer: fileTransfer,
		files:        make(map[uint32]*managedFileState),
	}
	if !typed {
		child := newManagedMuxChild(terminalStreamID, false)
		terminal.streams[terminalStreamID] = child
		terminal.defaultStream = terminalStreamID
	}
	go s.monitor()
	if typed {
		streamID, err := terminal.OpenTerminalStream(ctx, cols, rows, term)
		if err != nil {
			_ = terminal.finish()
			return nil, err
		}
		terminal.mu.Lock()
		terminal.defaultStream = streamID
		terminal.mu.Unlock()
	}
	return s, nil
}

func parseManagedMultiplexCapabilities(payload []byte) (typed bool, fileTransfer bool, err error) {
	if len(payload) == 0 {
		return false, false, nil
	}
	var accepted protocol.SessionAccepted
	if err := protocol.ParseTypedStreamJSON(payload, &accepted); err != nil {
		return false, false, errors.New("invalid session capabilities")
	}
	switch len(accepted.Capabilities) {
	case 1:
		if accepted.Capabilities[0] != protocol.CapabilityTypedStreamsV1 {
			return false, false, errors.New("unexpected session capabilities")
		}
		return true, false, nil
	case 2:
		if accepted.Capabilities[0] != protocol.CapabilityTypedStreamsV1 || accepted.Capabilities[1] != protocol.CapabilityFileTransferV1 {
			return false, false, errors.New("unexpected session capabilities")
		}
		return true, true, nil
	default:
		return false, false, errors.New("unexpected session capabilities")
	}
}

func (s *ManagedMultiplexSession) FileTransferAvailable() bool {
	if s == nil || s.terminal == nil || channelClosed(s.terminal.done) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fileTransfer
}

func (s *ManagedMultiplexSession) Done() <-chan struct{} {
	if s == nil || s.terminal == nil {
		return nil
	}
	return s.terminal.Done()
}

func (s *ManagedMultiplexSession) ProbeLatency(ctx context.Context) (time.Duration, error) {
	if s == nil || s.terminal == nil {
		return 0, io.ErrClosedPipe
	}
	return s.terminal.ProbeLatency(ctx)
}

func (s *ManagedMultiplexSession) ReadTerminal(ctx context.Context, maxBytes int) ([]byte, bool, error) {
	if s == nil || s.terminal == nil {
		return nil, true, io.ErrClosedPipe
	}
	return s.terminal.ReadTerminal(ctx, maxBytes)
}

func (s *ManagedMultiplexSession) WriteTerminal(ctx context.Context, data []byte) error {
	if s == nil || s.terminal == nil {
		return io.ErrClosedPipe
	}
	return s.terminal.WriteTerminal(ctx, data)
}

func (s *ManagedMultiplexSession) ResizeTerminal(ctx context.Context, cols, rows uint16) error {
	if s == nil || s.terminal == nil {
		return io.ErrClosedPipe
	}
	return s.terminal.ResizeTerminal(ctx, cols, rows)
}

func (s *ManagedMultiplexSession) OpenTerminalStream(ctx context.Context, cols, rows uint16, term string) (uint32, error) {
	if s == nil || s.terminal == nil {
		return 0, io.ErrClosedPipe
	}
	return s.terminal.OpenTerminalStream(ctx, cols, rows, term)
}

func (s *ManagedMultiplexSession) ReadTerminalStream(ctx context.Context, id uint32, maxBytes int) ([]byte, bool, error) {
	if s == nil || s.terminal == nil {
		return nil, true, io.ErrClosedPipe
	}
	return s.terminal.ReadTerminalStream(ctx, id, maxBytes)
}

func (s *ManagedMultiplexSession) WriteTerminalStream(ctx context.Context, id uint32, data []byte) error {
	if s == nil || s.terminal == nil {
		return io.ErrClosedPipe
	}
	return s.terminal.WriteTerminalStream(ctx, id, data)
}

func (s *ManagedMultiplexSession) ResizeTerminalStream(ctx context.Context, id uint32, cols, rows uint16) error {
	if s == nil || s.terminal == nil {
		return io.ErrClosedPipe
	}
	return s.terminal.ResizeTerminalStream(ctx, id, cols, rows)
}

func (s *ManagedMultiplexSession) CloseTerminalStream(ctx context.Context, id uint32) error {
	if s == nil || s.terminal == nil {
		return io.ErrClosedPipe
	}
	return s.terminal.CloseTerminalStream(ctx, id)
}

func (s *ManagedMultiplexSession) Close() error {
	if s == nil || s.terminal == nil {
		return nil
	}
	return s.terminal.Close()
}

// ManagedFileUpload is one upload child on a ManagedMultiplexSession. Commit is
// explicit and is the only operation that asks the server to publish the staged
// upload. Cancel discards it without closing the authenticated parent.
type ManagedFileUpload struct {
	session *ManagedMultiplexSession
	state   *managedFileState
	id      uint32
}

func (s *ManagedMultiplexSession) OpenFileUpload(ctx context.Context, metadata protocol.FileUploadOpen) (*ManagedFileUpload, error) {
	if err := protocol.ValidateFileUploadOpen(metadata); err != nil {
		return nil, err
	}
	state, id, err := s.openFileStream(ctx, protocol.StreamKindFileUpload, metadata, 1)
	if err != nil {
		return nil, err
	}
	return &ManagedFileUpload{session: s, state: state, id: id}, nil
}

func (u *ManagedFileUpload) Done() <-chan struct{} {
	if u == nil || u.state == nil || u.state.child == nil {
		return nil
	}
	return u.state.child.done
}

func (u *ManagedFileUpload) Write(ctx context.Context, data []byte) error {
	if u == nil || u.session == nil || u.state == nil || u.state.child == nil {
		return io.ErrClosedPipe
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	child := u.state.child
	remaining := data
	for len(remaining) != 0 {
		var n int
		for n == 0 {
			child.mu.Lock()
			if channelClosed(child.done) {
				child.mu.Unlock()
				return fileChildResult(u.state)
			}
			if child.sendCredit > 0 {
				n = len(remaining)
				if n > protocol.MaxTypedStreamChunk {
					n = protocol.MaxTypedStreamChunk
				}
				if uint32(n) > child.sendCredit {
					n = int(child.sendCredit)
				}
				child.sendCredit -= uint32(n)
			}
			child.mu.Unlock()
			if n == 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-u.session.terminal.done:
					return io.ErrClosedPipe
				case <-child.done:
					return fileChildResult(u.state)
				case <-child.creditNotify:
				}
			}
		}
		frame := protocol.Frame{Type: protocol.TypeStreamData, StreamID: u.id, Payload: append([]byte(nil), remaining[:n]...)}
		if err := u.session.terminal.writeFrameContext(ctx, frame); err != nil {
			_ = u.session.terminal.finish()
			return err
		}
		remaining = remaining[n:]
	}
	return nil
}

func (u *ManagedFileUpload) Commit(ctx context.Context) error {
	if u == nil || u.session == nil || u.state == nil || u.state.child == nil {
		return io.ErrClosedPipe
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	child := u.state.child
	child.mu.Lock()
	if channelClosed(child.done) {
		child.mu.Unlock()
		return fileChildResult(u.state)
	}
	sendClose := !child.closing
	child.closing = true
	child.mu.Unlock()
	if sendClose {
		payload, _ := protocol.JSON(protocol.StreamClose{Reason: "upload_complete"})
		if err := u.session.terminal.writeFrameContext(ctx, protocol.Frame{Type: protocol.TypeStreamClose, StreamID: u.id, Payload: payload}); err != nil {
			_ = u.session.terminal.finish()
			return err
		}
	}
	select {
	case <-ctx.Done():
		// Publication may already have occurred after the close was written.
		// End the parent rather than allowing a caller to mistake this for a
		// definitely uncommitted upload and retry on the same session.
		_ = u.session.terminal.finish()
		return ctx.Err()
	case <-u.session.terminal.done:
		return io.ErrClosedPipe
	case <-child.done:
		return u.state.result()
	}
}

func (u *ManagedFileUpload) Cancel(ctx context.Context) error {
	if u == nil || u.session == nil || u.state == nil {
		return nil
	}
	return u.session.cancelFile(ctx, u.id, u.state)
}

// ManagedFileDownload is one download child. Reads are bounded and replenish
// receive credit only after bytes have been consumed by the caller.
type ManagedFileDownload struct {
	session *ManagedMultiplexSession
	state   *managedFileState
	id      uint32
}

func (s *ManagedMultiplexSession) OpenFileDownload(ctx context.Context, metadata protocol.FileDownloadOpen) (*ManagedFileDownload, error) {
	if err := protocol.ValidateFileDownloadOpen(metadata); err != nil {
		return nil, err
	}
	state, id, err := s.openFileStream(ctx, protocol.StreamKindFileDownload, metadata, managedMuxReceiveWindow)
	if err != nil {
		return nil, err
	}
	return &ManagedFileDownload{session: s, state: state, id: id}, nil
}

func (d *ManagedFileDownload) Done() <-chan struct{} {
	if d == nil || d.state == nil || d.state.child == nil {
		return nil
	}
	return d.state.child.done
}

func (d *ManagedFileDownload) Read(ctx context.Context, maxBytes int) ([]byte, bool, error) {
	if d == nil || d.session == nil || d.state == nil || d.state.child == nil {
		return nil, true, io.ErrClosedPipe
	}
	if maxBytes == 0 {
		maxBytes = managedTerminalChunkLimit
	}
	if maxBytes < 1 || maxBytes > protocol.MaxTypedStreamChunk {
		return nil, false, errors.New("file download read size is out of range")
	}
	child := d.state.child
	child.readMu.Lock()
	defer child.readMu.Unlock()
	for {
		child.mu.Lock()
		if len(child.outputQueue) != 0 {
			chunk := child.outputQueue[0]
			n := len(chunk)
			if n > maxBytes {
				n = maxBytes
			}
			out := append([]byte(nil), chunk[:n]...)
			if n == len(chunk) {
				child.outputQueue[0] = nil
				child.outputQueue = child.outputQueue[1:]
			} else {
				child.outputQueue[0] = chunk[n:]
			}
			child.outputBytes -= n
			closed := channelClosed(child.done) && child.outputBytes == 0
			child.mu.Unlock()
			if n > 0 {
				payload, _ := protocol.JSON(protocol.StreamWindowUpdate{Bytes: uint32(n)})
				if err := d.session.terminal.writeFrameContext(ctx, protocol.Frame{Type: protocol.TypeStreamWindowUpdate, StreamID: d.id, Payload: payload}); err != nil {
					_ = d.session.terminal.finish()
					return out, true, err
				}
				child.mu.Lock()
				child.recvCredit += uint32(n)
				child.mu.Unlock()
			}
			if closed {
				return out, true, d.state.result()
			}
			return out, false, nil
		}
		closed := channelClosed(child.done)
		child.mu.Unlock()
		if closed {
			return nil, true, d.state.result()
		}
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-d.session.terminal.done:
			return nil, true, io.ErrClosedPipe
		case <-child.done:
		case <-child.outputNotify:
		}
	}
}

func (d *ManagedFileDownload) Cancel(ctx context.Context) error {
	if d == nil || d.session == nil || d.state == nil {
		return nil
	}
	return d.session.cancelFile(ctx, d.id, d.state)
}

func fileChildResult(state *managedFileState) error {
	if state == nil {
		return io.ErrClosedPipe
	}
	if err := state.result(); err != nil {
		return err
	}
	return io.ErrClosedPipe
}

func (s *ManagedMultiplexSession) openFileStream(ctx context.Context, kind protocol.StreamKind, metadata any, initialWindow uint32) (*managedFileState, uint32, error) {
	if s == nil || s.terminal == nil || channelClosed(s.terminal.done) {
		return nil, 0, io.ErrClosedPipe
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	metadataPayload, err := protocol.JSON(metadata)
	if err != nil {
		return nil, 0, err
	}

	s.mu.Lock()
	if !s.fileTransfer {
		s.mu.Unlock()
		return nil, 0, errors.New("file transfer was not negotiated")
	}
	if len(s.files) >= managedMuxMaxFileStreams {
		s.mu.Unlock()
		return nil, 0, errors.New("file stream limit reached")
	}
	s.terminal.mu.Lock()
	if !s.terminal.typed || s.terminal.allocated >= managedMuxMaxAllocated {
		s.terminal.mu.Unlock()
		s.mu.Unlock()
		return nil, 0, errors.New("typed stream limit reached")
	}
	id := s.terminal.nextStream
	if id < protocol.MinTypedStreamID {
		id = protocol.MinTypedStreamID
	}
	for {
		if _, exists := s.terminal.streams[id]; !exists {
			break
		}
		id++
	}
	s.terminal.nextStream = id + 1
	s.terminal.allocated++
	child := newManagedMuxChild(id, true)
	s.terminal.streams[id] = child
	state := &managedFileState{kind: kind, child: child}
	s.files[id] = state
	s.terminal.mu.Unlock()
	s.mu.Unlock()

	envelope := protocol.StreamOpen{Kind: kind, Metadata: metadataPayload, InitialWindow: initialWindow}
	switch kind {
	case protocol.StreamKindFileUpload:
		if _, err := protocol.ParseFileUploadStreamOpen(id, envelope); err != nil {
			s.removeFile(id, state)
			return nil, 0, err
		}
	case protocol.StreamKindFileDownload:
		if _, err := protocol.ParseFileDownloadStreamOpen(id, envelope); err != nil {
			s.removeFile(id, state)
			return nil, 0, err
		}
	default:
		s.removeFile(id, state)
		return nil, 0, errors.New("unsupported file stream kind")
	}
	payload, err := protocol.JSON(envelope)
	if err != nil {
		s.removeFile(id, state)
		return nil, 0, err
	}
	if err := s.terminal.writeFrameContext(ctx, protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: id, Payload: payload}); err != nil {
		_ = s.terminal.finish()
		return nil, 0, err
	}
	select {
	case <-ctx.Done():
		_ = s.terminal.finish()
		return nil, 0, ctx.Err()
	case <-s.terminal.done:
		return nil, 0, io.ErrClosedPipe
	case err := <-child.accepted:
		if err != nil {
			s.removeFile(id, state)
			return nil, 0, err
		}
		return state, id, nil
	}
}

func (s *ManagedMultiplexSession) cancelFile(ctx context.Context, id uint32, state *managedFileState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	child := state.child
	child.mu.Lock()
	if channelClosed(child.done) {
		child.mu.Unlock()
		if err := state.result(); err != nil {
			return err
		}
		return nil
	}
	child.closing = true
	child.mu.Unlock()
	streamErr := protocol.StreamError{Code: "client_cancelled", Message: "file transfer cancelled by client"}
	payload, _ := protocol.JSON(streamErr)
	if err := s.terminal.writeFrameContext(ctx, protocol.Frame{Type: protocol.TypeStreamError, StreamID: id, Payload: payload}); err != nil {
		_ = s.terminal.finish()
		return err
	}
	state.setError(context.Canceled)
	s.removeFile(id, state)
	return nil
}

func (s *ManagedMultiplexSession) fileState(id uint32) *managedFileState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.files[id]
}

func (s *ManagedMultiplexSession) removeFile(id uint32, state *managedFileState) {
	s.mu.Lock()
	if s.files[id] == state {
		delete(s.files, id)
	}
	s.mu.Unlock()
	if s.terminal != nil {
		s.terminal.removeChild(id)
	}
}

func (s *ManagedMultiplexSession) monitor() {
	for {
		frame, err := protocol.ReadFrame(s.terminal.conn)
		if err != nil {
			_ = s.terminal.finish()
			return
		}
		switch frame.Type {
		case protocol.TypeClose:
			_ = s.terminal.writeFrame(protocol.Frame{Type: protocol.TypeClose})
			_ = s.terminal.finish()
			return
		case protocol.TypePing:
			if s.terminal.writeFrame(protocol.Frame{Type: protocol.TypePong}) != nil {
				_ = s.terminal.finish()
				return
			}
		case protocol.TypePong:
			select {
			case s.terminal.probePong <- struct{}{}:
			default:
			}
		case protocol.TypeError:
			_ = s.terminal.finish()
			return
		case protocol.TypeData:
			if s.terminal.isTyped() || frame.StreamID != terminalStreamID || len(frame.Payload) == 0 || !s.terminal.enqueue(frame.StreamID, frame.Payload, false) {
				_ = s.terminal.finish()
				return
			}
		case protocol.TypeResize:
			if s.terminal.isTyped() {
				_ = s.terminal.finish()
				return
			}
		case protocol.TypeStreamAccepted:
			if !s.terminal.handleAccepted(frame) {
				_ = s.terminal.finish()
				return
			}
		case protocol.TypeStreamData:
			state := s.fileState(frame.StreamID)
			if state != nil {
				if !s.handleFileData(frame, state) {
					_ = s.terminal.finish()
					return
				}
			} else if !s.terminal.handleTypedData(frame) {
				_ = s.terminal.finish()
				return
			}
		case protocol.TypeStreamWindowUpdate:
			state := s.fileState(frame.StreamID)
			if state != nil && state.kind != protocol.StreamKindFileUpload {
				_ = s.terminal.finish()
				return
			}
			if !s.terminal.handleWindowUpdate(frame) {
				_ = s.terminal.finish()
				return
			}
		case protocol.TypeStreamClose:
			state := s.fileState(frame.StreamID)
			if state != nil {
				if !s.handleFileClose(frame, state) {
					_ = s.terminal.finish()
					return
				}
			} else if !s.terminal.handleStreamClose(frame) {
				_ = s.terminal.finish()
				return
			}
		case protocol.TypeStreamError:
			state := s.fileState(frame.StreamID)
			if state != nil {
				if !s.handleFileError(frame, state) {
					_ = s.terminal.finish()
					return
				}
			} else if !s.terminal.handleStreamError(frame) {
				_ = s.terminal.finish()
				return
			}
		default:
			_ = s.terminal.finish()
			return
		}
	}
}

func (s *ManagedMultiplexSession) handleFileData(frame protocol.Frame, state *managedFileState) bool {
	if state.kind != protocol.StreamKindFileDownload || protocol.ValidateStreamData(frame.StreamID, frame.Payload) != nil {
		return false
	}
	child := state.child
	child.mu.Lock()
	if !child.acceptedOK || uint32(len(frame.Payload)) > child.recvCredit || len(frame.Payload) > managedTerminalOutputLimit-child.outputBytes {
		child.mu.Unlock()
		return false
	}
	child.recvCredit -= uint32(len(frame.Payload))
	child.outputQueue = append(child.outputQueue, append([]byte(nil), frame.Payload...))
	child.outputBytes += len(frame.Payload)
	child.mu.Unlock()
	select {
	case child.outputNotify <- struct{}{}:
	default:
	}
	return true
}

func (s *ManagedMultiplexSession) handleFileClose(frame protocol.Frame, state *managedFileState) bool {
	var msg protocol.StreamClose
	if protocol.ParseTypedStreamJSON(frame.Payload, &msg) != nil || protocol.ValidateStreamClose(frame.StreamID, msg) != nil {
		return false
	}
	child := state.child
	child.mu.Lock()
	accepted := child.acceptedOK
	closing := child.closing
	child.mu.Unlock()
	if !accepted {
		return false
	}
	switch state.kind {
	case protocol.StreamKindFileUpload:
		if !closing || msg.Reason != "peer_close" {
			return false
		}
	case protocol.StreamKindFileDownload:
		if closing {
			if msg.Reason != "peer_close" {
				return false
			}
		} else if msg.Reason != "download_complete" {
			return false
		}
	default:
		return false
	}
	state.setCloseReason(msg.Reason)
	s.removeFile(frame.StreamID, state)
	return true
}

func (s *ManagedMultiplexSession) handleFileError(frame protocol.Frame, state *managedFileState) bool {
	var msg protocol.StreamError
	if protocol.ParseTypedStreamJSON(frame.Payload, &msg) != nil || protocol.ValidateStreamError(frame.StreamID, msg) != nil {
		return false
	}
	err := &ManagedFileStreamError{Code: msg.Code, Message: msg.Message}
	state.setError(err)
	child := state.child
	child.mu.Lock()
	accepted := child.acceptedOK
	child.mu.Unlock()
	if !accepted {
		child.acceptOnce.Do(func() { child.accepted <- err })
	}
	s.removeFile(frame.StreamID, state)
	return true
}
