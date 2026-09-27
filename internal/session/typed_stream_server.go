package session

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/terminal"
)

const typedTerminalReceiveWindow = 256 << 10

var errTypedStreamProtocol = errors.New("typed terminal stream protocol violation")

type typedTerminalPTY interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Resize(uint16, uint16) error
	Wait() error
	Close() error
}

type typedTerminalStarter func(shell string, cols, rows uint16, term string) (typedTerminalPTY, error)
type typedTerminalFrameWriter func(protocol.Frame) error

type typedTerminalChild struct {
	pty typedTerminalPTY

	mu         sync.Mutex
	sendCredit typedStreamCredit
	recvCredit typedStreamCredit
	creditCh   chan struct{}
	done       chan struct{}
	closeOnce  sync.Once
}

type typedTerminalServer struct {
	shell string
	start typedTerminalStarter
	write typedTerminalFrameWriter

	mu      sync.Mutex
	writeMu sync.Mutex
	states  *typedTerminalStreamSet
	streams map[uint32]*typedTerminalChild
}

func newTypedTerminalServer(shell string, write typedTerminalFrameWriter) *typedTerminalServer {
	return newTypedTerminalServerWithStarter(shell, write, func(shell string, cols, rows uint16, term string) (typedTerminalPTY, error) {
		return terminal.Start(shell, cols, rows, term)
	})
}

func newTypedTerminalServerWithStarter(shell string, write typedTerminalFrameWriter, start typedTerminalStarter) *typedTerminalServer {
	return &typedTerminalServer{
		shell:   shell,
		start:   start,
		write:   write,
		states:  newTypedTerminalStreamSet(),
		streams: make(map[uint32]*typedTerminalChild),
	}
}

func (s *typedTerminalServer) Handle(frame protocol.Frame) error {
	switch frame.Type {
	case protocol.TypeStreamOpen:
		return s.open(frame)
	case protocol.TypeStreamData:
		return s.data(frame)
	case protocol.TypeStreamWindowUpdate:
		return s.windowUpdate(frame)
	case protocol.TypeStreamResize:
		return s.resize(frame)
	case protocol.TypeStreamClose:
		return s.closeStream(frame.StreamID, "peer_close", true)
	default:
		return fmt.Errorf("%w: unexpected frame type %d", errTypedStreamProtocol, frame.Type)
	}
}

func (s *typedTerminalServer) open(frame protocol.Frame) error {
	var open protocol.StreamOpen
	if err := protocol.ParseJSON(frame.Payload, &open); err != nil {
		return fmt.Errorf("%w: malformed stream open", errTypedStreamProtocol)
	}
	if err := protocol.ValidateStreamOpen(frame.StreamID, open); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}

	s.mu.Lock()
	if err := s.states.reserve(frame.StreamID); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	s.mu.Unlock()

	pty, err := s.start(s.shell, open.Cols, open.Rows, open.Term)
	if err != nil {
		s.markClosed(frame.StreamID)
		return fmt.Errorf("start typed terminal PTY: %w", err)
	}
	sendCredit, err := newTypedStreamCredit(open.InitialWindow)
	if err != nil {
		_ = pty.Close()
		s.markClosed(frame.StreamID)
		return err
	}
	recvCredit, err := newTypedStreamCredit(typedTerminalReceiveWindow)
	if err != nil {
		_ = pty.Close()
		s.markClosed(frame.StreamID)
		return err
	}
	child := &typedTerminalChild{
		pty:        pty,
		sendCredit: sendCredit,
		recvCredit: recvCredit,
		creditCh:   make(chan struct{}, 1),
		done:       make(chan struct{}),
	}

	s.mu.Lock()
	s.streams[frame.StreamID] = child
	if err := s.states.accept(frame.StreamID); err != nil {
		delete(s.streams, frame.StreamID)
		s.mu.Unlock()
		_ = pty.Close()
		return err
	}
	s.mu.Unlock()

	accepted, err := protocol.JSON(protocol.StreamAccepted{InitialWindow: typedTerminalReceiveWindow})
	if err != nil {
		_ = s.closeStream(frame.StreamID, "encode_failed", false)
		return err
	}
	if err := s.writeFrame(protocol.Frame{Type: protocol.TypeStreamAccepted, StreamID: frame.StreamID, Payload: accepted}); err != nil {
		_ = s.closeStream(frame.StreamID, "transport_write_failed", false)
		return err
	}

	readDone := make(chan struct{})
	go s.forwardOutput(frame.StreamID, child, readDone)
	go s.waitProcess(frame.StreamID, child, readDone)
	return nil
}

func (s *typedTerminalServer) data(frame protocol.Frame) error {
	if err := protocol.ValidateStreamData(frame.StreamID, frame.Payload); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	child, err := s.openChild(frame.StreamID)
	if err != nil {
		return err
	}

	child.mu.Lock()
	if err := child.recvCredit.consume(uint32(len(frame.Payload))); err != nil {
		child.mu.Unlock()
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	child.mu.Unlock()

	n, writeErr := child.pty.Write(frame.Payload)
	if writeErr != nil || n != len(frame.Payload) {
		_ = s.closeStream(frame.StreamID, "pty_write_failed", true)
		if writeErr != nil {
			return writeErr
		}
		return io.ErrShortWrite
	}

	update := protocol.StreamWindowUpdate{Bytes: uint32(n)}
	payload, err := protocol.JSON(update)
	if err != nil {
		return err
	}
	if err := s.writeFrame(protocol.Frame{Type: protocol.TypeStreamWindowUpdate, StreamID: frame.StreamID, Payload: payload}); err != nil {
		_ = s.closeStream(frame.StreamID, "transport_write_failed", false)
		return err
	}
	child.mu.Lock()
	err = child.recvCredit.add(uint32(n))
	child.mu.Unlock()
	if err != nil {
		_ = s.closeStream(frame.StreamID, "credit_accounting_failed", false)
		return err
	}
	return nil
}

func (s *typedTerminalServer) windowUpdate(frame protocol.Frame) error {
	var update protocol.StreamWindowUpdate
	if err := protocol.ParseJSON(frame.Payload, &update); err != nil {
		return fmt.Errorf("%w: malformed window update", errTypedStreamProtocol)
	}
	if err := protocol.ValidateStreamWindowUpdate(frame.StreamID, update); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	child, err := s.openChild(frame.StreamID)
	if err != nil {
		return err
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

func (s *typedTerminalServer) resize(frame protocol.Frame) error {
	var resize protocol.Resize
	if err := protocol.ParseJSON(frame.Payload, &resize); err != nil {
		return fmt.Errorf("%w: malformed typed terminal resize", errTypedStreamProtocol)
	}
	if err := protocol.ValidateStreamResize(frame.StreamID, resize); err != nil {
		return fmt.Errorf("%w: %v", errTypedStreamProtocol, err)
	}
	child, err := s.openChild(frame.StreamID)
	if err != nil {
		return err
	}
	if err := child.pty.Resize(resize.Cols, resize.Rows); err != nil {
		_ = s.closeStream(frame.StreamID, "pty_resize_failed", true)
		return err
	}
	return nil
}

func (s *typedTerminalServer) openChild(streamID uint32) (*typedTerminalChild, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.states.isOpen(streamID) {
		return nil, fmt.Errorf("%w: stream %d is not open", errTypedStreamProtocol, streamID)
	}
	child := s.streams[streamID]
	if child == nil {
		return nil, fmt.Errorf("%w: stream %d has no PTY", errTypedStreamProtocol, streamID)
	}
	return child, nil
}

func (s *typedTerminalServer) forwardOutput(streamID uint32, child *typedTerminalChild, readDone chan<- struct{}) {
	defer close(readDone)
	buf := make([]byte, 32<<10)
	for {
		n, err := child.pty.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			if s.sendData(streamID, child, data) != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *typedTerminalServer) sendData(streamID uint32, child *typedTerminalChild, data []byte) error {
	for offset := 0; offset < len(data); {
		var chunk int
		for chunk == 0 {
			child.mu.Lock()
			available := child.sendCredit.available()
			if available > 0 {
				chunk = len(data) - offset
				if chunk > protocol.MaxTypedStreamChunk {
					chunk = protocol.MaxTypedStreamChunk
				}
				if uint32(chunk) > available {
					chunk = int(available)
				}
				if err := child.sendCredit.consume(uint32(chunk)); err != nil {
					child.mu.Unlock()
					return err
				}
			}
			child.mu.Unlock()
			if chunk == 0 {
				select {
				case <-child.creditCh:
				case <-child.done:
					return io.ErrClosedPipe
				}
			}
		}
		payload := append([]byte(nil), data[offset:offset+chunk]...)
		if err := s.writeFrame(protocol.Frame{Type: protocol.TypeStreamData, StreamID: streamID, Payload: payload}); err != nil {
			return err
		}
		offset += chunk
	}
	return nil
}

func (s *typedTerminalServer) waitProcess(streamID uint32, child *typedTerminalChild, readDone <-chan struct{}) {
	_ = child.pty.Wait()
	timer := time.NewTimer(terminalExitDrainTimeout)
	defer timer.Stop()
	select {
	case <-readDone:
		_ = s.closeStream(streamID, "process_exit", true)
	case <-timer.C:
		_ = s.closeStream(streamID, "pty_drain_timeout", true)
	case <-child.done:
	}
}

func (s *typedTerminalServer) closeStream(streamID uint32, reason string, sendClose bool) error {
	s.mu.Lock()
	child := s.streams[streamID]
	if child == nil || !s.states.isOpen(streamID) {
		s.mu.Unlock()
		return fmt.Errorf("%w: stream %d is not open", errTypedStreamProtocol, streamID)
	}
	_ = s.states.close(streamID)
	delete(s.streams, streamID)
	s.mu.Unlock()

	child.closeOnce.Do(func() {
		close(child.done)
		_ = child.pty.Close()
	})
	if !sendClose {
		return nil
	}
	payload, err := protocol.JSON(protocol.StreamClose{Reason: reason})
	if err != nil {
		return err
	}
	return s.writeFrame(protocol.Frame{Type: protocol.TypeStreamClose, StreamID: streamID, Payload: payload})
}

func (s *typedTerminalServer) markClosed(streamID uint32) {
	s.mu.Lock()
	_ = s.states.close(streamID)
	delete(s.streams, streamID)
	s.mu.Unlock()
}

func (s *typedTerminalServer) CloseAll() {
	s.mu.Lock()
	children := make([]*typedTerminalChild, 0, len(s.streams))
	for _, child := range s.streams {
		children = append(children, child)
	}
	s.streams = make(map[uint32]*typedTerminalChild)
	s.states.closeAll()
	s.mu.Unlock()

	for _, child := range children {
		child.closeOnce.Do(func() {
			close(child.done)
			_ = child.pty.Close()
		})
	}
}

func (s *typedTerminalServer) writeFrame(frame protocol.Frame) error {
	if s.write == nil {
		return errors.New("typed terminal frame writer is unavailable")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.write(frame)
}
