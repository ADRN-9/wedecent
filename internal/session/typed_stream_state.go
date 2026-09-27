package session

import (
	"errors"
	"fmt"
	"sync"

	"wedecent.com/wedecent/internal/protocol"
)

const (
	maxTerminalStreamsPerConnection   = 8
	maxTypedStreamIDsPerConnection    = 256
	maxTerminalStreamIDsPerConnection = maxTypedStreamIDsPerConnection
)

var (
	errTypedStreamIDReserved = errors.New("typed stream ID is reserved")
	errTypedStreamDuplicate  = errors.New("typed stream ID already used")
	errTypedStreamLimit      = errors.New("typed stream limit reached")
	errTypedStreamNotOpen    = errors.New("typed stream is not open")
	errTypedStreamKind       = errors.New("typed stream kind is invalid")
)

type typedStreamState uint8

const (
	typedStreamOpening typedStreamState = iota + 1
	typedStreamOpen
	typedStreamClosed
)

type typedStreamRecord struct {
	kind  protocol.StreamKind
	state typedStreamState
}

// typedParentStreamRegistry owns the connection-wide typed StreamID namespace.
// Closed IDs remain recorded for the lifetime of the authenticated parent so a
// different operation kind can never reuse a terminal/file/forwarding ID.
// The registry protects its own map because multiple operation engines share it.
type typedParentStreamRegistry struct {
	mu     sync.Mutex
	states map[uint32]typedStreamRecord
}

func newTypedParentStreamRegistry() *typedParentStreamRegistry {
	return &typedParentStreamRegistry{states: make(map[uint32]typedStreamRecord)}
}

func (r *typedParentStreamRegistry) reserve(streamID uint32, kind protocol.StreamKind) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if streamID < protocol.MinTypedStreamID {
		return errTypedStreamIDReserved
	}
	if kind == "" {
		return errTypedStreamKind
	}
	if _, exists := r.states[streamID]; exists {
		return errTypedStreamDuplicate
	}
	if len(r.states) >= maxTypedStreamIDsPerConnection {
		return errTypedStreamLimit
	}
	r.states[streamID] = typedStreamRecord{kind: kind, state: typedStreamOpening}
	return nil
}

func (r *typedParentStreamRegistry) accept(streamID uint32, kind protocol.StreamKind) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, exists := r.states[streamID]
	if !exists || record.kind != kind || record.state != typedStreamOpening {
		return fmt.Errorf("%w: %d", errTypedStreamNotOpen, streamID)
	}
	record.state = typedStreamOpen
	r.states[streamID] = record
	return nil
}

func (r *typedParentStreamRegistry) isOpen(streamID uint32, kind protocol.StreamKind) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, exists := r.states[streamID]
	return exists && record.kind == kind && record.state == typedStreamOpen
}

func (r *typedParentStreamRegistry) kind(streamID uint32) (protocol.StreamKind, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, exists := r.states[streamID]
	if !exists || record.state == typedStreamClosed {
		return "", false
	}
	return record.kind, true
}

func (r *typedParentStreamRegistry) close(streamID uint32, kind protocol.StreamKind) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, exists := r.states[streamID]
	if !exists || record.kind != kind || record.state == typedStreamClosed {
		return fmt.Errorf("%w: %d", errTypedStreamNotOpen, streamID)
	}
	record.state = typedStreamClosed
	r.states[streamID] = record
	return nil
}

func (r *typedParentStreamRegistry) closeKind(kind protocol.StreamKind) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for streamID, record := range r.states {
		if record.kind == kind && record.state != typedStreamClosed {
			record.state = typedStreamClosed
			r.states[streamID] = record
		}
	}
}

type typedTerminalStreamSet struct {
	registry *typedParentStreamRegistry
	open     int
}

func newTypedTerminalStreamSet() *typedTerminalStreamSet {
	return newTypedTerminalStreamSetWithRegistry(newTypedParentStreamRegistry())
}

func newTypedTerminalStreamSetWithRegistry(registry *typedParentStreamRegistry) *typedTerminalStreamSet {
	if registry == nil {
		registry = newTypedParentStreamRegistry()
	}
	return &typedTerminalStreamSet{registry: registry}
}

func (s *typedTerminalStreamSet) reserve(streamID uint32) error {
	// Stream 1 remains the legacy/default terminal. Additional typed terminals
	// therefore have one fewer slot than the connection-wide terminal limit.
	if s.open >= maxTerminalStreamsPerConnection-1 {
		return errTypedStreamLimit
	}
	if err := s.registry.reserve(streamID, protocol.StreamKindTerminal); err != nil {
		return err
	}
	s.open++
	return nil
}

func (s *typedTerminalStreamSet) accept(streamID uint32) error {
	return s.registry.accept(streamID, protocol.StreamKindTerminal)
}

func (s *typedTerminalStreamSet) isOpen(streamID uint32) bool {
	return s.registry.isOpen(streamID, protocol.StreamKindTerminal)
}

func (s *typedTerminalStreamSet) close(streamID uint32) error {
	if err := s.registry.close(streamID, protocol.StreamKindTerminal); err != nil {
		return err
	}
	if s.open > 0 {
		s.open--
	}
	return nil
}

func (s *typedTerminalStreamSet) closeAll() {
	s.registry.closeKind(protocol.StreamKindTerminal)
	s.open = 0
}
