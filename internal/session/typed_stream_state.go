package session

import (
	"errors"
	"fmt"
)

const maxTerminalStreamsPerConnection = 8

var (
	errTypedStreamIDReserved = errors.New("typed terminal stream ID is reserved")
	errTypedStreamDuplicate  = errors.New("typed terminal stream ID already used")
	errTypedStreamLimit      = errors.New("typed terminal stream limit reached")
	errTypedStreamNotOpen    = errors.New("typed terminal stream is not open")
)

type typedTerminalStreamState uint8

const (
	typedTerminalStreamOpening typedTerminalStreamState = iota + 1
	typedTerminalStreamOpen
	typedTerminalStreamClosed
)

type typedTerminalStreamSet struct {
	states map[uint32]typedTerminalStreamState
	open   int
}

func newTypedTerminalStreamSet() *typedTerminalStreamSet {
	return &typedTerminalStreamSet{states: make(map[uint32]typedTerminalStreamState)}
}

func (s *typedTerminalStreamSet) reserve(streamID uint32) error {
	if streamID <= terminalStreamID {
		return errTypedStreamIDReserved
	}
	if _, exists := s.states[streamID]; exists {
		return errTypedStreamDuplicate
	}
	// Stream 1 remains the legacy/default terminal. Additional typed terminals
	// therefore have one fewer slot than the connection-wide terminal limit.
	if s.open >= maxTerminalStreamsPerConnection-1 {
		return errTypedStreamLimit
	}
	s.states[streamID] = typedTerminalStreamOpening
	s.open++
	return nil
}

func (s *typedTerminalStreamSet) accept(streamID uint32) error {
	if s.states[streamID] != typedTerminalStreamOpening {
		return fmt.Errorf("%w: %d", errTypedStreamNotOpen, streamID)
	}
	s.states[streamID] = typedTerminalStreamOpen
	return nil
}

func (s *typedTerminalStreamSet) isOpen(streamID uint32) bool {
	return s.states[streamID] == typedTerminalStreamOpen
}

func (s *typedTerminalStreamSet) close(streamID uint32) error {
	state, exists := s.states[streamID]
	if !exists || state == typedTerminalStreamClosed {
		return fmt.Errorf("%w: %d", errTypedStreamNotOpen, streamID)
	}
	s.states[streamID] = typedTerminalStreamClosed
	if s.open > 0 {
		s.open--
	}
	return nil
}

func (s *typedTerminalStreamSet) closeAll() {
	for streamID, state := range s.states {
		if state != typedTerminalStreamClosed {
			s.states[streamID] = typedTerminalStreamClosed
		}
	}
	s.open = 0
}
