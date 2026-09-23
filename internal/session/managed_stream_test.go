package session

import (
	"context"
	"testing"
)

func TestManagedTerminalReadPreservesOrderAndFinalBytes(t *testing.T) {
	s := &ManagedTerminal{
		done:         make(chan struct{}),
		outputNotify: make(chan struct{}, 1),
	}
	input := []byte("abcdef")
	if !s.enqueueOutput(input) {
		t.Fatal("enqueue failed")
	}
	input[0] = 'X'

	first, closed, err := s.ReadTerminal(context.Background(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != "abc" || closed {
		t.Fatalf("first read = %q closed=%v", first, closed)
	}

	close(s.done)
	second, closed, err := s.ReadTerminal(context.Background(), managedTerminalChunkLimit)
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != "def" || !closed {
		t.Fatalf("second read = %q closed=%v", second, closed)
	}

	last, closed, err := s.ReadTerminal(context.Background(), managedTerminalChunkLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(last) != 0 || !closed {
		t.Fatalf("final read = %q closed=%v", last, closed)
	}
}

func TestManagedTerminalOutputBufferFailsClosedAtLimit(t *testing.T) {
	s := &ManagedTerminal{
		done:         make(chan struct{}),
		outputNotify: make(chan struct{}, 1),
	}
	if !s.enqueueOutput(make([]byte, managedTerminalOutputLimit)) {
		t.Fatal("buffer rejected payload at exact limit")
	}
	if s.enqueueOutput([]byte{1}) {
		t.Fatal("buffer accepted output beyond limit")
	}
}

func TestManagedTerminalReadHonorsCanceledContext(t *testing.T) {
	s := &ManagedTerminal{
		done:         make(chan struct{}),
		outputNotify: make(chan struct{}, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.ReadTerminal(ctx, managedTerminalChunkLimit); err != context.Canceled {
		t.Fatalf("read error = %v, want context.Canceled", err)
	}
}
