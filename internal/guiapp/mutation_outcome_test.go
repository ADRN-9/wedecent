package guiapp

import (
	"context"
	"errors"
	"testing"

	coreclient "wedecent.com/wedecent/internal/coreapi/client"
	"wedecent.com/wedecent/internal/coreapi/ipc"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type markedMutationError struct {
	err error
}

func (e *markedMutationError) Error() string { return "mutation outcome unknown: " + e.err.Error() }
func (e *markedMutationError) Unwrap() error { return e.err }
func (e *markedMutationError) MutationOutcomeUnknown() bool {
	return true
}

func TestControllerPreservesMarkedMutationUncertaintyWhileClearingGoneSession(t *testing.T) {
	gone := &coreclient.RemoteError{Code: ipc.ErrorConnectionNotFound, Message: "connection not found"}
	marked := &markedMutationError{err: gone}
	core := &fakeCore{
		connection: v1.Connection{ID: "conn_stale", DeviceID: "wd_peer0000000000", State: v1.ConnectionStateConnected},
		writeErr:   marked,
	}
	controller, err := New(core)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Connect(context.Background(), "wd_peer0000000000"); err != nil {
		t.Fatal(err)
	}

	err = controller.WriteTerminal(context.Background(), []byte("payload"))
	if !errors.Is(err, gone) {
		t.Fatalf("WriteTerminal() error = %v; want original marked error chain", err)
	}
	if errors.Is(err, ErrSessionLost) {
		t.Fatalf("WriteTerminal() error = %v; marked uncertainty was replaced by ErrSessionLost", err)
	}
	if !isMutationOutcomeUnknown(err) {
		t.Fatalf("WriteTerminal() error = %v; mutation marker was lost", err)
	}
	if _, ok := controller.ActiveConnection(); ok {
		t.Fatal("connection_not_found inside marked mutation error left stale session active")
	}
}
