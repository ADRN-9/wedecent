package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/coreapi/ipc"
)

func TestLifecycleErrorClassification(t *testing.T) {
	gone := &RemoteError{Code: ipc.ErrorConnectionNotFound, Message: "connection not found"}
	if !IsConnectionGone(gone) {
		t.Fatal("connection_not_found was not classified as gone")
	}
	if IsUnavailable(gone) {
		t.Fatal("connection_not_found was incorrectly classified as unavailable")
	}

	unavailable := &RemoteError{Code: ipc.ErrorConnectionUnavailable, Message: "connection service is unavailable"}
	if !IsUnavailable(unavailable) {
		t.Fatal("connection_unavailable was not classified as unavailable")
	}
	if IsConnectionGone(unavailable) {
		t.Fatal("connection_unavailable was incorrectly classified as gone")
	}
}

func TestUnavailableDeliveryClassification(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		mayReach   bool
		wantStage  UnavailableStage
		stageKnown bool
	}{
		{name: "dial", err: &UnavailableError{Stage: UnavailableStageDial}, mayReach: false, wantStage: UnavailableStageDial, stageKnown: true},
		{name: "deadline", err: &UnavailableError{Stage: UnavailableStageSetDeadline}, mayReach: false, wantStage: UnavailableStageSetDeadline, stageKnown: true},
		{name: "write", err: &UnavailableError{Stage: UnavailableStageWriteRequest}, mayReach: true, wantStage: UnavailableStageWriteRequest, stageKnown: true},
		{name: "read", err: &UnavailableError{Stage: UnavailableStageReadResponse}, mayReach: true, wantStage: UnavailableStageReadResponse, stageKnown: true},
		{name: "unknown typed", err: &UnavailableError{Stage: UnavailableStageUnknown}, mayReach: true, wantStage: UnavailableStageUnknown, stageKnown: true},
		{name: "legacy wrapper", err: fmt.Errorf("%w: legacy", ErrUnavailable), mayReach: true},
		{name: "other", err: errors.New("other"), mayReach: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RequestMayHaveReachedCore(tt.err); got != tt.mayReach {
				t.Fatalf("RequestMayHaveReachedCore() = %v, want %v", got, tt.mayReach)
			}
			if !tt.stageKnown {
				return
			}
			var unavailable *UnavailableError
			if !errors.As(tt.err, &unavailable) || unavailable.Stage != tt.wantStage {
				t.Fatalf("UnavailableError = %#v, want stage %v", unavailable, tt.wantStage)
			}
			if !errors.Is(tt.err, ErrUnavailable) {
				t.Fatal("typed unavailable error does not match ErrUnavailable")
			}
		})
	}
}

func TestDialFailureIsUnavailable(t *testing.T) {
	client, err := New(Config{
		Dial: func(context.Context) (net.Conn, error) {
			return nil, errors.New("pipe absent")
		},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.GetStatus(context.Background())
	if !errors.Is(err, ErrUnavailable) || !IsUnavailable(err) {
		t.Fatalf("dial error = %v, want unavailable", err)
	}
	var unavailable *UnavailableError
	if !errors.As(err, &unavailable) || unavailable.Stage != UnavailableStageDial {
		t.Fatalf("dial error = %#v, want dial stage", err)
	}
	if RequestMayHaveReachedCore(err) {
		t.Fatal("dial failure was incorrectly classified as possibly delivered")
	}
}
