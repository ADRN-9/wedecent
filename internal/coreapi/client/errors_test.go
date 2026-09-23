package client

import (
	"context"
	"errors"
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
}
