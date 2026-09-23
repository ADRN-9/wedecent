package client

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/coreapi/ipc"
)

func TestResponseLossIsPossiblyDelivered(t *testing.T) {
	dialer := &scriptedDialer{t: t, handlers: []func(net.Conn){func(conn net.Conn) {
		_, _ = ipc.ReadRequest(conn)
		// Closing without a response proves the client completed its request
		// write but cannot know whether the server acted on it.
	}}}
	client, err := New(Config{
		Dial:    dialer.Dial,
		Timeout: time.Second,
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x91}, 18)),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.GetStatus(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("GetStatus() error = %v; want ErrUnavailable", err)
	}
	var unavailable *UnavailableError
	if !errors.As(err, &unavailable) || unavailable.Stage != UnavailableStageReadResponse {
		t.Fatalf("GetStatus() unavailable = %#v; want read-response stage", unavailable)
	}
	if !RequestMayHaveReachedCore(err) {
		t.Fatal("response loss was not classified as possibly delivered")
	}
}

func TestCanceledResponseReadPreservesDeliveryStage(t *testing.T) {
	requestRead := make(chan struct{})
	release := make(chan struct{})
	dialer := &scriptedDialer{t: t, handlers: []func(net.Conn){func(conn net.Conn) {
		if _, err := ipc.ReadRequest(conn); err != nil {
			return
		}
		close(requestRead)
		<-release
	}}}
	client, err := New(Config{
		Dial:    dialer.Dial,
		Timeout: 5 * time.Second,
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x92}, 18)),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.GetStatus(ctx)
		done <- err
	}()
	select {
	case <-requestRead:
	case <-time.After(time.Second):
		t.Fatal("server did not receive request")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v; want context.Canceled", err)
		}
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("error = %v; want ErrUnavailable stage retained", err)
		}
		var unavailable *UnavailableError
		if !errors.As(err, &unavailable) || unavailable.Stage != UnavailableStageReadResponse {
			t.Fatalf("unavailable = %#v; want read-response stage", unavailable)
		}
		if !RequestMayHaveReachedCore(err) {
			t.Fatal("canceled response read was not classified as possibly delivered")
		}
	case <-time.After(time.Second):
		t.Fatal("client read did not unblock after cancellation")
	}
	close(release)
}
