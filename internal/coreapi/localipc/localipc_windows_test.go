//go:build windows

package localipc

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestWindowsSIDDerivedEndpointAndDescriptor(t *testing.T) {
	const sid = "S-1-5-21-111-222-333-1001"

	first, err := pipeNameForSID(sid)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pipeNameForSID(sid)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("pipe names differ: %q != %q", first, second)
	}
	if !strings.HasPrefix(first, windowsPipePrefix) {
		t.Fatalf("pipe name = %q, missing prefix", first)
	}
	if strings.Contains(first, sid) {
		t.Fatalf("pipe name exposes raw SID: %q", first)
	}

	sddl, err := securityDescriptorForSID(sid)
	if err != nil {
		t.Fatal(err)
	}
	if want := "D:P(A;;GA;;;" + sid + ")"; sddl != want {
		t.Fatalf("SDDL = %q, want %q", sddl, want)
	}
}

func TestWindowsRejectsUnsafeSIDText(t *testing.T) {
	for _, sid := range []string{
		"",
		"S-1",
		"S-1-5);(A;;GA;;;WD",
		"S-1-5-21-abc",
		"S-1-5-21-",
	} {
		if _, err := pipeNameForSID(sid); !errors.Is(err, ErrUnsafeEndpoint) {
			t.Fatalf("pipeNameForSID(%q) error = %v, want ErrUnsafeEndpoint", sid, err)
		}
	}
}

func TestWindowsListenDialRoundTrip(t *testing.T) {
	listener, err := Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverErr <- err
			return
		}
		if string(buf) != "ping" {
			serverErr <- errors.New("unexpected request")
			return
		}
		_, err = conn.Write([]byte("pong"))
		serverErr <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "pong" {
		t.Fatalf("response = %q", response)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestWindowsDialHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Dial(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial() error = %v, want context.Canceled", err)
	}
}
