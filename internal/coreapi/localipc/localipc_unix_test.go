//go:build aix || android || darwin || dragonfly || freebsd || ios || linux || netbsd || openbsd || solaris

package localipc

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixListenDialRoundTripAndPermissions(t *testing.T) {
	t.Setenv("WEDECENT_HOME", t.TempDir())

	listener, err := Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	path, err := Endpoint()
	if err != nil {
		t.Fatal(err)
	}
	assertMode(t, filepath.Dir(path), 0o700)
	assertMode(t, path, 0o600)

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

func TestUnixEndpointRejectsRelativeCoreHome(t *testing.T) {
	t.Setenv("WEDECENT_HOME", "relative-state")
	if _, err := Endpoint(); !errors.Is(err, ErrUnsafeEndpoint) {
		t.Fatalf("Endpoint() error = %v, want ErrUnsafeEndpoint", err)
	}
}

func TestUnixListenRejectsUnsafeExistingEndpoint(t *testing.T) {
	base := t.TempDir()
	t.Setenv("WEDECENT_HOME", base)
	path, err := Endpoint()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(); !errors.Is(err, ErrUnsafeEndpoint) {
		t.Fatalf("Listen() error = %v, want ErrUnsafeEndpoint", err)
	}
}

func TestUnixListenRejectsSecondLiveListener(t *testing.T) {
	t.Setenv("WEDECENT_HOME", t.TempDir())
	listener, err := Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	if _, err := Listen(); !errors.Is(err, ErrEndpointInUse) {
		t.Fatalf("second Listen() error = %v, want ErrEndpointInUse", err)
	}
}

func TestUnixDialHonorsCanceledContext(t *testing.T) {
	t.Setenv("WEDECENT_HOME", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Dial(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial() error = %v, want context.Canceled", err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %#o, want %#o", path, got, want)
	}
}
