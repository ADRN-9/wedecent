//go:build linux

package routercontrol

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLinuxRouterAdminEndpointIsAbstractUnixSocket(t *testing.T) {
	if !strings.HasPrefix(linuxRouterAdminSocket, "@") {
		t.Fatalf("linux router admin endpoint = %q, want abstract Unix socket", linuxRouterAdminSocket)
	}
	if strings.Contains(linuxRouterAdminSocket, "/") {
		t.Fatalf("linux router admin endpoint = %q, unexpectedly uses filesystem path", linuxRouterAdminSocket)
	}
}

func TestLinuxRouterAdminRoundTrip(t *testing.T) {
	address := fmt.Sprintf("@wedecent-router-admin-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	listener, err := listenLinuxRouterAdmin(address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	if got := listener.Addr().Network(); got != "unix" {
		t.Fatalf("listener network = %q, want unix", got)
	}
	if got := listener.Addr().String(); got != address {
		t.Fatalf("listener address = %q, want %q", got, address)
	}

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		accepted <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dialLinuxRouterAdmin(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	select {
	case err := <-accepted:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestLinuxRouterAdminDialHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := dialLinuxRouterAdmin(ctx, "@wedecent-router-admin-never-used")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("dial returned a connection for canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("dial error = %v, want context.Canceled", err)
	}
}
