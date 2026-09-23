package routercontrol

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/trust"
)

func routerControlTestIdentity(t *testing.T, name string) *identity.Identity {
	t.Helper()
	id, err := identity.Ensure(t.TempDir(), name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func routerControlPeer(t *testing.T, id *identity.Identity) trust.Peer {
	t.Helper()
	fingerprint, err := identity.FingerprintPublicKey(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return trust.Peer{
		ID:          id.ID,
		Name:        id.Name,
		Fingerprint: fingerprint,
	}
}

func routerControllerStore(t *testing.T) *trust.Store {
	t.Helper()
	store, err := trust.Open(filepath.Join(t.TempDir(), "trusted-router-controllers.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func routerControlTestPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		accepted <- acceptResult{conn: conn, err: err}
	}()

	client, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	result := <-accepted
	if result.err != nil {
		client.Close()
		t.Fatal(result.err)
	}
	return client, result.conn
}

func TestAuthenticatedRouterAdminChannel(t *testing.T) {
	t.Parallel()

	agent := routerControlTestIdentity(t, "agent")
	controller := routerControlTestIdentity(t, "controller")
	controllers := routerControllerStore(t)
	if err := controllers.Put(routerControlPeer(t, controller)); err != nil {
		t.Fatal(err)
	}

	clientRaw, serverRaw := routerControlTestPipe(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverDone := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := AcceptAuthenticated(ctx, serverRaw, agent, controllers)
		serverDone <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: err}
	}()

	clientConn, err := DialAuthenticated(
		ctx,
		clientRaw,
		controller,
		routerControlPeer(t, agent),
	)
	if err != nil {
		t.Fatalf("DialAuthenticated() error: %v", err)
	}
	defer clientConn.Close()

	serverResult := <-serverDone
	if serverResult.err != nil {
		t.Fatalf("AcceptAuthenticated() error: %v", serverResult.err)
	}
	defer serverResult.conn.Close()

	const payload = "router-admin-authenticated"
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, len(payload))
		_, err := io.ReadFull(serverResult.conn, buf)
		if err == nil && string(buf) != payload {
			err = errors.New("authenticated stream altered payload")
		}
		readDone <- err
	}()

	if _, err := clientConn.Write([]byte(payload)); err != nil {
		t.Fatalf("write authenticated payload: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("read authenticated payload: %v", err)
	}
}

func TestAuthenticatedRouterAdminRejectsUntrustedController(t *testing.T) {
	t.Parallel()

	agent := routerControlTestIdentity(t, "agent")
	controller := routerControlTestIdentity(t, "controller")
	controllers := routerControllerStore(t)

	clientRaw, serverRaw := routerControlTestPipe(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		_, err := AcceptAuthenticated(ctx, serverRaw, agent, controllers)
		serverErr <- err
	}()

	_, _ = DialAuthenticated(
		ctx,
		clientRaw,
		controller,
		routerControlPeer(t, agent),
	)

	select {
	case err := <-serverErr:
		if !errors.Is(err, ErrControllerUntrusted) {
			t.Fatalf("AcceptAuthenticated() error = %v, want ErrControllerUntrusted", err)
		}
	case <-ctx.Done():
		t.Fatal("server did not reject untrusted controller")
	}
}

func TestAuthenticatedRouterAdminRejectsWrongAgentFingerprint(t *testing.T) {
	t.Parallel()

	agent := routerControlTestIdentity(t, "agent")
	controller := routerControlTestIdentity(t, "controller")
	other := routerControlTestIdentity(t, "other")
	controllers := routerControllerStore(t)
	if err := controllers.Put(routerControlPeer(t, controller)); err != nil {
		t.Fatal(err)
	}

	wrongAgent := routerControlPeer(t, agent)
	wrongAgent.Fingerprint = routerControlPeer(t, other).Fingerprint

	clientRaw, serverRaw := routerControlTestPipe(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := AcceptAuthenticated(ctx, serverRaw, agent, controllers)
		if conn != nil {
			_ = conn.Close()
		}
		serverDone <- err
	}()

	_, err := DialAuthenticated(ctx, clientRaw, controller, wrongAgent)
	if !errors.Is(err, ErrPeerIdentityMismatch) {
		t.Fatalf("DialAuthenticated() error = %v, want ErrPeerIdentityMismatch", err)
	}

	select {
	case <-serverDone:
	case <-ctx.Done():
		t.Fatal("server handshake did not finish after client rejection")
	}
}

func TestAuthenticatedRouterAdminRejectsMismatchedControllerFingerprint(t *testing.T) {
	t.Parallel()

	agent := routerControlTestIdentity(t, "agent")
	controller := routerControlTestIdentity(t, "controller")
	other := routerControlTestIdentity(t, "other")
	controllers := routerControllerStore(t)

	trusted := routerControlPeer(t, controller)
	trusted.Fingerprint = routerControlPeer(t, other).Fingerprint
	if err := controllers.Put(trusted); err != nil {
		t.Fatal(err)
	}

	clientRaw, serverRaw := routerControlTestPipe(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		_, err := AcceptAuthenticated(ctx, serverRaw, agent, controllers)
		serverErr <- err
	}()

	_, _ = DialAuthenticated(
		ctx,
		clientRaw,
		controller,
		routerControlPeer(t, agent),
	)

	select {
	case err := <-serverErr:
		if !errors.Is(err, ErrPeerIdentityMismatch) {
			t.Fatalf("AcceptAuthenticated() error = %v, want ErrPeerIdentityMismatch", err)
		}
	case <-ctx.Done():
		t.Fatal("server did not reject fingerprint mismatch")
	}
}
