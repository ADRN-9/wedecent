package portforward

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/trust"
)

func TestManagerTrustStoreRevocationTerminatesParentAndChildStreams(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	store, err := trust.Open(filepath.Join(t.TempDir(), "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(trust.Peer{ID: string(testDestination), Fingerprint: "test-fingerprint"}); err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := testClaims(now, DirectionLocal)
	auth, err := SignAuthorization(privateKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	replay := NewMemoryReplay(8)
	replay.Now = func() time.Time { return now }
	listener := newQueueListener()
	connector := &pipeConnector{opened: make(chan net.Conn, 1)}
	manager, err := NewManager(ManagerConfig{
		LocalDeviceID: testInitiator,
		Verifier: AuthorizationVerifier{PublicKey: publicKey, Replay: replay, Now: func() time.Time { return now }},
		TrustChecker: store,
		TrustPollInterval: 20 * time.Millisecond,
		PermissionAuthorizer: allowPortForwardPermission{},
		Connector: connector,
		Audit: &memoryAudit{},
		Limits: managerTestLimits(),
		Listen: func(string, string) (net.Listener, error) { return listener, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	if _, err := manager.Start(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	client, core := net.Pipe()
	if !listener.inject(core) {
		t.Fatal("listener rejected child connection")
	}
	var remote net.Conn
	select {
	case remote = <-connector.opened:
	case <-time.After(time.Second):
		t.Fatal("child stream was not opened")
	}
	defer remote.Close()

	if len(manager.List()) != 1 {
		t.Fatal("forward did not become active")
	}
	if _, err := store.DeletePeer(string(testDestination)); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(2 * time.Second)
	for len(manager.List()) != 0 {
		select {
		case <-deadline:
			t.Fatal("trust-store revocation did not stop forwarding")
		case <-time.After(10 * time.Millisecond):
		}
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("child connection remained active after trust revocation")
	}
	_ = client.Close()
}

func TestManagerFailsClosedWhenPeerTrustStoreCannotBeRead(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	path := filepath.Join(t.TempDir(), "trusted-devices.json")
	store, err := trust.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(trust.Peer{ID: string(testDestination), Fingerprint: "test-fingerprint"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.IsTrusted(context.Background(), string(testDestination)); err == nil {
		t.Fatal("corrupt trust store was treated as readable")
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := testClaims(now, DirectionLocal)
	auth, err := SignAuthorization(privateKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	replay := NewMemoryReplay(8)
	replay.Now = func() time.Time { return now }
	listener := newQueueListener()
	manager, err := NewManager(ManagerConfig{
		LocalDeviceID: testInitiator,
		Verifier: AuthorizationVerifier{PublicKey: publicKey, Replay: replay, Now: func() time.Time { return now }},
		TrustChecker: store,
		TrustPollInterval: 20 * time.Millisecond,
		PermissionAuthorizer: allowPortForwardPermission{},
		Connector: &pipeConnector{},
		Audit: &memoryAudit{},
		Limits: managerTestLimits(),
		Listen: func(string, string) (net.Listener, error) { return listener, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, err := manager.Start(context.Background(), auth); !errors.Is(err, ErrPeerNotTrusted) {
		t.Fatalf("Start error = %v, want fail-closed peer trust error", err)
	}
	if len(manager.List()) != 0 {
		t.Fatal("unreadable peer trust store allowed a forward")
	}
}
