package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/relayproto"
)

type gatedConn struct {
	net.Conn
	mu      sync.Mutex
	writes  int
	entered chan struct{}
	release chan struct{}
	failed  bool
	once    sync.Once
}

func (c *gatedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	n := c.writes
	c.mu.Unlock()
	if n == 3 {
		c.once.Do(func() { close(c.entered) })
		if c.failed {
			return 0, io.ErrClosedPipe
		}
		<-c.release
	}
	return c.Conn.Write(p)
}

type relayTestHandler struct {
	activated chan struct{}
	once      sync.Once
}

func (h *relayTestHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *relayTestHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Message == "relay slot parked" {
		h.once.Do(func() { close(h.activated) })
	}
	return nil
}
func (h *relayTestHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *relayTestHandler) WithGroup(string) slog.Handler      { return h }

func registerRelayTestAgent(t *testing.T, conn net.Conn) (string, *identity.Identity) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := identity.DeviceID(pub)
	challenge, err := relayproto.Read(conn)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Type != relayproto.TypeChallenge || challenge.Challenge == "" {
		t.Fatalf("challenge = %#v", challenge)
	}
	sig := ed25519.Sign(private, relayproto.RegistrationBytes(challenge.Challenge, id))
	msg := relayproto.Message{
		Type:      relayproto.TypeRegister,
		DeviceID:  id,
		PublicKey: base64.RawStdEncoding.EncodeToString(pub),
		Signature: base64.RawStdEncoding.EncodeToString(sig),
	}
	if err := relayproto.Write(conn, msg); err != nil {
		t.Fatal(err)
	}
	return id, &identity.Identity{ID: id, PublicKey: pub, PrivateKey: private}
}

func TestServerDoesNotPublishSlotBeforeWaitingAcknowledgementCompletes(t *testing.T) {
	broker := NewBroker(2, time.Minute)
	handler := &relayTestHandler{activated: make(chan struct{})}
	server := &Server{Broker: broker, Logger: slog.New(handler)}
	serverSide, clientSide := net.Pipe()
	gated := &gatedConn{Conn: serverSide, entered: make(chan struct{}), release: make(chan struct{})}
	serverDone := make(chan struct{})
	go func() {
		server.ServeConn(gated)
		close(serverDone)
	}()
	deviceID, _ := registerRelayTestAgent(t, clientSide)
	select {
	case <-gated.entered:
	case <-time.After(time.Second):
		t.Fatal("registration acknowledgement write did not reach barrier")
	}
	if _, err := broker.Take(deviceID); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("slot was claimable before acknowledgement: %v", err)
	}
	close(gated.release)
	waiting, err := relayproto.Read(clientSide)
	if err != nil || waiting.Type != relayproto.TypeWaiting {
		t.Fatalf("waiting acknowledgement = %#v, %v", waiting, err)
	}
	select {
	case <-handler.activated:
	case <-time.After(time.Second):
		t.Fatal("slot was not activated after acknowledgement")
	}
	slot, err := broker.Take(deviceID)
	if err != nil {
		t.Fatalf("slot unavailable after acknowledgement: %v", err)
	}
	slot.finish()
	_ = slot.conn.Close()
	_ = clientSide.Close()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server did not stop after slot completion")
	}
}

func TestServerRemovesReservationWhenWaitingAcknowledgementFails(t *testing.T) {
	broker := NewBroker(1, time.Minute)
	server := &Server{Broker: broker}
	serverSide, clientSide := net.Pipe()
	gated := &gatedConn{Conn: serverSide, entered: make(chan struct{}), release: make(chan struct{}), failed: true}
	serverDone := make(chan struct{})
	go func() {
		server.ServeConn(gated)
		close(serverDone)
	}()
	deviceID, _ := registerRelayTestAgent(t, clientSide)
	select {
	case <-gated.entered:
	case <-time.After(time.Second):
		t.Fatal("registration acknowledgement write did not reach failure gate")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server did not return after failed acknowledgement")
	}
	if _, err := broker.Take(deviceID); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("failed acknowledgement left claimable slot: %v", err)
	}
	_ = clientSide.Close()
}

func TestServerRemovesParkedSlotAfterPeerDisconnect(t *testing.T) {
	broker := NewBroker(1, time.Minute)
	handler := &relayTestHandler{activated: make(chan struct{})}
	server := &Server{Broker: broker, Logger: slog.New(handler)}
	serverSide, clientSide := net.Pipe()
	serverDone := make(chan struct{})
	go func() {
		server.ServeConn(serverSide)
		close(serverDone)
	}()
	deviceID, _ := registerRelayTestAgent(t, clientSide)
	select {
	case <-handler.activated:
	case <-time.After(time.Second):
		t.Fatal("registration did not activate")
	}
	broker.mu.Lock()
	var parked *slot
	for _, candidate := range broker.slots[deviceID] {
		parked = candidate
	}
	broker.mu.Unlock()
	if parked == nil {
		t.Fatal("active slot missing from broker")
	}
	_ = clientSide.Close()
	select {
	case <-parked.done:
	case <-time.After(time.Second):
		t.Fatal("peer disconnect did not remove and finish slot")
	}
	if _, err := broker.Take(deviceID); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("disconnected slot remained claimable: %v", err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server did not stop after peer disconnect")
	}
}
