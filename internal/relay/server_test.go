package relay

import (
	"bytes"
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
	waiting, err := relayproto.Read(clientSide)
	if err != nil || waiting.Type != relayproto.TypeWaiting {
		t.Fatalf("waiting acknowledgement = %#v, %v", waiting, err)
	}
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


func TestRelayRegistrationToSessionHandoffPreservesApplicationBytes(t *testing.T) {
	broker := NewBroker(2, time.Minute)
	handler := &relayTestHandler{activated: make(chan struct{})}
	server := &Server{Broker: broker, Logger: slog.New(handler)}

	agentServer, agentPeer := net.Pipe()
	agentDone := make(chan struct{})
	go func() {
		server.ServeConn(agentServer)
		close(agentDone)
	}()
	deviceID, _ := registerRelayTestAgent(t, agentPeer)
	waiting, err := relayproto.Read(agentPeer)
	if err != nil || waiting.Type != relayproto.TypeWaiting {
		t.Fatalf("registration acknowledgement = %#v, %v", waiting, err)
	}
	select {
	case <-handler.activated:
	case <-time.After(time.Second):
		t.Fatal("registered agent was not activated")
	}

	clientServer, clientPeer := net.Pipe()
	clientDone := make(chan struct{})
	go func() {
		server.ServeConn(clientServer)
		close(clientDone)
	}()
	challenge, err := relayproto.Read(clientPeer)
	if err != nil || challenge.Type != relayproto.TypeChallenge {
		t.Fatalf("client challenge = %#v, %v", challenge, err)
	}
	if err := relayproto.Write(clientPeer, relayproto.Message{Type: relayproto.TypeConnect, DeviceID: deviceID}); err != nil {
		t.Fatal(err)
	}

	agentReady, err := relayproto.Read(agentPeer)
	if err != nil || agentReady.Type != relayproto.TypeReady {
		t.Fatalf("agent ready = %#v, %v", agentReady, err)
	}
	clientReady, err := relayproto.Read(clientPeer)
	if err != nil || clientReady.Type != relayproto.TypeReady {
		t.Fatalf("client ready = %#v, %v", clientReady, err)
	}

	payload := []byte("valid-session-application-frame\x00\xff")
	writeDone := make(chan error, 1)
	go func() {
		_, err := agentPeer.Write(payload)
		writeDone <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(clientPeer, got); err != nil {
		t.Fatalf("read application payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("bridged application bytes = %x, want %x", got, payload)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write application payload: %v", err)
	}

	_ = agentPeer.Close()
	_ = clientPeer.Close()
	for name, done := range map[string]<-chan struct{}{"agent": agentDone, "client": clientDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s relay handler did not terminate", name)
		}
	}
}

func TestPrematureAgentApplicationBytesFailClosedBeforeConnect(t *testing.T) {
	broker := NewBroker(1, time.Minute)
	handler := &relayTestHandler{activated: make(chan struct{})}
	server := &Server{Broker: broker, Logger: slog.New(handler)}

	agentServer, agentPeer := net.Pipe()
	agentDone := make(chan struct{})
	go func() {
		server.ServeConn(agentServer)
		close(agentDone)
	}()
	deviceID, _ := registerRelayTestAgent(t, agentPeer)
	waiting, err := relayproto.Read(agentPeer)
	if err != nil || waiting.Type != relayproto.TypeWaiting {
		t.Fatalf("registration acknowledgement = %#v, %v", waiting, err)
	}
	select {
	case <-handler.activated:
	case <-time.After(time.Second):
		t.Fatal("registered agent was not activated")
	}
	broker.mu.Lock()
	var parked *slot
	for _, candidate := range broker.slots[deviceID] {
		parked = candidate
	}
	broker.mu.Unlock()
	if parked == nil {
		t.Fatal("active relay slot missing")
	}

	// The agent protocol forbids application data until TypeReady.
	if _, err := agentPeer.Write([]byte("premature")); err != nil {
		t.Fatalf("premature probe did not reach watcher: %v", err)
	}
	select {
	case <-parked.done:
	case <-time.After(time.Second):
		t.Fatal("premature application bytes did not close the parked slot")
	}

	clientServer, clientPeer := net.Pipe()
	clientDone := make(chan struct{})
	go func() {
		server.ServeConn(clientServer)
		close(clientDone)
	}()
	challenge, err := relayproto.Read(clientPeer)
	if err != nil || challenge.Type != relayproto.TypeChallenge {
		t.Fatalf("client challenge = %#v, %v", challenge, err)
	}
	if err := relayproto.Write(clientPeer, relayproto.Message{Type: relayproto.TypeConnect, DeviceID: deviceID}); err != nil {
		t.Fatal(err)
	}
	rejected, err := relayproto.Read(clientPeer)
	if err != nil || rejected.Type != relayproto.TypeError || rejected.Code != "unavailable" {
		t.Fatalf("premature-data session result = %#v, %v; want unavailable error", rejected, err)
	}
	_ = clientPeer.Close()
	_ = agentPeer.Close()
	for name, done := range map[string]<-chan struct{}{"agent": agentDone, "client": clientDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s relay handler did not terminate", name)
		}
	}
}


func TestServeConnContextCancelsInitialProtocolRead(t *testing.T) {
	server := &Server{Broker: NewBroker(1, time.Minute)}
	serverSide, peer := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		server.ServeConnContext(ctx, serverSide)
		close(done)
	}()
	challenge, err := relayproto.Read(peer)
	if err != nil || challenge.Type != relayproto.TypeChallenge {
		t.Fatalf("challenge = %#v, %v", challenge, err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt initial relay protocol read")
	}
	_ = peer.Close()
}

func TestServeConnContextTimesOutInitialProtocolRead(t *testing.T) {
	server := &Server{Broker: NewBroker(1, time.Minute), ReadTimeout: 25 * time.Millisecond}
	serverSide, peer := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.ServeConnContext(context.Background(), serverSide)
		close(done)
	}()
	challenge, err := relayproto.Read(peer)
	if err != nil || challenge.Type != relayproto.TypeChallenge {
		t.Fatalf("challenge = %#v, %v", challenge, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("initial relay protocol read did not time out")
	}
	_ = peer.Close()
}


func TestReadRelayControlMessageTimeoutsAtHeaderAndPayload(t *testing.T) {
	for _, stage := range []string{"header", "payload"} {
		t.Run(stage, func(t *testing.T) {
			server, peer := net.Pipe()
			defer server.Close()
			defer peer.Close()
			result := make(chan error, 1)
			go func() {
				_, err := readRelayControlMessage(context.Background(), server, 25*time.Millisecond)
				result <- err
			}()
			if stage == "payload" {
				if _, err := peer.Write([]byte{0, 0, 0, 8}); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-result:
				var netErr net.Error
				if !errors.As(err, &netErr) || !netErr.Timeout() {
					t.Fatalf("read error = %v, want timeout", err)
				}
			case <-time.After(time.Second):
				t.Fatal("relay control read did not time out")
			}
		})
	}
}

func TestReadRelayControlMessageCancellationAtHeaderAndPayload(t *testing.T) {
	for _, stage := range []string{"header", "payload"} {
		t.Run(stage, func(t *testing.T) {
			server, peer := net.Pipe()
			defer server.Close()
			defer peer.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := readRelayControlMessage(ctx, server, time.Hour)
				result <- err
			}()
			if stage == "payload" {
				if _, err := peer.Write([]byte{0, 0, 0, 8}); err != nil {
					t.Fatal(err)
				}
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("read error = %v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt relay control read")
			}
		})
	}
}
