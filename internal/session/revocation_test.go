package session

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/trust"
)

const revocationTestJTI = "00000000-0000-4000-8000-000000000001"

type revocationTestPTY struct {
	closed chan struct{}
	once   sync.Once
}

func newRevocationTestPTY() *revocationTestPTY {
	return &revocationTestPTY{closed: make(chan struct{})}
}

func (p *revocationTestPTY) Read([]byte) (int, error) {
	<-p.closed
	return 0, io.EOF
}

func (p *revocationTestPTY) Write(data []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, io.ErrClosedPipe
	default:
		return len(data), nil
	}
}

func (p *revocationTestPTY) Resize(uint16, uint16) error { return nil }

func (p *revocationTestPTY) Wait() error {
	<-p.closed
	return nil
}

func (p *revocationTestPTY) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

type revocationTestAuthorizer struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (a *revocationTestAuthorizer) Authorize(ctx context.Context, _, _, _ string) error {
	if a.entered != nil {
		a.once.Do(func() { close(a.entered) })
		select {
		case <-a.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (a *revocationTestAuthorizer) VerifyConsumptionEvidence(_ context.Context, clientID, targetID, jti, flow string) (GrantConsumptionEvidence, error) {
	return GrantConsumptionEvidence{
		Version:              1,
		AuthorizationRunID:   "00000000-0000-4000-8000-000000000010",
		ValidationAttemptID:  "00000000-0000-4000-8000-000000000011",
		ConsumptionAttemptID: "00000000-0000-4000-8000-000000000012",
		ValidationEventID:    "00000000-0000-4000-8000-000000000013",
		ConsumptionEventID:   "00000000-0000-4000-8000-000000000014",
		GrantID:              "00000000-0000-4000-8000-000000000015",
		JTI:                  jti,
		ClientDeviceID:       clientID,
		TargetDeviceID:       targetID,
		Permission:           "terminal.connect",
		Flow:                 flow,
		ValidationOutcome:    "accepted",
		ConsumptionOutcome:   "consumed",
	}, nil
}

type revocationTestRig struct {
	t                 *testing.T
	server            *Server
	serverID          *identity.Identity
	serverFingerprint string
	stateDir          string
	trustPath         string
	mu                sync.Mutex
	ptys              []*revocationTestPTY
}

func newRevocationTestRig(t *testing.T, authorizer *revocationTestAuthorizer) *revocationTestRig {
	t.Helper()
	serverID, err := identity.Ensure(t.TempDir(), "server")
	if err != nil {
		t.Fatal(err)
	}
	serverFingerprint, err := identity.FingerprintPublicKey(serverID.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	trustPath := filepath.Join(stateDir, "trusted-clients.json")
	store, err := trust.Open(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	rig := &revocationTestRig{
		t:                 t,
		serverID:          serverID,
		serverFingerprint: serverFingerprint,
		stateDir:          stateDir,
		trustPath:         trustPath,
	}
	rig.server = &Server{
		Identity:         serverID,
		Trust:            store,
		StateDir:         stateDir,
		DirectAuthorizer: authorizer,
	}
	rig.server.terminalStart = func(string, uint16, uint16, string) (terminalSessionPTY, error) {
		pty := newRevocationTestPTY()
		rig.mu.Lock()
		rig.ptys = append(rig.ptys, pty)
		rig.mu.Unlock()
		return pty, nil
	}
	return rig
}

func (r *revocationTestRig) addClient(name string) *identity.Identity {
	r.t.Helper()
	client, err := identity.Ensure(r.t.TempDir(), name)
	if err != nil {
		r.t.Fatal(err)
	}
	fingerprint, err := identity.FingerprintPublicKey(client.PublicKey)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.server.Trust.Put(trust.Peer{ID: client.ID, Name: client.Name, Fingerprint: fingerprint}); err != nil {
		r.t.Fatal(err)
	}
	return client
}

func (r *revocationTestRig) dial(client *identity.Identity, kind TransportKind) *tls.Conn {
	r.t.Helper()
	clientRaw, serverRaw := net.Pipe()
	if kind == TransportWebSocketRelay {
		go r.server.ServeParkedRelayConn(serverRaw)
	} else {
		go r.server.ServeConnWithTransport(serverRaw, TransportMetadata{Kind: kind})
	}
	conn := tls.Client(clientRaw, identity.ClientTLS(client, r.serverFingerprint))
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		r.t.Fatal(err)
	}
	if err := conn.Handshake(); err != nil {
		r.t.Fatal(err)
	}
	return conn
}

func (r *revocationTestRig) sendOpen(conn *tls.Conn, kind TransportKind, typed bool) error {
	r.t.Helper()
	var capabilities []protocol.Capability
	if typed {
		capabilities = []protocol.Capability{protocol.CapabilityTypedStreamsV1}
	}
	var frame protocol.Frame
	if kind == TransportWebSocketRelay {
		payload, err := protocol.JSON(protocol.OpenSession{
			Cols: 80, Rows: 24, Term: "xterm-256color", GrantJTI: revocationTestJTI, Capabilities: capabilities,
		})
		if err != nil {
			return err
		}
		frame = protocol.Frame{Type: protocol.TypeOpenSession, Payload: payload}
	} else {
		payload, err := protocol.JSON(protocol.OpenAuthorizedSession{
			Cols: 80, Rows: 24, Term: "xterm-256color", ConnectionGrant: revocationTestGrant(), Capabilities: capabilities,
		})
		if err != nil {
			return err
		}
		frame = protocol.Frame{Type: protocol.TypeOpenAuthorizedSession, Payload: payload}
	}
	return protocol.WriteFrame(conn, frame)
}

func (r *revocationTestRig) readAccepted(conn *tls.Conn) error {
	r.t.Helper()
	frame, err := protocol.ReadFrame(conn)
	if err != nil {
		return err
	}
	if frame.Type == protocol.TypeError {
		var protocolErr protocol.Error
		if err := protocol.ParseJSON(frame.Payload, &protocolErr); err != nil {
			return err
		}
		return errors.New(protocolErr.Code)
	}
	if frame.Type != protocol.TypeSessionAccepted {
		return errors.New("session was not accepted")
	}
	return nil
}

func (r *revocationTestRig) open(client *identity.Identity, kind TransportKind, typed bool) (*tls.Conn, error) {
	r.t.Helper()
	conn := r.dial(client, kind)
	if err := r.sendOpen(conn, kind, typed); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := r.readAccepted(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (r *revocationTestRig) ptyAt(index int) *revocationTestPTY {
	r.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		if index < len(r.ptys) {
			pty := r.ptys[index]
			r.mu.Unlock()
			return pty
		}
		r.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	r.t.Fatalf("PTY %d was not started", index)
	return nil
}

func revocationTestGrant() string {
	payload, _ := json.Marshal(map[string]string{"jti": revocationTestJTI})
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func waitRevocationConnectionClosed(t *testing.T, conn *tls.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		_, err := protocol.ReadFrame(conn)
		if err == nil {
			// A PTY may finish concurrently and emit its final close frame.
			continue
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatal("revoked terminal connection remained open")
		}
		return
	}
}

func waitRevocationPTYClosed(t *testing.T, pty *revocationTestPTY) {
	t.Helper()
	select {
	case <-pty.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("revocation did not close the PTY/ConPTY resource")
	}
}

func readRevocationAudit(t *testing.T, stateDir string) []audit.Event {
	t.Helper()
	file, err := os.Open(filepath.Join(stateDir, audit.FileName))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var events []audit.Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event audit.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

func waitRevocationSessionsIdle(t *testing.T, server *Server) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		server.activeSessionsMu.Lock()
		activeCount := len(server.activeSessions)
		watcherRunning := server.activeSessionsRunning
		server.activeSessionsMu.Unlock()
		if activeCount == 0 && !watcherRunning {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("active terminal session watcher did not stop after all sessions finished")
}

func waitRevocationAuditEvents(t *testing.T, stateDir string, ready func([]audit.Event) bool) []audit.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		events := readRevocationAudit(t, stateDir)
		if ready(events) {
			return events
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected revocation audit events were not persisted")
	return nil
}

func TestRevocationTerminatesOnlyTargetClientAcrossTerminalTransports(t *testing.T) {
	rig := newRevocationTestRig(t, &revocationTestAuthorizer{})
	clientA := rig.addClient("client-a")
	clientB := rig.addClient("client-b")

	type active struct {
		conn      *tls.Conn
		pty       *revocationTestPTY
		transport string
	}
	sessions := []active{}
	for _, kind := range []TransportKind{TransportDirectTCP, TransportRawRelay, TransportWebSocketRelay} {
		conn, err := rig.open(clientA, kind, false)
		if err != nil {
			t.Fatalf("open %s session: %v", kind, err)
		}
		sessions = append(sessions, active{conn: conn, pty: rig.ptyAt(len(sessions)), transport: string(kind)})
	}
	unrelated, err := rig.open(clientB, TransportDirectTCP, false)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedPTY := rig.ptyAt(3)

	if _, err := trust.Revoke(rig.trustPath, clientA.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := rig.server.Trust.Lookup(clientA.ID); err != nil || ok {
		t.Fatalf("revoked client remained in the server trust snapshot: trusted=%v err=%v", ok, err)
	}
	for _, item := range sessions {
		waitRevocationPTYClosed(t, item.pty)
		waitRevocationConnectionClosed(t, item.conn)
		_ = item.conn.Close()
	}

	if err := protocol.WriteFrame(unrelated, protocol.Frame{Type: protocol.TypePing}); err != nil {
		t.Fatalf("unrelated client was disconnected: %v", err)
	}
	frame, err := protocol.ReadFrame(unrelated)
	if err != nil || frame.Type != protocol.TypePong {
		t.Fatalf("unrelated client ping response = %#v, %v", frame, err)
	}
	select {
	case <-unrelatedPTY.closed:
		t.Fatal("unrelated client's PTY was terminated")
	default:
	}

	reconnect, err := rig.open(clientA, TransportDirectTCP, false)
	if err == nil {
		_ = reconnect.Close()
		t.Fatal("revoked client reconnected successfully")
	}
	if !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("reconnection error = %v, want unauthorized", err)
	}

	if _, err := trust.Revoke(rig.trustPath, clientB.ID); err != nil {
		t.Fatal(err)
	}
	waitRevocationConnectionClosed(t, unrelated)
	waitRevocationPTYClosed(t, unrelatedPTY)
	_ = unrelated.Close()

	events := waitRevocationAuditEvents(t, rig.stateDir, func(events []audit.Event) bool {
		terminated, closed := 0, 0
		for _, event := range events {
			if event.PeerID != clientA.ID {
				continue
			}
			if event.Type == "terminal.session_terminated" {
				terminated++
			}
			if event.Type == "terminal.session_closed" {
				closed++
			}
		}
		return terminated == 3 && closed == 3
	})
	terminated := map[string]audit.Event{}
	closed := map[string]audit.Event{}
	for _, event := range events {
		if event.PeerID != clientA.ID {
			continue
		}
		switch event.Type {
		case "terminal.session_terminated":
			terminated[event.SessionID] = event
		case "terminal.session_closed":
			closed[event.SessionID] = event
		}
	}
	if len(terminated) != 3 || len(closed) != 3 {
		t.Fatalf("revocation audit counts: terminated=%d closed=%d, want 3 each", len(terminated), len(closed))
	}
	for _, item := range sessions {
		var sessionID string
		for id, event := range terminated {
			if event.Transport == item.transport {
				sessionID = id
				break
			}
		}
		if len(sessionID) != 36 {
			t.Fatalf("missing attributable termination event for %s: %#v", item.transport, terminated)
		}
		event := terminated[sessionID]
		if event.ActorID != rig.serverID.ID || event.PeerID != clientA.ID || event.Reason != "client_revoked" {
			t.Fatalf("incorrect termination audit: %+v", event)
		}
		if closeEvent, ok := closed[sessionID]; !ok || closeEvent.Reason != "client_revoked" || closeEvent.PeerID != clientA.ID {
			t.Fatalf("missing matching session-closed audit for %s: %+v", sessionID, closeEvent)
		}
	}
	waitRevocationSessionsIdle(t, rig.server)
}

func TestRevocationClosesTypedTerminalPTYs(t *testing.T) {
	rig := newRevocationTestRig(t, &revocationTestAuthorizer{})
	client := rig.addClient("typed-client")
	conn, err := rig.open(client, TransportDirectTCP, true)
	if err != nil {
		t.Fatal(err)
	}
	openPayload, err := protocol.JSON(protocol.StreamOpen{
		Kind: protocol.StreamKindTerminal, Cols: 80, Rows: 24, Term: "xterm-256color", InitialWindow: 64 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeStreamOpen, StreamID: 2, Payload: openPayload}); err != nil {
		t.Fatal(err)
	}
	accepted, err := protocol.ReadFrame(conn)
	if err != nil || accepted.Type != protocol.TypeStreamAccepted {
		t.Fatalf("typed terminal stream acceptance = %#v, %v", accepted, err)
	}
	pty := rig.ptyAt(0)
	if _, err := trust.Revoke(rig.trustPath, client.ID); err != nil {
		t.Fatal(err)
	}
	waitRevocationConnectionClosed(t, conn)
	waitRevocationPTYClosed(t, pty)
	_ = conn.Close()

	events := waitRevocationAuditEvents(t, rig.stateDir, func(events []audit.Event) bool {
		for _, event := range events {
			if event.Type == "terminal.stream_closed" && event.PeerID == client.ID && event.Reason == "client_revoked" && event.StreamID == 2 {
				return true
			}
		}
		return false
	})
	found := false
	for _, event := range events {
		if event.Type == "terminal.stream_closed" && event.PeerID == client.ID && event.Reason == "client_revoked" && event.StreamID == 2 {
			found = true
		}
	}
	if !found {
		t.Fatal("typed terminal stream termination was not audited")
	}
	waitRevocationSessionsIdle(t, rig.server)
}

func TestRevocationIsNotMissedWhenClientIsRepairedImmediately(t *testing.T) {
	rig := newRevocationTestRig(t, &revocationTestAuthorizer{})
	client := rig.addClient("repair-race-client")
	conn, err := rig.open(client, TransportDirectTCP, false)
	if err != nil {
		t.Fatal(err)
	}
	pty := rig.ptyAt(0)
	before, ok := rig.server.Trust.Get(client.ID)
	if !ok || before.Generation == "" {
		t.Fatal("active session has no trust generation")
	}
	if _, err := trust.Revoke(rig.trustPath, client.ID); err != nil {
		t.Fatal(err)
	}
	if err := rig.server.Trust.Put(trust.Peer{ID: client.ID, Name: client.Name, Fingerprint: before.Fingerprint}); err != nil {
		t.Fatal(err)
	}
	after, ok := rig.server.Trust.Get(client.ID)
	if !ok || after.Generation == before.Generation {
		t.Fatal("re-pair did not advance the peer trust generation")
	}
	waitRevocationConnectionClosed(t, conn)
	waitRevocationPTYClosed(t, pty)
	_ = conn.Close()

	events := waitRevocationAuditEvents(t, rig.stateDir, func(events []audit.Event) bool {
		for _, event := range events {
			if event.Type == "terminal.session_terminated" && event.PeerID == client.ID && event.Reason == "client_revoked" {
				return true
			}
		}
		return false
	})
	found := false
	for _, event := range events {
		if event.Type == "terminal.session_terminated" && event.PeerID == client.ID && event.Reason == "client_revoked" {
			found = true
		}
	}
	if !found {
		t.Fatal("immediate re-pair kept an established session alive")
	}
	waitRevocationSessionsIdle(t, rig.server)
}

func TestTrustStoreReadFailuresTerminateActiveSessions(t *testing.T) {
	for _, mode := range []string{"malformed", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			rig := newRevocationTestRig(t, &revocationTestAuthorizer{})
			client := rig.addClient("storage-failure-client")
			conn, err := rig.open(client, TransportDirectTCP, false)
			if err != nil {
				t.Fatal(err)
			}
			pty := rig.ptyAt(0)
			switch mode {
			case "malformed":
				err = os.WriteFile(rig.trustPath, []byte("{malformed"), 0o600)
			case "unavailable":
				err = os.Remove(rig.trustPath)
				if err == nil {
					err = os.Mkdir(rig.trustPath, 0o700)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			waitRevocationConnectionClosed(t, conn)
			waitRevocationPTYClosed(t, pty)
			_ = conn.Close()

			found := false
			for _, event := range waitRevocationAuditEvents(t, rig.stateDir, func(events []audit.Event) bool {
				for _, event := range events {
					if event.Type == "terminal.session_terminated" && event.PeerID == client.ID && event.Reason == "trust_store_unavailable" {
						return true
					}
				}
				return false
			}) {
				if event.Type == "terminal.session_terminated" && event.PeerID == client.ID && event.Reason == "trust_store_unavailable" {
					found = true
				}
			}
			if !found {
				t.Fatal("trust-store read failure did not produce a fail-closed termination audit")
			}
			waitRevocationSessionsIdle(t, rig.server)
		})
	}
}

func TestRevocationDuringSessionAdmissionFailsClosed(t *testing.T) {
	rig := newRevocationTestRig(t, &revocationTestAuthorizer{})
	client := rig.addClient("admission-race-client")
	entered := make(chan struct{})
	release := make(chan struct{})
	rig.server.beforeSessionAdmission = func() {
		close(entered)
		<-release
	}

	conn := rig.dial(client, TransportDirectTCP)
	if err := rig.sendOpen(conn, TransportDirectTCP, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("session did not reach the final admission boundary")
	}
	pty := rig.ptyAt(0)
	if _, err := trust.Revoke(rig.trustPath, client.ID); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := rig.readAccepted(conn); err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("session admission after concurrent revoke = %v, want unauthorized", err)
	}
	waitRevocationPTYClosed(t, pty)
	_ = conn.Close()

	rig.server.activeSessionsMu.Lock()
	activeCount := len(rig.server.activeSessions)
	rig.server.activeSessionsMu.Unlock()
	if activeCount != 0 {
		t.Fatalf("failed admission left %d active session records", activeCount)
	}
}
