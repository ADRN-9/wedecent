package session

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/transport"
	"wedecent.com/wedecent/internal/trust"
)

const revocationTestJTI = "00000000-0000-4000-8000-000000000001"

type revocationTestPTY struct {
	closed   chan struct{}
	once     sync.Once
	closeErr error
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
	return p.closeErr
}

type revocationObservedConn struct {
	net.Conn
	mu               sync.Mutex
	armed            bool
	firstWrite       chan struct{}
	firstOnce        sync.Once
	firstWriteBytes  []byte
	writeReturned    chan struct{}
	writeReturnedOnce sync.Once
}

func newRevocationObservedConn(conn net.Conn) *revocationObservedConn {
	return &revocationObservedConn{
		Conn: conn, firstWrite: make(chan struct{}), writeReturned: make(chan struct{}),
	}
}

func (c *revocationObservedConn) arm() {
	c.mu.Lock()
	c.armed = true
	c.firstWriteBytes = nil
	c.mu.Unlock()
}

func (c *revocationObservedConn) firstRecord() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.firstWriteBytes...)
}

func (c *revocationObservedConn) Write(buffer []byte) (int, error) {
	first := false
	c.mu.Lock()
	if c.armed {
		c.firstOnce.Do(func() {
			first = true
			c.firstWriteBytes = append([]byte(nil), buffer...)
			close(c.firstWrite)
		})
	}
	c.mu.Unlock()
	n, err := c.Conn.Write(buffer)
	if first {
		c.writeReturnedOnce.Do(func() { close(c.writeReturned) })
	}
	return n, err
}

type tlsRecordCounterConn struct {
	net.Conn
	mu      sync.Mutex
	enabled bool
	pending []byte
	records uint64
}

func (c *tlsRecordCounterConn) enable() {
	c.mu.Lock()
	c.enabled = true
	c.mu.Unlock()
}

func (c *tlsRecordCounterConn) recordCount() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.records
}

func (c *tlsRecordCounterConn) Write(buffer []byte) (int, error) {
	n, err := c.Conn.Write(buffer)
	if n > 0 {
		c.mu.Lock()
		if c.enabled {
			c.pending = append(c.pending, buffer[:n]...)
			for len(c.pending) >= 5 {
				recordLength := int(binary.BigEndian.Uint16(c.pending[3:5]))
				if len(c.pending) < 5+recordLength {
					break
				}
				if c.pending[0] == 23 {
					c.records++
				}
				c.pending = c.pending[5+recordLength:]
			}
		}
		c.mu.Unlock()
	}
	return n, err
}

func clientTrafficSecret(t *testing.T, keyLog *bytes.Buffer) []byte {
	t.Helper()
	for _, line := range strings.Split(keyLog.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "CLIENT_TRAFFIC_SECRET_0" {
			secret, err := hex.DecodeString(fields[2])
			if err != nil {
				t.Fatal(err)
			}
			return secret
		}
	}
	t.Fatal("TLS key log did not contain CLIENT_TRAFFIC_SECRET_0")
	return nil
}

func hkdfExpandLabel(secret []byte, label string, hashFunc func() hash.Hash, length int) []byte {
	fullLabel := "tls13 " + label
	info := make([]byte, 2+1+len(fullLabel)+1)
	binary.BigEndian.PutUint16(info[:2], uint16(length))
	info[2] = byte(len(fullLabel))
	copy(info[3:], fullLabel)
	info[3+len(fullLabel)] = 0

	var output, previous []byte
	for counter := byte(1); len(output) < length; counter++ {
		mac := hmac.New(hashFunc, secret)
		_, _ = mac.Write(previous)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		output = append(output, previous...)
	}
	return output[:length]
}

func tls13KeyUpdateRequest(t *testing.T, state tls.ConnectionState, secret []byte, sequence uint64) []byte {
	t.Helper()
	var hashFunc func() hash.Hash
	keyLength := 0
	switch state.CipherSuite {
	case tls.TLS_AES_128_GCM_SHA256:
		hashFunc, keyLength = sha256.New, 16
	case tls.TLS_AES_256_GCM_SHA384:
		hashFunc, keyLength = sha512.New384, 32
	default:
		t.Fatalf("TLS 1.3 cipher suite %x is not supported by the KeyUpdate test helper", state.CipherSuite)
	}
	key := hkdfExpandLabel(secret, "key", hashFunc, keyLength)
	iv := hkdfExpandLabel(secret, "iv", hashFunc, 12)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := append([]byte(nil), iv...)
	var sequenceBytes [8]byte
	binary.BigEndian.PutUint64(sequenceBytes[:], sequence)
	for i := range sequenceBytes {
		nonce[len(nonce)-len(sequenceBytes)+i] ^= sequenceBytes[i]
	}

	// TLS 1.3 KeyUpdate(request_update=1), followed by the inner handshake type.
	plaintext := []byte{24, 0, 0, 1, 1, 22}
	recordLength := len(plaintext) + aead.Overhead()
	header := []byte{23, 3, 3, byte(recordLength >> 8), byte(recordLength)}
	ciphertext := aead.Seal(nil, nonce, plaintext, header)
	return append(header, ciphertext...)
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

func (r *revocationTestRig) ptyCount() int {
	r.t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ptys)
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

type revocationAbortCountingConn struct {
	net.Conn
	mu        sync.Mutex
	abortCall int
	closeCall int
}

func (c *revocationAbortCountingConn) Abort() error {
	c.mu.Lock()
	c.abortCall++
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *revocationAbortCountingConn) Close() error {
	c.mu.Lock()
	c.closeCall++
	c.mu.Unlock()
	return c.Conn.Close()
}

func TestAbortSessionTransportUnwrapsNestedTLSWrappers(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	counted := &revocationAbortCountingConn{Conn: local}
	inner := tls.Client(counted, &tls.Config{MinVersion: tls.VersionTLS13})
	outer := tls.Client(inner, &tls.Config{MinVersion: tls.VersionTLS13})

	if err := abortSessionTransport(outer); err != nil {
		t.Fatalf("abort nested raw-relay TLS wrappers: %v", err)
	}
	counted.mu.Lock()
	abortCalls, closeCalls := counted.abortCall, counted.closeCall
	counted.mu.Unlock()
	if abortCalls != 1 || closeCalls != 0 {
		t.Fatalf("underlying transport calls: Abort=%d Close=%d, want Abort=1 Close=0", abortCalls, closeCalls)
	}
}

type revocationDeadlineFailureConn struct {
	net.Conn
}

func (c *revocationDeadlineFailureConn) SetWriteDeadline(time.Time) error {
	return errors.New("write deadline unsupported")
}

func TestWriteSessionAcceptedFailsClosedWhenDeadlineCannotBeSet(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	conn := &revocationDeadlineFailureConn{Conn: local}
	if err := writeSessionAccepted(conn, protocol.Frame{Type: protocol.TypeSessionAccepted}); err == nil {
		t.Fatal("session acceptance succeeded without a bounded write deadline")
	}
}

type revocationRelayPeer struct {
	conn   net.Conn
	reader *bufio.Reader
}

type revocationWebSocketRelay struct {
	ctx       context.Context
	cancel    context.CancelFunc
	agents    chan *revocationRelayPeer
	clients   chan *revocationRelayPeer
	mu        sync.Mutex
	peers     []*revocationRelayPeer
	closeOnce sync.Once
}

func newRevocationWebSocketRelay() *revocationWebSocketRelay {
	ctx, cancel := context.WithCancel(context.Background())
	relay := &revocationWebSocketRelay{
		ctx:     ctx,
		cancel:  cancel,
		agents:  make(chan *revocationRelayPeer, 1),
		clients: make(chan *revocationRelayPeer, 1),
	}
	go relay.pair()
	return relay
}

func (r *revocationWebSocketRelay) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	role := request.URL.Query().Get("role")
	if role != "agent" && role != "client" {
		http.Error(w, "invalid relay role", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket hijacking unavailable", http.StatusInternalServerError)
		return
	}
	raw, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	digest := sha1.Sum([]byte(
		request.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
	))
	accept := base64.StdEncoding.EncodeToString(digest[:])
	if _, err := fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
		_ = raw.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		_ = raw.Close()
		return
	}
	peer := &revocationRelayPeer{conn: raw, reader: rw.Reader}
	r.mu.Lock()
	r.peers = append(r.peers, peer)
	r.mu.Unlock()

	channel := r.clients
	if role == "agent" {
		channel = r.agents
	}
	select {
	case channel <- peer:
	case <-r.ctx.Done():
		_ = raw.Close()
	}
}

func (r *revocationWebSocketRelay) pair() {
	var agent, client *revocationRelayPeer
	select {
	case agent = <-r.agents:
	case <-r.ctx.Done():
		return
	}
	select {
	case client = <-r.clients:
	case <-r.ctx.Done():
		return
	}
	go r.forward(agent, client)
	go r.forward(client, agent)
}

func (r *revocationWebSocketRelay) forward(source, destination *revocationRelayPeer) {
	for {
		opcode, payload, err := readRevocationWebSocketFrame(source.reader)
		if err != nil {
			r.closePeers()
			return
		}
		if err := writeRevocationWebSocketFrame(destination.conn, opcode, payload); err != nil {
			r.closePeers()
			return
		}
		if opcode == 0x8 {
			r.closePeers()
			return
		}
	}
}

func (r *revocationWebSocketRelay) closePeers() {
	r.closeOnce.Do(func() {
		r.cancel()
		r.mu.Lock()
		peers := append([]*revocationRelayPeer(nil), r.peers...)
		r.mu.Unlock()
		for _, peer := range peers {
			_ = peer.conn.Close()
		}
	})
}

func (r *revocationWebSocketRelay) Close() {
	r.closePeers()
}

func readRevocationWebSocketFrame(reader *bufio.Reader) (byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(extended[:])
	}
	if length > 32<<20 {
		return 0, nil, errors.New("test relay frame exceeds limit")
	}
	masked := header[1]&0x80 != 0
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for index := range payload {
			payload[index] ^= mask[index&3]
		}
	}
	return header[0] & 0x0f, payload, nil
}

func writeRevocationWebSocketFrame(writer io.Writer, opcode byte, payload []byte) error {
	var header [10]byte
	header[0] = 0x80 | opcode
	headerLength := 2
	switch {
	case len(payload) < 126:
		header[1] = byte(len(payload))
	case len(payload) <= 65535:
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(len(payload)))
		headerLength = 4
	default:
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(len(payload)))
		headerLength = 10
	}
	if err := writeRevocationAll(writer, header[:headerLength]); err != nil {
		return err
	}
	return writeRevocationAll(writer, payload)
}

func writeRevocationAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func TestRevocationAbortsEstablishedSessionThroughWebRelayGoAdapter(t *testing.T) {
	rig := newRevocationTestRig(t, &revocationTestAuthorizer{})
	client := rig.addClient("web-relay-revocation-client")
	relay := newRevocationWebSocketRelay()
	server := httptest.NewServer(relay)
	defer server.Close()
	defer relay.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	agentConn, err := transport.WaitWebRelaySession(ctx, server.URL, transport.WebRelayOptions{
		Token:             "agent-ticket",
		Timeout:           5 * time.Second,
		KeepAliveInterval: -1,
	}, rig.serverID.ID, 1)
	if err != nil {
		t.Fatalf("wait for WebSocket relay session: %v", err)
	}
	go rig.server.ServeParkedRelayConn(agentConn)

	clientRaw, err := (transport.WebRelayDialer{
		BaseURL:        server.URL,
		TargetDeviceID: rig.serverID.ID,
		Options: transport.WebRelayOptions{
			Token:             "client-ticket",
			Timeout:           5 * time.Second,
			ConnectionGrant:   "header.payload.signature",
			KeepAliveInterval: -1,
		},
	}).Dial(ctx)
	if err != nil {
		t.Fatalf("dial WebSocket relay client: %v", err)
	}
	conn := tls.Client(clientRaw, identity.ClientTLS(client, rig.serverFingerprint))
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.Handshake(); err != nil {
		t.Fatalf("inner terminal TLS handshake through WebSocket adapter: %v", err)
	}
	if err := rig.sendOpen(conn, TransportWebSocketRelay, false); err != nil {
		t.Fatalf("open terminal session through WebSocket adapter: %v", err)
	}
	if err := rig.readAccepted(conn); err != nil {
		t.Fatalf("read WebSocket terminal session acceptance: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})
	pty := rig.ptyAt(0)

	if _, err := trust.Revoke(rig.trustPath, client.ID); err != nil {
		t.Fatal(err)
	}
	waitRevocationPTYClosed(t, pty)
	waitRevocationConnectionClosed(t, conn)
	_ = conn.Close()
	_ = clientRaw.Close()

	events := waitRevocationAuditEvents(t, rig.stateDir, func(events []audit.Event) bool {
		terminated, closed := 0, 0
		for _, event := range events {
			if event.PeerID != client.ID {
				continue
			}
			if event.Type == "terminal.session_terminated" && event.Reason == "client_revoked" {
				terminated++
			}
			if event.Type == "terminal.session_closed" && event.Reason == "client_revoked" {
				closed++
			}
		}
		return terminated == 1 && closed == 1
	})
	terminated, closed := 0, 0
	terminatedAt, closedAt := -1, -1
	for index, event := range events {
		if event.PeerID != client.ID {
			continue
		}
		if event.Type == "terminal.session_terminated" && event.Reason == "client_revoked" {
			terminated++
			terminatedAt = index
		}
		if event.Type == "terminal.session_closed" && event.Reason == "client_revoked" {
			closed++
			closedAt = index
		}
	}
	if terminated != 1 || closed != 1 || terminatedAt >= closedAt {
		t.Fatalf("WebSocket revocation audit: terminated=%d at %d, closed=%d at %d", terminated, terminatedAt, closed, closedAt)
	}
	waitRevocationSessionsIdle(t, rig.server)
}

func TestRevocationForceClosesBlockedTLS13KeyUpdateAndOtherSessions(t *testing.T) {
	rig := newRevocationTestRig(t, &revocationTestAuthorizer{})
	client := rig.addClient("blocked-tls13-client")
	firstPTY := newRevocationTestPTY()
	secondPTY := newRevocationTestPTY()
	var startMu sync.Mutex
	starts := 0
	rig.server.terminalStart = func(string, uint16, uint16, string) (terminalSessionPTY, error) {
		startMu.Lock()
		defer startMu.Unlock()
		starts++
		if starts == 1 {
			rig.mu.Lock()
			rig.ptys = append(rig.ptys, firstPTY)
			rig.mu.Unlock()
			return firstPTY, nil
		}
		rig.mu.Lock()
		rig.ptys = append(rig.ptys, secondPTY)
		rig.mu.Unlock()
		return secondPTY, nil
	}

	clientRaw, serverRaw := net.Pipe()
	observedServer := newRevocationObservedConn(serverRaw)
	go rig.server.ServeConnWithTransport(observedServer, TransportMetadata{Kind: TransportDirectTCP})
	clientTransport := &tlsRecordCounterConn{Conn: clientRaw}
	keyLog := &bytes.Buffer{}
	clientConfig := identity.ClientTLS(client, rig.serverFingerprint)
	clientConfig.MinVersion = tls.VersionTLS13
	clientConfig.MaxVersion = tls.VersionTLS13
	clientConfig.KeyLogWriter = keyLog
	conn := tls.Client(clientTransport, clientConfig)
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	clientTransport.enable()
	hookEntered := make(chan struct{})
	releaseHook := make(chan struct{})
	var hookMu sync.Mutex
	hookCalls := 0
	rig.server.afterSessionAccepted = func() {
		hookMu.Lock()
		hookCalls++
		call := hookCalls
		hookMu.Unlock()
		if call == 1 {
			close(hookEntered)
			<-releaseHook
		}
	}
	if err := rig.sendOpen(conn, TransportDirectTCP, false); err != nil {
		t.Fatal(err)
	}
	if err := rig.readAccepted(conn); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Time{})
	select {
	case <-hookEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("first session did not reach the post-acceptance barrier")
	}

	other, err := rig.open(client, TransportDirectTCP, false)
	if err != nil {
		t.Fatalf("open independent session before KeyUpdate: %v", err)
	}
	startMu.Lock()
	startedCount := starts
	startMu.Unlock()
	if startedCount != 2 {
		t.Fatalf("PTY starts = %d, want two independent sessions", startedCount)
	}

	// No PTY output or application write is active. After releasing the
	// barrier, the next TLS record written by the server is the KeyUpdate reply.
	observedServer.arm()
	close(releaseHook)
	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated TLS version = %x, want TLS 1.3", state.Version)
	}
	sequence := clientTransport.recordCount()
	if sequence == 0 {
		t.Fatal("client application record sequence was not captured")
	}
	secret := clientTrafficSecret(t, keyLog)
	keyUpdate := tls13KeyUpdateRequest(t, state, secret, sequence)
	if err := clientRaw.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := clientRaw.Write(keyUpdate); err != nil {
		t.Fatalf("send TLS 1.3 KeyUpdate request: %v", err)
	}
	_ = clientRaw.SetWriteDeadline(time.Time{})

	select {
	case <-observedServer.firstWrite:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not attempt a TLS 1.3 KeyUpdate response")
	}
	responseRecord := observedServer.firstRecord()
	if len(responseRecord) != 27 || responseRecord[0] != 23 ||
		int(binary.BigEndian.Uint16(responseRecord[3:5])) != 22 {
		t.Fatalf("blocked server TLS record = %x (length %d), want 27-byte encrypted KeyUpdate response", responseRecord, len(responseRecord))
	}
	select {
	case <-observedServer.writeReturned:
		t.Fatal("TLS KeyUpdate response write returned before the peer read it")
	default:
	}

	if _, err := trust.Revoke(rig.trustPath, client.ID); err != nil {
		t.Fatal(err)
	}
	waitRevocationPTYClosed(t, firstPTY)
	waitRevocationPTYClosed(t, secondPTY)
	waitRevocationConnectionClosed(t, conn)
	waitRevocationConnectionClosed(t, other)
	select {
	case <-observedServer.writeReturned:
	case <-time.After(time.Second):
		t.Fatal("transport abort did not release the blocked TLS KeyUpdate response write")
	}
	_ = conn.Close()
	_ = other.Close()

	events := waitRevocationAuditEvents(t, rig.stateDir, func(events []audit.Event) bool {
		terminated, closed := 0, 0
		for _, event := range events {
			if event.PeerID == client.ID && event.Type == "terminal.session_terminated" {
				terminated++
			}
			if event.PeerID == client.ID && event.Type == "terminal.session_closed" {
				closed++
			}
		}
		return terminated == 2 && closed == 2
	})
	terminated, closed := 0, 0
	terminatedIndex := make(map[string]int)
	closedIndex := make(map[string]int)
	for index, event := range events {
		if event.PeerID != client.ID {
			continue
		}
		if event.Type == "terminal.session_terminated" && event.Reason == "client_revoked" {
			terminated++
			terminatedIndex[event.SessionID] = index
		}
		if event.Type == "terminal.session_closed" && event.Reason == "client_revoked" {
			closed++
			closedIndex[event.SessionID] = index
		}
	}
	if terminated != 2 || closed != 2 {
		t.Fatalf("revocation audit counts: terminated=%d closed=%d, want two each", terminated, closed)
	}
	for sessionID, terminatedAt := range terminatedIndex {
		if closedAt, ok := closedIndex[sessionID]; !ok || terminatedAt >= closedAt {
			t.Fatalf("session %s audit order: terminated at %d, closed at %d", sessionID, terminatedAt, closedAt)
		}
	}
	waitRevocationSessionsIdle(t, rig.server)
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
	if rig.ptyCount() != 0 {
		t.Fatal("PTY or shell started before final serialized authorization")
	}
	if _, err := trust.Revoke(rig.trustPath, client.ID); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := rig.readAccepted(conn); err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("session admission after concurrent revoke = %v, want unauthorized", err)
	}
	if got := rig.ptyCount(); got != 0 {
		t.Fatalf("rejected session started %d PTYs", got)
	}
	_ = conn.Close()

	rig.server.activeSessionsMu.Lock()
	activeCount := len(rig.server.activeSessions)
	rig.server.activeSessionsMu.Unlock()
	if activeCount != 0 {
		t.Fatalf("failed admission left %d active session records", activeCount)
	}
}

func TestAdmissionReservationFirstThenRevocationCleansEstablishedSession(t *testing.T) {
	rig := newRevocationTestRig(t, &revocationTestAuthorizer{})
	client := rig.addClient("admission-first-client")
	ptyStarted := make(chan struct{})
	release := make(chan struct{})
	rig.server.afterSessionAccepted = func() {
		close(ptyStarted)
		<-release
	}

	conn := rig.dial(client, TransportDirectTCP)
	if err := rig.sendOpen(conn, TransportDirectTCP, false); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	go func() { accepted <- rig.readAccepted(conn) }()
	select {
	case <-ptyStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("session did not reserve admission and start its PTY")
	}
	if err := <-accepted; err != nil {
		t.Fatalf("admission-first session was not accepted: %v", err)
	}
	if rig.ptyCount() != 1 {
		t.Fatalf("PTY count after admission-first reservation = %d, want 1", rig.ptyCount())
	}
	rig.server.activeSessionsMu.Lock()
	activeCount := len(rig.server.activeSessions)
	rig.server.activeSessionsMu.Unlock()
	if activeCount != 1 {
		t.Fatalf("admission reservation count = %d, want 1", activeCount)
	}

	if _, err := trust.Revoke(rig.trustPath, client.ID); err != nil {
		t.Fatal(err)
	}
	pty := rig.ptyAt(0)
	waitRevocationPTYClosed(t, pty)
	waitRevocationConnectionClosed(t, conn)
	close(release)
	_ = conn.Close()
	waitRevocationSessionsIdle(t, rig.server)

	events := waitRevocationAuditEvents(t, rig.stateDir, func(events []audit.Event) bool {
		opened, terminated, closed := 0, 0, 0
		for _, event := range events {
			if event.PeerID != client.ID {
				continue
			}
			switch event.Type {
			case "terminal.session_opened":
				opened++
			case "terminal.session_terminated":
				terminated++
			case "terminal.session_closed":
				closed++
			}
		}
		return opened == 1 && terminated == 1 && closed == 1
	})
	opened, terminated, closed := 0, 0, 0
	for _, event := range events {
		if event.PeerID != client.ID {
			continue
		}
		switch event.Type {
		case "terminal.session_opened":
			opened++
		case "terminal.session_terminated":
			if event.Reason == "client_revoked" {
				terminated++
			}
		case "terminal.session_closed":
			if event.Reason == "client_revoked" {
				closed++
			}
		}
	}
	if opened != 1 || terminated != 1 || closed != 1 {
		t.Fatalf("admission-first audit counts: opened=%d terminated=%d closed=%d", opened, terminated, closed)
	}
}


type revocationAbortFailureConn struct {
	net.Conn
	abortErr error
}

func (c *revocationAbortFailureConn) Abort() error {
	_ = c.Conn.Close()
	return c.abortErr
}

func TestRevocationDuringPTYStartupAbortsBeforeAcceptance(t *testing.T) {
	rig := newRevocationTestRig(t, &revocationTestAuthorizer{})
	client := rig.addClient("revocation-during-pty-startup")
	pty := newRevocationTestPTY()
	startupEntered := make(chan struct{})
	releaseStartup := make(chan struct{})
	rig.server.terminalStart = func(string, uint16, uint16, string) (terminalSessionPTY, error) {
		close(startupEntered)
		<-releaseStartup
		rig.mu.Lock()
		rig.ptys = append(rig.ptys, pty)
		rig.mu.Unlock()
		return pty, nil
	}

	conn := rig.dial(client, TransportDirectTCP)
	if err := rig.sendOpen(conn, TransportDirectTCP, false); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Time{})
	select {
	case <-startupEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("PTY startup did not reach its synchronization barrier")
	}
	rig.server.activeSessionsMu.Lock()
	reserved := len(rig.server.activeSessions)
	rig.server.activeSessionsMu.Unlock()
	if reserved != 1 {
		t.Fatalf("active session reservations during PTY startup = %d, want 1", reserved)
	}

	if _, err := trust.Revoke(rig.trustPath, client.ID); err != nil {
		t.Fatal(err)
	}
	waitRevocationConnectionClosed(t, conn)
	close(releaseStartup)
	pty = rig.ptyAt(0)
	waitRevocationPTYClosed(t, pty)
	if err := rig.readAccepted(conn); err == nil {
		t.Fatal("revoked session received an acceptance frame after PTY startup")
	}
	_ = conn.Close()
	waitRevocationSessionsIdle(t, rig.server)

	events := waitRevocationAuditEvents(t, rig.stateDir, func(events []audit.Event) bool {
		for _, event := range events {
			if event.PeerID == client.ID && event.Type == "terminal.session_terminated" {
				return true
			}
		}
		return false
	})
	terminated := 0
	for _, event := range events {
		if event.PeerID != client.ID {
			continue
		}
		switch event.Type {
		case "terminal.session_terminated":
			terminated++
			if event.Outcome != "success" || event.Reason != "client_revoked" {
				t.Fatalf("startup revocation outcome/reason = %q/%q", event.Outcome, event.Reason)
			}
		case "terminal.session_opened", "terminal.session_closed":
			t.Fatalf("session emitted %s despite never being accepted: %+v", event.Type, event)
		}
	}
	if terminated != 1 {
		t.Fatalf("termination audit count = %d, want one", terminated)
	}
}

func TestTerminationPropagatesAbortAndPTYCleanupErrors(t *testing.T) {
	rig := newRevocationTestRig(t, &revocationTestAuthorizer{})
	client := rig.addClient("termination-cleanup-error")
	abortErr := errors.New("injected transport abort failure")
	ptyErr := errors.New("injected PTY close failure")
	clientConn, peerConn := net.Pipe()
	defer peerConn.Close()
	rawConn := &revocationAbortFailureConn{Conn: clientConn, abortErr: abortErr}
	fingerprint, err := identity.FingerprintPublicKey(client.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	active, err := rig.server.admitTerminalSession(client.ID,
		fingerprint, "direct_tcp", rawConn, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pty := newRevocationTestPTY()
	pty.closeErr = ptyErr
	if err := active.setCleanup(pty.Close); err != nil {
		t.Fatal(err)
	}
	terminationErr := active.terminate("client_revoked")
	if !errors.Is(terminationErr, abortErr) || !errors.Is(terminationErr, ptyErr) {
		t.Fatalf("termination error = %v, want both abort and PTY close errors", terminationErr)
	}
	if err := active.finish(); !errors.Is(err, abortErr) || !errors.Is(err, ptyErr) {
		t.Fatalf("finish error = %v, want propagated termination failures", err)
	}
	waitRevocationPTYClosed(t, pty)
	waitRevocationSessionsIdle(t, rig.server)

	events := waitRevocationAuditEvents(t, rig.stateDir, func(events []audit.Event) bool {
		for _, event := range events {
			if event.Type == "terminal.session_terminated" && event.PeerID == client.ID {
				return true
			}
		}
		return false
	})
	for _, event := range events {
		if event.Type == "terminal.session_terminated" && event.PeerID == client.ID {
			if event.Outcome != "failed" {
				t.Fatalf("termination audit outcome = %q, want failed", event.Outcome)
			}
			return
		}
	}
	t.Fatal("termination audit event missing")
}

func TestRevocationPTYCleanupFailureMarksTerminationAndCloseAuditFailed(t *testing.T) {
	rig := newRevocationTestRig(t, &revocationTestAuthorizer{})
	client := rig.addClient("revocation-pty-close-error")
	pty := newRevocationTestPTY()
	pty.closeErr = errors.New("injected PTY close failure")
	rig.server.terminalStart = func(string, uint16, uint16, string) (terminalSessionPTY, error) {
		rig.mu.Lock()
		rig.ptys = append(rig.ptys, pty)
		rig.mu.Unlock()
		return pty, nil
	}
	conn, err := rig.open(client, TransportDirectTCP, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Revoke(rig.trustPath, client.ID); err != nil {
		t.Fatal(err)
	}
	waitRevocationPTYClosed(t, pty)
	waitRevocationConnectionClosed(t, conn)
	_ = conn.Close()
	waitRevocationSessionsIdle(t, rig.server)

	events := waitRevocationAuditEvents(t, rig.stateDir, func(events []audit.Event) bool {
		terminated, closed := false, false
		for _, event := range events {
			if event.PeerID != client.ID {
				continue
			}
			if event.Type == "terminal.session_terminated" && event.Outcome == "failed" {
				terminated = true
			}
			if event.Type == "terminal.session_closed" && event.Outcome == "failed" {
				closed = true
			}
		}
		return terminated && closed
	})
	terminatedAt, closedAt := -1, -1
	for index, event := range events {
		if event.PeerID != client.ID {
			continue
		}
		if event.Type == "terminal.session_terminated" {
			if event.Outcome != "failed" {
				t.Fatalf("termination audit outcome = %q, want failed", event.Outcome)
			}
			terminatedAt = index
		}
		if event.Type == "terminal.session_closed" {
			if event.Outcome != "failed" {
				t.Fatalf("session-closed audit outcome = %q, want failed", event.Outcome)
			}
			closedAt = index
		}
	}
	if terminatedAt < 0 || closedAt <= terminatedAt {
		t.Fatalf("audit ordering: terminated at %d, session closed at %d", terminatedAt, closedAt)
	}
}

type revocationAdmissionFailureConn struct {
	net.Conn
	mu          sync.Mutex
	failWrite   bool
	abortCalls  int
	abortCalled chan struct{}
	abortOnce   sync.Once
}

func (c *revocationAdmissionFailureConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	fail := c.failWrite
	c.mu.Unlock()
	if fail {
		return errors.New("injected admission write-deadline failure")
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func (c *revocationAdmissionFailureConn) Abort() error {
	c.mu.Lock()
	c.abortCalls++
	c.mu.Unlock()
	c.abortOnce.Do(func() { close(c.abortCalled) })
	return c.Conn.Close()
}

func (c *revocationAdmissionFailureConn) failAdmissionWrites() {
	c.mu.Lock()
	c.failWrite = true
	c.mu.Unlock()
}

func TestTypedStreamAdmissionWriteFailureAbortsWithoutErrorFrame(t *testing.T) {
	rig := newRevocationTestRig(t, &revocationTestAuthorizer{})
	client := rig.addClient("typed-admission-write-failure")
	clientRaw, serverRaw := net.Pipe()
	observed := &revocationAdmissionFailureConn{
		Conn: serverRaw, abortCalled: make(chan struct{}),
	}
	go rig.server.ServeConnWithTransport(observed, TransportMetadata{Kind: TransportDirectTCP})

	conn := tls.Client(clientRaw, identity.ClientTLS(client, rig.serverFingerprint))
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Time{})
	observed.failAdmissionWrites()
	if err := rig.sendOpen(conn, TransportDirectTCP, true); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	frame, readErr := protocol.ReadFrame(conn)
	if readErr == nil {
		t.Fatalf("typed admission failure sent a follow-up frame type %d; want raw transport abort", frame.Type)
	}
	select {
	case <-observed.abortCalled:
	case <-time.After(time.Second):
		t.Fatal("typed admission write failure did not immediately abort the raw transport")
	}
	observed.mu.Lock()
	abortCalls := observed.abortCalls
	observed.mu.Unlock()
	if abortCalls != 1 {
		t.Fatalf("raw transport Abort calls = %d, want one", abortCalls)
	}
	_ = conn.Close()

	rig.server.activeSessionsMu.Lock()
	activeCount := len(rig.server.activeSessions)
	rig.server.activeSessionsMu.Unlock()
	if activeCount != 0 {
		t.Fatalf("failed typed admission left %d active session reservations", activeCount)
	}

	events := waitRevocationAuditEvents(t, rig.stateDir, func(events []audit.Event) bool {
		for _, event := range events {
			if event.PeerID == client.ID && event.Type == "terminal.session_opened" {
				return true
			}
		}
		return false
	})
	for _, event := range events {
		if event.PeerID == client.ID && event.Type == "terminal.session_opened" {
			if event.Outcome != "failed" || event.Reason != "session_accept_failed" {
				t.Fatalf("typed admission failure audit = %q/%q", event.Outcome, event.Reason)
			}
			return
		}
	}
	t.Fatal("typed admission failure audit event missing")
}

