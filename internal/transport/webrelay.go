package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" // WebSocket RFC 6455 handshake requires SHA-1.
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	webSocketGUID       = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxWebSocketMessage = 32 << 20
)

type WebRelayOptions struct {
	// TicketSource is the v2 proof-of-possession credential source. When set,
	// it takes precedence over Token and is called for every WebSocket upgrade.
	TicketSource      func(ctx context.Context, relayBaseURL, targetDeviceID, role string, slot int) (string, error)
	Token             string // Legacy v1 shared relay token; retained for migration only.
	ConnectionGrant   string // Short-lived account authorization JWT for client terminal connections.
	Timeout           time.Duration
	KeepAliveInterval time.Duration
}

type WebRelayDialer struct {
	BaseURL        string
	TargetDeviceID string
	Options        WebRelayOptions
}

func (d WebRelayDialer) Dial(ctx context.Context) (Conn, error) {
	u, err := webRelayURL(d.BaseURL, d.TargetDeviceID, "client", 0)
	if err != nil {
		return nil, err
	}
	return dialWebSocket(ctx, u, d.Options)
}

func WaitWebRelaySession(ctx context.Context, baseURL string, opts WebRelayOptions, deviceID string, slot int) (net.Conn, error) {
	u, err := webRelayURL(baseURL, deviceID, "agent", slot)
	if err != nil {
		return nil, err
	}
	return dialWebSocket(ctx, u, opts)
}

func webRelayURL(baseURL, deviceID, role string, slot int) (string, error) {
	if !validDeviceID(deviceID) {
		return "", errors.New("invalid WeDecent device ID")
	}
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Host == "" {
		return "", errors.New("web relay must be a URL such as https://relay.wedecent.com")
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "wss", "ws":
	default:
		return "", errors.New("web relay URL scheme must be https, http, wss, or ws")
	}
	u.Path = "/v1/stream/" + deviceID
	q := u.Query()
	switch role {
	case "agent":
		if slot < 1 || slot > 32 {
			return "", errors.New("web relay agent slot must be between 1 and 32")
		}
		q.Set("role", role)
		q.Set("slot", strconv.Itoa(slot))
	case "client":
		if slot != 0 {
			return "", errors.New("web relay client must not specify an agent slot")
		}
		q.Set("role", role)
	default:
		return "", errors.New("invalid web relay role")
	}
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String(), nil
}

func validDeviceID(s string) bool {
	if len(s) != 19 || !strings.HasPrefix(s, "wd_") {
		return false
	}
	for _, r := range s[3:] {
		if (r < 'a' || r > 'z') && (r < '2' || r > '7') {
			return false
		}
	}
	return true
}

func dialWebSocket(ctx context.Context, rawURL string, opts WebRelayOptions) (net.Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("invalid WebSocket URL")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	credential, err := webRelayCredential(ctx, u, opts)
	if err != nil {
		return nil, err
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	var raw net.Conn
	if u.Scheme == "wss" {
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host}}
		raw, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else if u.Scheme == "ws" {
		raw, err = dialer.DialContext(ctx, "tcp", addr)
	} else {
		return nil, errors.New("unsupported WebSocket scheme")
	}
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	_ = raw.SetDeadline(deadline)
	conn, err := websocketClientHandshake(raw, u, credential, strings.TrimSpace(opts.ConnectionGrant))
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})

	keepAlive := opts.KeepAliveInterval
	if keepAlive == 0 {
		keepAlive = 30 * time.Second
	}
	if keepAlive > 0 {
		go conn.keepAlive(ctx, keepAlive)
	}

	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-conn.done:
		}
	}()
	return conn, nil
}

func webRelayCredential(ctx context.Context, u *url.URL, opts WebRelayOptions) (string, error) {
	if opts.TicketSource == nil {
		return strings.TrimSpace(opts.Token), nil
	}
	const prefix = "/v1/stream/"
	if !strings.HasPrefix(u.Path, prefix) {
		return "", errors.New("invalid web relay stream path")
	}
	targetDeviceID := strings.TrimPrefix(u.Path, prefix)
	if !validDeviceID(targetDeviceID) {
		return "", errors.New("invalid web relay target device ID")
	}
	role := u.Query().Get("role")
	slot := 0
	switch role {
	case "agent":
		parsed, err := strconv.Atoi(u.Query().Get("slot"))
		if err != nil || parsed < 1 || parsed > 32 {
			return "", errors.New("invalid web relay agent slot")
		}
		slot = parsed
	case "client":
		if u.Query().Has("slot") {
			return "", errors.New("web relay client must not specify an agent slot")
		}
	default:
		return "", errors.New("invalid web relay role")
	}
	relayBaseURL, err := webRelayOriginURL(u)
	if err != nil {
		return "", err
	}
	ticket, err := opts.TicketSource(ctx, relayBaseURL, targetDeviceID, role, slot)
	if err != nil {
		return "", fmt.Errorf("issue web relay ticket: %w", err)
	}
	if strings.TrimSpace(ticket) == "" {
		return "", errors.New("web relay ticket source returned an empty ticket")
	}
	return strings.TrimSpace(ticket), nil
}

func webRelayOriginURL(u *url.URL) (string, error) {
	if u == nil || u.Host == "" {
		return "", errors.New("invalid web relay URL")
	}
	scheme := u.Scheme
	switch scheme {
	case "wss":
		scheme = "https"
	case "ws":
		scheme = "http"
	case "https", "http":
	default:
		return "", errors.New("unsupported web relay URL scheme")
	}
	return (&url.URL{Scheme: scheme, Host: u.Host}).String(), nil
}

func websocketClientHandshake(raw net.Conn, u *url.URL, token, connectionGrant string) (*wsNetConn, error) {
	keyBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Key: %s\r\n", key)
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	b.WriteString("User-Agent: WeDecent/2\r\n")
	if token != "" {
		fmt.Fprintf(&b, "Authorization: Bearer %s\r\n", token)
	}
	if connectionGrant != "" {
		if strings.ContainsAny(connectionGrant, "\r\n") {
			return nil, errors.New("connection grant contains invalid whitespace")
		}
		fmt.Fprintf(&b, "X-WeDecent-Connection-Grant: %s\r\n", connectionGrant)
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(raw, b.String()); err != nil {
		return nil, err
	}

	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, fmt.Errorf("web relay handshake: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("web relay rejected connection: %s", msg)
	}
	if !headerTokenContains(resp.Header, "Connection", "upgrade") || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("web relay returned an invalid WebSocket upgrade")
	}
	expected := websocketAccept(key)
	if resp.Header.Get("Sec-WebSocket-Accept") != expected {
		return nil, errors.New("web relay WebSocket accept key mismatch")
	}
	return &wsNetConn{raw: raw, br: br, done: make(chan struct{})}, nil
}

func websocketAccept(key string) string {
	h := sha1.Sum([]byte(key + webSocketGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

func headerTokenContains(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

type wsNetConn struct {
	raw net.Conn
	br  *bufio.Reader

	readMu  sync.Mutex
	writeMu sync.Mutex
	closeMu sync.Mutex
	readBuf bytes.Reader
	closed  bool
	done    chan struct{}
}

func (c *wsNetConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.readBuf.Len() > 0 {
			return c.readBuf.Read(p)
		}
		payload, err := c.readMessage()
		if err != nil {
			return 0, err
		}
		c.readBuf.Reset(payload)
	}
}

func (c *wsNetConn) Write(p []byte) (int, error) {
	if len(p) > maxWebSocketMessage {
		return 0, errors.New("WebSocket write exceeds 32 MiB")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.writeFrame(0x2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsNetConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return nil
	}
	c.closed = true
	close(c.done)
	c.closeMu.Unlock()

	c.writeMu.Lock()
	_ = c.writeFrame(0x8, []byte{0x03, 0xE8})
	c.writeMu.Unlock()
	return c.raw.Close()
}

func (c *wsNetConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *wsNetConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *wsNetConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *wsNetConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *wsNetConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

func (c *wsNetConn) readMessage() ([]byte, error) {
	var out []byte
	var started bool
	for {
		fin, opcode, payload, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		switch opcode {
		case 0x8:
			return nil, parseWebSocketClose(payload)
		case 0x9:
			c.writeMu.Lock()
			err := c.writeFrame(0xA, payload)
			c.writeMu.Unlock()
			if err != nil {
				return nil, err
			}
			continue
		case 0xA:
			continue
		case 0x2:
			if started {
				return nil, errors.New("unexpected binary frame during fragmented message")
			}
			started = true
			out = append(out, payload...)
		case 0x0:
			if !started {
				return nil, errors.New("unexpected WebSocket continuation frame")
			}
			out = append(out, payload...)
		default:
			return nil, fmt.Errorf("unsupported WebSocket opcode %d", opcode)
		}
		if len(out) > maxWebSocketMessage {
			return nil, errors.New("WebSocket message exceeds 32 MiB")
		}
		if started && fin {
			return out, nil
		}
	}
}

func (c *wsNetConn) keepAlive(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-ticker.C:
			payload := []byte(strconv.FormatInt(time.Now().Unix(), 10))
			c.writeMu.Lock()
			err := c.writeFrame(0x9, payload)
			c.writeMu.Unlock()
			if err != nil {
				_ = c.Close()
				return
			}
		}
	}
}

type webSocketCloseError struct {
	Code   uint16
	Reason string
}

func (e *webSocketCloseError) Error() string {
	if e.Code == 0 {
		return "websocket closed"
	}
	if e.Reason == "" {
		return fmt.Sprintf("websocket closed with code %d", e.Code)
	}
	return fmt.Sprintf("websocket closed with code %d: %s", e.Code, e.Reason)
}

func parseWebSocketClose(payload []byte) error {
	if len(payload) == 0 {
		return io.EOF
	}
	if len(payload) == 1 {
		return errors.New("invalid WebSocket close frame")
	}
	return &webSocketCloseError{
		Code:   binary.BigEndian.Uint16(payload[:2]),
		Reason: string(payload[2:]),
	}
}

func (c *wsNetConn) readFrame() (bool, byte, []byte, error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(c.br, h); err != nil {
		return false, 0, nil, err
	}
	fin := h[0]&0x80 != 0
	opcode := h[0] & 0x0F
	if h[0]&0x70 != 0 {
		return false, 0, nil, errors.New("unsupported WebSocket RSV bits")
	}
	masked := h[1]&0x80 != 0
	if masked {
		return false, 0, nil, errors.New("server WebSocket frame must not be masked")
	}
	length := uint64(h[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
		if length&(1<<63) != 0 {
			return false, 0, nil, errors.New("invalid WebSocket payload length")
		}
	}
	if opcode >= 0x8 && (!fin || length > 125) {
		return false, 0, nil, errors.New("invalid WebSocket control frame")
	}
	if length > maxWebSocketMessage {
		return false, 0, nil, errors.New("WebSocket frame exceeds 32 MiB")
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return false, 0, nil, err
	}
	return fin, opcode, payload, nil
}

func (c *wsNetConn) writeFrame(opcode byte, payload []byte) error {
	if len(payload) > maxWebSocketMessage {
		return errors.New("WebSocket frame exceeds 32 MiB")
	}
	var header [14]byte
	header[0] = 0x80 | (opcode & 0x0F)
	n := 2
	l := len(payload)
	switch {
	case l <= 125:
		header[1] = 0x80 | byte(l)
	case l <= 0xFFFF:
		header[1] = 0x80 | 126
		binary.BigEndian.PutUint16(header[2:4], uint16(l))
		n = 4
	default:
		header[1] = 0x80 | 127
		binary.BigEndian.PutUint64(header[2:10], uint64(l))
		n = 10
	}
	var mask [4]byte
	if _, err := io.ReadFull(rand.Reader, mask[:]); err != nil {
		return err
	}
	copy(header[n:n+4], mask[:])
	n += 4
	if _, err := c.raw.Write(header[:n]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i&3]
	}
	_, err := c.raw.Write(masked)
	return err
}
