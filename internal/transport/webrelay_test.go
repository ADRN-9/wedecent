package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/relayproto"
)

func TestWebRelayURL(t *testing.T) {
	got, err := webRelayURL("https://relay.wedecent.com", "wd_4ksk5edkttwsxqx4", "agent", 4)
	if err != nil {
		t.Fatal(err)
	}
	want := "wss://relay.wedecent.com/v1/stream/wd_4ksk5edkttwsxqx4?role=agent&slot=4"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestWebRelayClientURLHasNoSlot(t *testing.T) {
	got, err := webRelayURL("https://relay.wedecent.com", "wd_4ksk5edkttwsxqx4", "client", 0)
	if err != nil {
		t.Fatal(err)
	}
	want := "wss://relay.wedecent.com/v1/stream/wd_4ksk5edkttwsxqx4?role=client"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestWebRelayRejectsInvalidAgentSlot(t *testing.T) {
	if _, err := webRelayURL("https://relay.wedecent.com", "wd_4ksk5edkttwsxqx4", "agent", 0); err == nil {
		t.Fatal("expected invalid agent slot to fail")
	}
}

func TestWebRelayCredentialPrefersTicketSource(t *testing.T) {
	u, err := url.Parse("wss://relay.wedecent.com/v1/stream/wd_4ksk5edkttwsxqx4?role=agent&slot=3")
	if err != nil {
		t.Fatal(err)
	}
	var gotTarget, gotRole string
	var gotSlot int
	credential, err := webRelayCredential(context.Background(), u, WebRelayOptions{
		Token: "legacy-token",
		TicketSource: func(ctx context.Context, relayBaseURL, targetDeviceID, role string, slot int) (string, error) {
			if relayBaseURL != "https://relay.wedecent.com" {
				t.Fatalf("unexpected relay base URL %q", relayBaseURL)
			}
			gotTarget, gotRole, gotSlot = targetDeviceID, role, slot
			return "wdt2.test.signature", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if credential != "wdt2.test.signature" {
		t.Fatalf("unexpected credential %q", credential)
	}
	if gotTarget != "wd_4ksk5edkttwsxqx4" || gotRole != "agent" || gotSlot != 3 {
		t.Fatalf("unexpected ticket scope: target=%q role=%q slot=%d", gotTarget, gotRole, gotSlot)
	}
}

func TestWebRelayCredentialLegacyFallback(t *testing.T) {
	u, err := url.Parse("wss://relay.wedecent.com/v1/stream/wd_4ksk5edkttwsxqx4?role=client")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := webRelayCredential(context.Background(), u, WebRelayOptions{Token: "legacy-token"})
	if err != nil {
		t.Fatal(err)
	}
	if credential != "legacy-token" {
		t.Fatalf("unexpected legacy credential %q", credential)
	}
}

func TestWebSocketAcceptRFCExample(t *testing.T) {
	got := websocketAccept("dGhlIHNhbXBsZSBub25jZQ==")
	want := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestWSNetConnWritesMaskedBinaryFrame(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	conn := &wsNetConn{raw: client, br: bufio.NewReader(client), done: make(chan struct{})}
	defer client.Close()

	want := []byte("hello")
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Write(want)
		errCh <- err
	}()

	h := make([]byte, 2)
	if _, err := io.ReadFull(server, h); err != nil {
		t.Fatal(err)
	}
	if h[0] != 0x82 || h[1]&0x80 == 0 {
		t.Fatalf("unexpected header: %x", h)
	}
	length := int(h[1] & 0x7f)
	if length != len(want) {
		t.Fatalf("length %d", length)
	}
	mask := make([]byte, 4)
	if _, err := io.ReadFull(server, mask); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(server, payload); err != nil {
		t.Fatal(err)
	}
	for i := range payload {
		payload[i] ^= mask[i&3]
	}
	if !bytes.Equal(payload, want) {
		t.Fatalf("got %q want %q", payload, want)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestDialWebSocketSendsConnectionGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer wdt2.test.signature" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-WeDecent-Connection-Grant") != "header.payload.signature" {
			http.Error(w, "missing connection grant", http.StatusForbidden)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server does not support hijacking")
		}
		raw, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer raw.Close()
		accept := websocketAccept(r.Header.Get("Sec-WebSocket-Key"))
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
		_ = rw.Flush()
	}))
	defer server.Close()

	u := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/stream/wd_4ksk5edkttwsxqx4?role=client"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialWebSocket(ctx, u, WebRelayOptions{
		Timeout:         5 * time.Second,
		ConnectionGrant: "header.payload.signature",
		TicketSource: func(context.Context, string, string, string, int) (string, error) {
			return "wdt2.test.signature", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestWebSocketHandshakeRejectsConnectionGrantHeaderInjection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	u, err := url.Parse("ws://relay.test/v1/stream/wd_4ksk5edkttwsxqx4?role=client")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := websocketClientHandshake(client, u, "token", "good\r\nInjected: value"); err == nil {
		t.Fatal("expected connection grant header injection to fail")
	}
}

func TestDialWebSocketUsesTicketSource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer wdt2.test.signature" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("role") != "client" {
			http.Error(w, "wrong role", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server does not support hijacking")
		}
		raw, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer raw.Close()
		accept := websocketAccept(r.Header.Get("Sec-WebSocket-Key"))
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
		_ = rw.Flush()
	}))
	defer server.Close()

	u := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/stream/wd_4ksk5edkttwsxqx4?role=client"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialWebSocket(ctx, u, WebRelayOptions{
		Timeout: 5 * time.Second,
		TicketSource: func(ctx context.Context, relayBaseURL, targetDeviceID, role string, slot int) (string, error) {
			if relayBaseURL != server.URL {
				t.Fatalf("unexpected relay base URL %q, want %q", relayBaseURL, server.URL)
			}
			if targetDeviceID != "wd_4ksk5edkttwsxqx4" || role != "client" || slot != 0 {
				t.Fatalf("unexpected ticket scope: target=%q role=%q slot=%d", targetDeviceID, role, slot)
			}
			return "wdt2.test.signature", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestDialWebSocketRoundTrip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server does not support hijacking")
		}
		raw, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer raw.Close()
		accept := websocketAccept(r.Header.Get("Sec-WebSocket-Key"))
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
		if err := rw.Flush(); err != nil {
			return
		}

		payload, err := readMaskedClientFrame(rw.Reader)
		if err != nil {
			return
		}
		_ = writeServerBinaryFrame(raw, payload)
	}))
	defer server.Close()

	u := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/stream/wd_4ksk5edkttwsxqx4?role=client"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialWebSocket(ctx, u, WebRelayOptions{Token: "test-token", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	want := []byte("encrypted-inner-tls-bytes")
	if _, err := conn.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

type wsAbortObservedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *wsAbortObservedConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

type wsAbortCountingConn struct {
	net.Conn
	mu        sync.Mutex
	abortCall int
	closeCall int
}

func (c *wsAbortCountingConn) Abort() error {
	c.mu.Lock()
	c.abortCall++
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *wsAbortCountingConn) Close() error {
	c.mu.Lock()
	c.closeCall++
	c.mu.Unlock()
	return c.Conn.Close()
}

func TestWSNetConnAbortUnblocksBlockedWriterWithoutWriteMutex(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	observed := &wsAbortObservedConn{Conn: client, started: make(chan struct{})}
	conn := &wsNetConn{raw: observed, br: bufio.NewReader(observed), done: make(chan struct{})}

	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write(bytes.Repeat([]byte("x"), 1<<20))
		writeDone <- err
	}()
	select {
	case <-observed.started:
	case <-time.After(time.Second):
		t.Fatal("WebSocket writer did not reach the blocked underlying write")
	}

	abortDone := make(chan error, 1)
	go func() { abortDone <- conn.Abort() }()
	select {
	case err := <-abortDone:
		if err != nil {
			t.Fatalf("abort WebSocket transport: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Abort waited for the WebSocket write mutex")
	}
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("blocked WebSocket writer unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("force-closing the underlying socket did not unblock the writer")
	}
}

func TestWSNetConnAbortUnwrapsTLSWithoutGracefulClose(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	counted := &wsAbortCountingConn{Conn: client}
	tlsConn := tls.Client(counted, &tls.Config{MinVersion: tls.VersionTLS13})
	conn := &wsNetConn{raw: tlsConn, br: bufio.NewReader(tlsConn), done: make(chan struct{})}

	if err := conn.Abort(); err != nil {
		t.Fatalf("abort nested TLS/WebSocket transport: %v", err)
	}
	counted.mu.Lock()
	abortCalls, closeCalls := counted.abortCall, counted.closeCall
	counted.mu.Unlock()
	if abortCalls != 1 || closeCalls != 0 {
		t.Fatalf("underlying transport calls: Abort=%d Close=%d, want Abort=1 Close=0", abortCalls, closeCalls)
	}
}

func TestWaitWebRelaySessionExposesForceAbortForEstablishedSocket(t *testing.T) {
	peerClosed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("server does not support hijacking")
			return
		}
		raw, rw, err := hj.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		accept := websocketAccept(r.Header.Get("Sec-WebSocket-Key"))
		_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
		if err := rw.Flush(); err != nil {
			t.Error(err)
			_ = raw.Close()
			return
		}
		defer raw.Close()
		for _, message := range []relayproto.Message{
			{Type: relayproto.TypeChallenge, Challenge: "challenge"},
			{Type: relayproto.TypeWaiting},
			{Type: relayproto.TypeReady},
		} {
			var control bytes.Buffer
			if err := relayproto.Write(&control, message); err != nil {
				t.Error(err)
				return
			}
			if err := writeServerBinaryFrame(raw, control.Bytes()); err != nil {
				t.Error(err)
				return
			}
		}
		_, _ = io.Copy(io.Discard, raw)
		close(peerClosed)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := WaitWebRelaySession(ctx, server.URL, WebRelayOptions{
		Token:             "test-agent-ticket",
		KeepAliveInterval: -1,
	}, "wd_4ksk5edkttwsxqx4", 1)
	if err != nil {
		t.Fatal(err)
	}
	aborter, ok := conn.(interface{ Abort() error })
	if !ok {
		t.Fatal("WaitWebRelaySession did not return a force-abort-capable transport")
	}
	if err := aborter.Abort(); err != nil {
		t.Fatalf("abort established WebSocket relay session: %v", err)
	}
	select {
	case <-peerClosed:
	case <-time.After(time.Second):
		t.Fatal("relay peer did not observe the force-closed transport")
	}
}

func readMaskedClientFrame(r *bufio.Reader) ([]byte, error) {
	h, err := r.Peek(2)
	if err != nil {
		return nil, err
	}
	if h[0]&0x0f != 0x2 || h[1]&0x80 == 0 {
		return nil, fmt.Errorf("unexpected client frame header %x", h)
	}
	_, _ = r.Discard(2)
	length := int(h[1] & 0x7f)
	if length >= 126 {
		return nil, errors.New("test helper only supports short frames")
	}
	mask := make([]byte, 4)
	if _, err := io.ReadFull(r, mask); err != nil {
		return nil, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i&3]
	}
	return payload, nil
}

func writeServerBinaryFrame(w io.Writer, payload []byte) error {
	if len(payload) > 125 {
		return errors.New("test helper only supports short frames")
	}
	_, err := w.Write(append([]byte{0x82, byte(len(payload))}, payload...))
	return err
}
