package transport

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebRelayURL(t *testing.T) {
	got, err := webRelayURL("https://relay.wedecent.com", "wd_4ksk5edkttwsxqx4", "agent")
	if err != nil {
		t.Fatal(err)
	}
	want := "wss://relay.wedecent.com/v1/stream/wd_4ksk5edkttwsxqx4?role=agent"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
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
