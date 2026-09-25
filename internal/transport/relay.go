package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/relayproto"
)

type RelayOptions struct {
	CAFile     string
	ServerName string
	Timeout    time.Duration
}

type MultiDialer struct {
	Relay    RelayOptions
	WebRelay WebRelayOptions
}

func (d MultiDialer) Dial(ctx context.Context, locator string) (Conn, error) {
	if strings.HasPrefix(locator, "tcp://") {
		u, err := url.Parse(locator)
		if err != nil || u.Host == "" {
			return nil, errors.New("invalid TCP locator")
		}
		return TCPDialer{Timeout: d.Relay.Timeout}.Dial(ctx, u.Host)
	}
	if strings.HasPrefix(locator, "rfcomm://") {
		endpoint := strings.TrimPrefix(locator, "rfcomm://")
		if endpoint == "" || strings.ContainsAny(endpoint, "?#") {
			return nil, errors.New("invalid RFCOMM locator")
		}
		return RFCOMMDialer{Timeout: d.Relay.Timeout}.Dial(ctx, endpoint)
	}
	if strings.HasPrefix(locator, "serial://") {
		u, err := url.Parse(locator)
		if err != nil || u.Scheme != "serial" || u.Host != "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Path == "" {
			return nil, errors.New("invalid serial locator")
		}
		if locator != "serial://"+u.Path {
			return nil, errors.New("invalid serial locator")
		}
		return SerialDialer{}.Dial(ctx, u.Path)
	}
	if strings.HasPrefix(locator, "relay://") {
		u, err := url.Parse(locator)
		if err != nil || u.Host == "" {
			return nil, errors.New("invalid relay locator")
		}
		deviceID := strings.TrimPrefix(u.EscapedPath(), "/")
		if deviceID == "" || strings.Contains(deviceID, "/") {
			return nil, errors.New("relay locator is missing device ID")
		}
		return RelayDialer{Address: u.Host, TargetDeviceID: deviceID, Options: d.Relay}.Dial(ctx)
	}
	if strings.HasPrefix(locator, "wsrelay://") {
		u, err := url.Parse(locator)
		if err != nil || u.Host == "" {
			return nil, errors.New("invalid web relay locator")
		}
		deviceID := strings.TrimPrefix(u.EscapedPath(), "/")
		if !validDeviceID(deviceID) {
			return nil, errors.New("web relay locator has invalid device ID")
		}
		return WebRelayDialer{BaseURL: "https://" + u.Host, TargetDeviceID: deviceID, Options: d.WebRelay}.Dial(ctx)
	}
	return TCPDialer{Timeout: d.Relay.Timeout}.Dial(ctx, locator)
}

type RelayDialer struct {
	Address        string
	TargetDeviceID string
	Options        RelayOptions
}

func (d RelayDialer) Dial(ctx context.Context) (Conn, error) {
	conn, err := dialRelayTLS(ctx, d.Address, d.Options)
	if err != nil {
		return nil, err
	}
	challenge, err := relayproto.Read(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if challenge.Type != relayproto.TypeChallenge {
		conn.Close()
		return nil, errors.New("relay did not send challenge")
	}
	if err := relayproto.Write(conn, relayproto.Message{Type: relayproto.TypeConnect, DeviceID: d.TargetDeviceID}); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := relayproto.Read(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.Type == relayproto.TypeError {
		conn.Close()
		return nil, fmt.Errorf("relay %s: %s", resp.Code, resp.Error)
	}
	if resp.Type != relayproto.TypeReady {
		conn.Close()
		return nil, errors.New("relay did not enter ready state")
	}
	return conn, nil
}

func WaitRelaySession(ctx context.Context, address string, opts RelayOptions, id *identity.Identity) (net.Conn, error) {
	conn, err := dialRelayTLS(ctx, address, opts)
	if err != nil {
		return nil, err
	}
	challenge, err := relayproto.Read(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if challenge.Type != relayproto.TypeChallenge || challenge.Challenge == "" {
		conn.Close()
		return nil, errors.New("relay did not send challenge")
	}
	sig := ed25519.Sign(id.PrivateKey, relayproto.RegistrationBytes(challenge.Challenge, id.ID))
	msg := relayproto.Message{
		Type: relayproto.TypeRegister, DeviceID: id.ID,
		PublicKey: base64.RawStdEncoding.EncodeToString(id.PublicKey),
		Signature: base64.RawStdEncoding.EncodeToString(sig),
	}
	if err := relayproto.Write(conn, msg); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := relayproto.Read(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.Type == relayproto.TypeError {
		conn.Close()
		return nil, fmt.Errorf("relay %s: %s", resp.Code, resp.Error)
	}
	if resp.Type != relayproto.TypeWaiting {
		conn.Close()
		return nil, errors.New("relay did not accept registration")
	}
	cancelWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-cancelWatch:
		}
	}()
	resp, err = relayproto.Read(conn)
	close(cancelWatch)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.Type == relayproto.TypeError {
		conn.Close()
		return nil, fmt.Errorf("relay %s: %s", resp.Code, resp.Error)
	}
	if resp.Type != relayproto.TypeReady {
		conn.Close()
		return nil, errors.New("relay did not enter ready state")
	}
	return conn, nil
}

func dialRelayTLS(ctx context.Context, address string, opts RelayOptions) (*tls.Conn, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	nd := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	raw, err := nd.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	serverName := opts.ServerName
	if serverName == "" {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			raw.Close()
			return nil, errors.New("relay address must be host:port")
		}
		serverName = host
	}
	roots, err := loadRoots(opts.CAFile)
	if err != nil {
		raw.Close()
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots, NextProtos: []string{relayproto.ALPN}}
	conn := tls.Client(raw, cfg)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("relay TLS handshake: %w", err)
	}
	if conn.ConnectionState().NegotiatedProtocol != relayproto.ALPN {
		conn.Close()
		return nil, errors.New("relay ALPN mismatch")
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func loadRoots(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	pemData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	if !roots.AppendCertsFromPEM(pemData) {
		return nil, errors.New("relay CA file contains no certificates")
	}
	return roots, nil
}
