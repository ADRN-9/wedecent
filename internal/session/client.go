package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/terminal"
	"wedecent.com/wedecent/internal/transport"
	"wedecent.com/wedecent/internal/trust"
)

type Client struct {
	Identity *identity.Identity
	Trust    *trust.Store
	Dialer   transport.Dialer
}

func (c *Client) Pair(ctx context.Context, endpoint, expectedFingerprint, secret string) (trust.Peer, error) {
	raw, err := c.dial(ctx, endpoint)
	if err != nil {
		return trust.Peer{}, err
	}
	defer raw.Close()
	conn, err := tlsClient(raw, c.Identity, expectedFingerprint)
	if err != nil {
		return trust.Peer{}, err
	}
	defer conn.Close()
	payload, _ := protocol.JSON(protocol.PairRequest{PairingSecret: secret, ClientID: c.Identity.ID, ClientName: c.Identity.Name})
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypePairRequest, Payload: payload}); err != nil {
		return trust.Peer{}, err
	}
	frame, err := protocol.ReadFrame(conn)
	if err != nil {
		return trust.Peer{}, err
	}
	if frame.Type == protocol.TypeError {
		return trust.Peer{}, protocolError(frame.Payload)
	}
	if frame.Type != protocol.TypePairResponse {
		return trust.Peer{}, errors.New("unexpected pairing response")
	}
	var resp protocol.PairResponse
	if err := protocol.ParseJSON(frame.Payload, &resp); err != nil {
		return trust.Peer{}, err
	}
	peerCert, err := identity.PeerCertificate(conn.ConnectionState())
	if err != nil {
		return trust.Peer{}, err
	}
	fp, _ := identity.FingerprintPublicKey(peerCert.PublicKey)
	if resp.DeviceID != identity.CertificateDeviceID(peerCert) {
		return trust.Peer{}, errors.New("server device ID mismatch")
	}
	peer := trust.Peer{ID: resp.DeviceID, Name: resp.DeviceName, Fingerprint: fp, Endpoint: endpoint, TrustedAt: time.Now().UTC()}
	if err := c.Trust.Put(peer); err != nil {
		return trust.Peer{}, err
	}
	return peer, nil
}

func (c *Client) ConnectTerminal(ctx context.Context, peer trust.Peer, in *os.File, out io.Writer) (int, error) {
	raw, err := c.dial(ctx, peer.Endpoint)
	if err != nil {
		return 0, err
	}
	defer raw.Close()
	conn, err := tlsClient(raw, c.Identity, peer.Fingerprint)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	cols, rows := uint16(80), uint16(24)
	isTTY := terminal.IsTerminal(in)
	if isTTY {
		if c2, r2, err := terminal.Size(in); err == nil && c2 > 0 && r2 > 0 {
			cols, rows = c2, r2
		}
	}
	open := protocol.OpenSession{Cols: cols, Rows: rows, Term: os.Getenv("TERM")}
	payload, _ := protocol.JSON(open)
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypeOpenSession, Payload: payload}); err != nil {
		return 0, err
	}
	first, err := protocol.ReadFrame(conn)
	if err != nil {
		return 0, err
	}
	if first.Type == protocol.TypeError {
		return 0, protocolError(first.Payload)
	}
	if first.Type != protocol.TypeSessionAccepted {
		return 0, errors.New("session was not accepted")
	}

	var rawState *terminal.RawState
	if isTTY {
		rawState, err = terminal.MakeRaw(in)
		if err != nil {
			return 0, err
		}
		defer terminal.Restore(in, rawState)
	}

	var writeMu sync.Mutex
	writeFrame := func(f protocol.Frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return protocol.WriteFrame(conn, f)
	}

	writeErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := in.Read(buf)
			if n > 0 {
				data := append([]byte(nil), buf[:n]...)
				if werr := writeFrame(protocol.Frame{Type: protocol.TypeData, StreamID: terminalStreamID, Payload: data}); werr != nil {
					writeErr <- werr
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					// PTYs use EOT to signal end-of-input without tearing down output.
					_ = writeFrame(protocol.Frame{Type: protocol.TypeData, StreamID: terminalStreamID, Payload: []byte{4}})
				}
				writeErr <- err
				return
			}
		}
	}()

	if isTTY {
		stopResize := watchResize(func() {
			c2, r2, err := terminal.Size(in)
			if err != nil {
				return
			}
			payload, _ := protocol.JSON(protocol.Resize{Cols: c2, Rows: r2})
			_ = writeFrame(protocol.Frame{Type: protocol.TypeResize, Payload: payload})
		})
		defer stopResize()
	}

	for {
		frame, err := protocol.ReadFrame(conn)
		if err != nil {
			return 255, err
		}
		switch frame.Type {
		case protocol.TypeData:
			if frame.StreamID == terminalStreamID {
				if _, err := out.Write(frame.Payload); err != nil {
					return 255, err
				}
			}
		case protocol.TypeClose:
			var closeMsg protocol.Close
			_ = protocol.ParseJSON(frame.Payload, &closeMsg)
			return closeMsg.ExitCode, nil
		case protocol.TypeError:
			return 255, protocolError(frame.Payload)
		}
		select {
		case err := <-writeErr:
			if err != nil && !errors.Is(err, io.EOF) {
				return 255, err
			}
		default:
		}
	}
}

func (c *Client) dial(ctx context.Context, endpoint string) (transport.Conn, error) {
	if c.Dialer == nil {
		c.Dialer = transport.MultiDialer{}
	}
	return c.Dialer.Dial(ctx, endpoint)
}

func tlsClient(raw transport.Conn, id *identity.Identity, fp string) (*tls.Conn, error) {
	conn := tls.Client(raw, identity.ClientTLS(id, fp))
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func protocolError(payload []byte) error {
	var p protocol.Error
	if protocol.ParseJSON(payload, &p) != nil {
		return errors.New("remote protocol error")
	}
	return fmt.Errorf("%s: %s", p.Code, p.Message)
}
