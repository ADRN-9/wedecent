package meshnet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/trust"
)

const (
	MeshALPN             = "wedecent-mesh/1"
	meshHandshakeTimeout = 15 * time.Second
)

var (
	ErrNeighborConfig           = errors.New("meshnet: invalid neighbor-link configuration")
	ErrNeighborUntrusted        = errors.New("meshnet: neighboring device is not trusted")
	ErrNeighborIdentityMismatch = errors.New("meshnet: neighboring device identity mismatch")
)

// TLSLink is an authenticated neighbor-to-neighbor mesh stream.
//
// It deliberately also satisfies net.Conn so that, after route negotiation,
// the same outer encrypted stream can carry an inner endpoint TLS connection.
// Routers must treat those inner bytes as opaque.
type TLSLink struct {
	conn      *tls.Conn
	local     mesh.DeviceID
	remote    mesh.DeviceID
	transport mesh.TransportName
}

func (l *TLSLink) Read(p []byte) (int, error) {
	return l.conn.Read(p)
}

func (l *TLSLink) Write(p []byte) (int, error) {
	return l.conn.Write(p)
}

func (l *TLSLink) Close() error {
	return l.conn.Close()
}

func (l *TLSLink) Local() mesh.DeviceID {
	return l.local
}

func (l *TLSLink) Remote() mesh.DeviceID {
	return l.remote
}

func (l *TLSLink) Transport() mesh.TransportName {
	return l.transport
}

func (l *TLSLink) LocalAddr() net.Addr {
	return l.conn.LocalAddr()
}

func (l *TLSLink) RemoteAddr() net.Addr {
	return l.conn.RemoteAddr()
}

func (l *TLSLink) SetDeadline(t time.Time) error {
	return l.conn.SetDeadline(t)
}

func (l *TLSLink) SetReadDeadline(t time.Time) error {
	return l.conn.SetReadDeadline(t)
}

func (l *TLSLink) SetWriteDeadline(t time.Time) error {
	return l.conn.SetWriteDeadline(t)
}

// DialTrustedLink authenticates an already-open stream to the expected
// neighboring device.
//
// Ownership of raw transfers to this function. On success the returned link
// owns it; on failure it is closed.
func DialTrustedLink(
	ctx context.Context,
	raw net.Conn,
	localIdentity *identity.Identity,
	peer ResolvedPeer,
) (*TLSLink, error) {
	if raw == nil || localIdentity == nil {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, ErrNeighborConfig
	}

	remoteID := mesh.DeviceID(strings.TrimSpace(string(peer.ID)))
	if strings.TrimSpace(string(remoteID)) == "" ||
		strings.TrimSpace(peer.Fingerprint) == "" ||
		strings.TrimSpace(string(peer.Transport)) == "" {
		_ = raw.Close()
		return nil, ErrNeighborConfig
	}

	expectedFP, err := identity.ParseFingerprint(peer.Fingerprint)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("%w: invalid trusted fingerprint", ErrNeighborConfig)
	}

	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{localIdentity.Certificate},
		InsecureSkipVerify: true, // Verified exclusively by VerifyConnection.
		NextProtos:         []string{MeshALPN},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != MeshALPN {
				return ErrNeighborIdentityMismatch
			}

			cert, err := meshPeerCertificate(cs)
			if err != nil {
				return err
			}

			certID := identity.CertificateDeviceID(cert)
			if certID == "" || mesh.DeviceID(certID) != remoteID {
				return ErrNeighborIdentityMismatch
			}

			gotFP, err := identity.FingerprintPublicKey(cert.PublicKey)
			if err != nil || gotFP != expectedFP {
				return ErrNeighborIdentityMismatch
			}

			return nil
		},
	}

	conn := tls.Client(raw, cfg)
	if err := meshTLSHandshake(ctx, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &TLSLink{
		conn:      conn,
		local:     mesh.DeviceID(localIdentity.ID),
		remote:    remoteID,
		transport: peer.Transport,
	}, nil
}

// AcceptTrustedLink authenticates an already-accepted stream from a neighboring
// device against router-owned trust.
//
// The inbound client certificate is mandatory. Successful authentication is
// based on both device ID derived from the Ed25519 key and the full pinned
// public-key fingerprint.
//
// Ownership of raw transfers to this function.
func AcceptTrustedLink(
	ctx context.Context,
	raw net.Conn,
	localIdentity *identity.Identity,
	peers *trust.Store,
	transportName mesh.TransportName,
) (*TLSLink, error) {
	if raw == nil ||
		localIdentity == nil ||
		peers == nil ||
		strings.TrimSpace(string(transportName)) == "" {
		if raw != nil {
			_ = raw.Close()
		}
		return nil, ErrNeighborConfig
	}

	var authenticatedRemote mesh.DeviceID

	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{localIdentity.Certificate},
		ClientAuth:   tls.RequireAnyClientCert,
		NextProtos:   []string{MeshALPN},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != MeshALPN {
				return ErrNeighborIdentityMismatch
			}

			cert, err := meshPeerCertificate(cs)
			if err != nil {
				return err
			}

			remoteID := identity.CertificateDeviceID(cert)
			if remoteID == "" {
				return ErrNeighborIdentityMismatch
			}

			trustedPeer, ok := peers.Get(remoteID)
			if !ok {
				return ErrNeighborUntrusted
			}
			if trustedPeer.ID != remoteID {
				return ErrNeighborIdentityMismatch
			}

			wantFP, err := identity.ParseFingerprint(trustedPeer.Fingerprint)
			if err != nil {
				return ErrNeighborIdentityMismatch
			}

			gotFP, err := identity.FingerprintPublicKey(cert.PublicKey)
			if err != nil || gotFP != wantFP {
				return ErrNeighborIdentityMismatch
			}

			authenticatedRemote = mesh.DeviceID(remoteID)
			return nil
		},
	}

	conn := tls.Server(raw, cfg)
	if err := meshTLSHandshake(ctx, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if authenticatedRemote == "" {
		_ = conn.Close()
		return nil, ErrNeighborIdentityMismatch
	}

	return &TLSLink{
		conn:      conn,
		local:     mesh.DeviceID(localIdentity.ID),
		remote:    authenticatedRemote,
		transport: transportName,
	}, nil
}

func meshPeerCertificate(cs tls.ConnectionState) (*x509.Certificate, error) {
	if len(cs.PeerCertificates) != 1 {
		return nil, ErrNeighborIdentityMismatch
	}

	cert := cs.PeerCertificates[0]
	if err := identity.ValidatePeerCertificate(cert); err != nil {
		return nil, ErrNeighborIdentityMismatch
	}

	return cert, nil
}

func meshTLSHandshake(ctx context.Context, conn *tls.Conn) error {
	handshakeCtx, cancel := context.WithTimeout(ctx, meshHandshakeTimeout)
	defer cancel()

	deadline, _ := handshakeCtx.Deadline()
	_ = conn.SetDeadline(deadline)

	closeDone := make(chan struct{})
	stopClose := context.AfterFunc(handshakeCtx, func() {
		defer close(closeDone)
		_ = conn.Close()
	})

	err := conn.HandshakeContext(handshakeCtx)

	if !stopClose() {
		<-closeDone
	}

	// Authentication failures are more specific than a context deadline that
	// happens to race with the TLS failure path. Preserve those sentinels for
	// local policy/audit decisions.
	if errors.Is(err, ErrNeighborUntrusted) ||
		errors.Is(err, ErrNeighborIdentityMismatch) {
		return fmt.Errorf("meshnet: neighbor TLS handshake: %w", err)
	}

	if ctxErr := handshakeCtx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return fmt.Errorf("meshnet: neighbor TLS handshake: %w", err)
	}

	_ = conn.SetDeadline(time.Time{})
	return nil
}

var _ mesh.Link = (*TLSLink)(nil)
var _ net.Conn = (*TLSLink)(nil)
