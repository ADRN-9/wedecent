package routercontrol

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
	"wedecent.com/wedecent/internal/trust"
)

const (
	RouterAdminALPN           = "wedecent-router-admin/1"
	routerAdminHandshakeLimit = 10 * time.Second
)

var (
	ErrAuthConfig           = errors.New("routercontrol: invalid authentication configuration")
	ErrPeerIdentityMismatch = errors.New("routercontrol: peer identity mismatch")
	ErrControllerUntrusted  = errors.New("routercontrol: controller is not trusted")
)

// ControllerTrust is the minimum authorization view required by the TLS server.
// Keeping this narrower than trust.Store lets the agent reload the dedicated
// controller file for every new admin connection without exposing mutation.
type ControllerTrust interface {
	Get(string) (trust.Peer, bool)
}

// authenticatedConn deliberately closes the owned raw stream directly. A
// graceful TLS close can block indefinitely if the peer stops reading shutdown
// records. This protocol is one framed request/response per connection, so a
// complete frame provides the application-level message boundary we need.
type authenticatedConn struct {
	*tls.Conn
	raw net.Conn
}

func (c *authenticatedConn) Close() error {
	if c == nil || c.raw == nil {
		return nil
	}
	return c.raw.Close()
}

// DialAuthenticated upgrades an already-local stream to mutually authenticated
// TLS. The controller pins the exact agent device ID and full public-key
// fingerprint; normal Web PKI roots are intentionally not consulted.
func DialAuthenticated(
	ctx context.Context,
	raw net.Conn,
	controller *identity.Identity,
	agent trust.Peer,
) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		closeRaw(raw)
		return nil, err
	}
	if raw == nil || !validIdentity(controller) || strings.TrimSpace(agent.ID) == "" {
		closeRaw(raw)
		return nil, ErrAuthConfig
	}
	wantFingerprint, err := identity.ParseFingerprint(agent.Fingerprint)
	if err != nil {
		closeRaw(raw)
		return nil, ErrAuthConfig
	}

	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{controller.Certificate},
		InsecureSkipVerify: true, // Exact identity and fingerprint are verified below.
		NextProtos:         []string{RouterAdminALPN},
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.NegotiatedProtocol != RouterAdminALPN {
				return ErrPeerIdentityMismatch
			}
			cert, err := singleValidatedPeerCertificate(state)
			if err != nil {
				return err
			}
			if identity.CertificateDeviceID(cert) != agent.ID {
				return ErrPeerIdentityMismatch
			}
			gotFingerprint, err := identity.FingerprintPublicKey(cert.PublicKey)
			if err != nil || gotFingerprint != wantFingerprint {
				return ErrPeerIdentityMismatch
			}
			return nil
		},
	}

	conn := tls.Client(raw, cfg)
	if err := handshakeRouterAdmin(ctx, conn); err != nil {
		closeRaw(raw)
		return nil, err
	}
	return &authenticatedConn{Conn: conn, raw: raw}, nil
}

// AcceptAuthenticated upgrades an already-local stream to mutually
// authenticated TLS. A controller is authorized only by the dedicated trust
// source supplied here; terminal pairing and route trust stores are not inputs.
func AcceptAuthenticated(
	ctx context.Context,
	raw net.Conn,
	agent *identity.Identity,
	controllers ControllerTrust,
) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		closeRaw(raw)
		return nil, err
	}
	if raw == nil || !validIdentity(agent) || controllers == nil {
		closeRaw(raw)
		return nil, ErrAuthConfig
	}

	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{agent.Certificate},
		ClientAuth:   tls.RequireAnyClientCert,
		NextProtos:   []string{RouterAdminALPN},
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.NegotiatedProtocol != RouterAdminALPN {
				return ErrPeerIdentityMismatch
			}
			cert, err := singleValidatedPeerCertificate(state)
			if err != nil {
				return err
			}
			controllerID := identity.CertificateDeviceID(cert)
			if strings.TrimSpace(controllerID) == "" {
				return ErrPeerIdentityMismatch
			}
			peer, ok := controllers.Get(controllerID)
			if !ok {
				return ErrControllerUntrusted
			}
			if peer.ID != controllerID {
				return ErrPeerIdentityMismatch
			}
			wantFingerprint, err := identity.ParseFingerprint(peer.Fingerprint)
			if err != nil {
				return ErrPeerIdentityMismatch
			}
			gotFingerprint, err := identity.FingerprintPublicKey(cert.PublicKey)
			if err != nil || gotFingerprint != wantFingerprint {
				return ErrPeerIdentityMismatch
			}
			return nil
		},
	}

	conn := tls.Server(raw, cfg)
	if err := handshakeRouterAdmin(ctx, conn); err != nil {
		closeRaw(raw)
		return nil, err
	}
	return &authenticatedConn{Conn: conn, raw: raw}, nil
}

func validIdentity(id *identity.Identity) bool {
	return id != nil &&
		strings.TrimSpace(id.ID) != "" &&
		len(id.Certificate.Certificate) > 0
}

func singleValidatedPeerCertificate(state tls.ConnectionState) (*x509.Certificate, error) {
	if len(state.PeerCertificates) != 1 {
		return nil, ErrPeerIdentityMismatch
	}
	cert := state.PeerCertificates[0]
	if err := identity.ValidatePeerCertificate(cert); err != nil {
		return nil, ErrPeerIdentityMismatch
	}
	return cert, nil
}

func handshakeRouterAdmin(ctx context.Context, conn *tls.Conn) error {
	handshakeCtx, cancel := context.WithTimeout(ctx, routerAdminHandshakeLimit)
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

	if errors.Is(err, ErrControllerUntrusted) || errors.Is(err, ErrPeerIdentityMismatch) {
		return fmt.Errorf("routercontrol: TLS handshake: %w", err)
	}
	if ctxErr := handshakeCtx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return fmt.Errorf("routercontrol: TLS handshake failed")
	}

	_ = conn.SetDeadline(time.Time{})
	return nil
}

func closeRaw(raw net.Conn) {
	if raw != nil {
		_ = raw.Close()
	}
}
