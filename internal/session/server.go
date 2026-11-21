package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/audit"
	"wedecent.com/wedecent/internal/buildinfo"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/protocol"
	"wedecent.com/wedecent/internal/trust"
)

const (
	terminalStreamID         = 1
	sessionPolicyExitCode    = 124
	terminalExitDrainTimeout = 2 * time.Second
)

var errTerminalDrainTimeout = errors.New("terminal output drain timeout")

type DirectAuthorizer interface {
	Authorize(context.Context, string, string, string) error
}

type Server struct {
	Identity              *identity.Identity
	Trust                 *trust.Store
	StateDir              string
	Shell                 string
	Logger                *slog.Logger
	DirectAuthorizer      DirectAuthorizer
	FileTransfer          *FileTransferRuntime
	Policy                SessionPolicy
	terminalStart         terminalPTYStarter
	activeSessionsMu      sync.Mutex
	activeSessions        map[string]*activeTerminalSession
	activeSessionsRunning bool

	// This per-server fault seam is nil in production.
	beforeSessionAdmission func()
	afterSessionAccepted   func()
	pairingCompletionAudit func(*audit.Log, audit.Event) error
}

// ServeConn preserves the direct-TCP default for legacy callers. Production
// transport adapters should use ServeConnWithTransport explicitly.
func (s *Server) ServeConn(raw net.Conn) {
	s.ServeConnWithTransport(raw, transportMetadataFromConn(raw))
}

// ServeConnWithTransport accepts only locally supplied, validated transport
// metadata. The label is audit context only; it never participates in identity
// verification, authorization, or routing decisions.
func (s *Server) ServeConnWithTransport(raw net.Conn, metadata TransportMetadata) {
	s.serveConn(raw, 15*time.Second, true, metadata)
}

// ServeParkedRelayConn serves a relay connection that may sit idle until a
// client is matched by the relay. The outer authenticated WebSocket relay is
// responsible for parking the connection; the inner TLS handshake starts only
// when a client arrives, so there is intentionally no pre-client deadline.
func (s *Server) ServeParkedRelayConn(raw net.Conn) {
	s.serveConn(raw, 0, false, TransportMetadata{Kind: TransportWebSocketRelay})
}

func (s *Server) serveConn(raw net.Conn, handshakeTimeout time.Duration, requireInBandAuthorization bool, metadata TransportMetadata) {
	if raw == nil {
		return
	}
	transport, err := metadata.auditLabel()
	if err != nil {
		s.log().Error("invalid session transport metadata", "error", err)
		_ = raw.Close()
		return
	}
	defer raw.Close()
	tlsConn := tls.Server(raw, identity.ServerTLS(s.Identity))
	if handshakeTimeout > 0 {
		_ = tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
	}
	if err := tlsConn.Handshake(); err != nil {
		s.log().Warn("TLS handshake failed", "remote", raw.RemoteAddr(), "error", err)
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	first, err := protocol.ReadFrame(tlsConn)
	if err != nil {
		return
	}
	switch first.Type {
	case protocol.TypePairRequest:
		s.handlePair(tlsConn, first, metadata)
	case protocol.TypeOpenSession:
		if requireInBandAuthorization {
			s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", Transport: transport, Reason: "authorization_required"})
			_ = sendError(tlsConn, "authorization_required", "this transport requires an authorized session request")
			return
		}
		s.handleTerminal(raw, tlsConn, first, metadata, nil)
	case protocol.TypeOpenAuthorizedSession:
		if !requireInBandAuthorization {
			s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", Transport: transport, Reason: "unexpected_authorized_request"})
			_ = sendError(tlsConn, "unexpected_message", "authorized session requests are not valid on this transport")
			return
		}
		s.handleAuthorizedTerminal(raw, tlsConn, first, metadata)
	default:
		_ = sendError(tlsConn, "unexpected_message", "expected pairing or session request")
	}
}

func (s *Server) handlePair(conn *tls.Conn, first protocol.Frame, metadata TransportMetadata) {
	transport, _ := metadata.auditLabel()
	peer, err := identity.PeerCertificate(conn.ConnectionState())
	if err != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "pairing.request", Outcome: "denied", Transport: transport, Reason: "client_certificate_required"})
		_ = sendError(conn, "client_certificate_required", err.Error())
		return
	}
	var req protocol.PairRequest
	if err := protocol.ParseJSON(first.Payload, &req); err != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "pairing.request", Outcome: "denied", Transport: transport, Reason: "invalid_request"})
		_ = sendError(conn, "bad_request", "invalid pair request")
		return
	}
	fp, err := identity.FingerprintPublicKey(peer.PublicKey)
	if err != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "pairing.request", Outcome: "denied", PeerID: req.ClientID, Transport: transport, Reason: "invalid_client_key"})
		_ = sendError(conn, "pairing_denied", "invalid client key")
		return
	}
	clientID := identity.CertificateDeviceID(peer)
	if clientID == "" || req.ClientID != clientID {
		s.recordTransportAudit(metadata, audit.Event{Type: "pairing.request", Outcome: "denied", PeerID: req.ClientID, Transport: transport, Reason: "client_identity_mismatch"})
		_ = sendError(conn, "pairing_denied", "client identity mismatch")
		return
	}
	name := cleanName(req.ClientName)
	if name == "" {
		name = peer.Subject.CommonName
	}
	// Reject invalid secrets before reserving bounded recovery capacity.
	// Locked consumption still checks again, including concurrent rotation.
	valid, err := trust.CheckPairingSecret(s.StateDir, req.PairingSecret)
	if err != nil {
		s.log().Error("pairing state preflight failed", "peer_id", clientID, "error", err)
		_ = sendError(conn, "server_error", "pairing state unavailable")
		return
	}
	if !valid {
		s.recordTransportAudit(metadata, audit.Event{Type: "pairing.request", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "invalid_pairing_secret"})
		_ = sendError(conn, "pairing_denied", "invalid or already consumed pairing secret")
		return
	}
	attemptID, err := audit.NewPairingAttemptID()
	if err != nil {
		_ = sendError(conn, "server_error", "pairing audit is unavailable")
		return
	}
	recovery, err := audit.OpenPairingRecovery(s.StateDir)
	if err == nil {
		var pairingAudit *audit.Log
		pairingAudit, err = audit.Open(s.StateDir)
		if err == nil {
			pending := transportAuditEvent(metadata, audit.Event{
				Type: "pairing.request", Outcome: "pending", ActorID: s.Identity.ID,
				PeerID: clientID, AttemptID: attemptID,
			})
			err = pairingAudit.Append(pending)
		}
		if err == nil {
			err = recovery.Begin(audit.PairingOutcome{
				AttemptID: attemptID, ActorID: s.Identity.ID,
				PeerID: clientID, Fingerprint: fp,
			})
		}
		if err == nil {
			s.handlePairCommit(conn, metadata, clientID, name, fp, req.PairingSecret, attemptID, pairingAudit, recovery)
			return
		}
	}
	s.log().Error("pairing audit preflight failed", "peer_id", clientID, "error", err)
	_ = sendError(conn, "server_error", "pairing audit is unavailable")
}

// handlePairCommit runs only after both independent pending records are durable.
func (s *Server) handlePairCommit(conn *tls.Conn, metadata TransportMetadata, clientID, name, fp, secret, attemptID string, pairingAudit *audit.Log, recovery *audit.PairingRecovery) {
	transport, _ := metadata.auditLabel()
	// Identity and fingerprint were verified before the durable transaction.
	pairErr := trust.PairClientWithSecret(s.StateDir, secret, s.Trust, trust.Peer{
		ID: clientID, Name: name, Fingerprint: fp,
	})
	reconciled := trust.IsPairingReconciled(pairErr)
	outcome := audit.PairingOutcomeSuccess
	if pairErr != nil && !reconciled {
		outcome = audit.PairingOutcomeFailed
		if errors.Is(pairErr, trust.ErrPairingTrustUncertain) {
			outcome = audit.PairingOutcomeUncertain
		} else if errors.Is(pairErr, trust.ErrPairingSecretInvalid) {
			outcome = audit.PairingOutcomeDenied
		}
	}
	if err := recovery.Complete(attemptID, outcome); err != nil {
		// Trust may be committed. Preserve the pending entry, never fabricate denial.
		s.log().Error("pairing outcome not synchronized", "peer_id", clientID, "attempt_id", attemptID, "error", err)
	}
	if pairErr != nil && !reconciled {
		if errors.Is(pairErr, trust.ErrPairingSecretInvalid) {
			// A denied recovery outcome also requires durable audit proof before
			// it can be acknowledged. Missing completion leaves the record intact.
			denial := audit.Event{
				Time: time.Now().UTC(), Type: "pairing.request", Outcome: "denied",
				ActorID: s.Identity.ID, PeerID: clientID, Transport: transport,
				TransportProvenance: transportAuditProvenance(transport),
				AttemptID:           attemptID, Reason: "invalid_pairing_secret",
			}
			denial = transportAuditEvent(metadata, denial)
			if err := pairingAudit.Append(denial); err != nil {
				s.log().Error("pairing denial completion audit unavailable", "attempt_id", attemptID, "error", err)
			} else if err := recovery.ConfirmCompletion(pairingAudit, attemptID, denial); err != nil {
				s.log().Error("pairing denial audit proof uncertain", "attempt_id", attemptID, "error", err)
			}
			_ = sendError(conn, "pairing_denied", "invalid or already consumed pairing secret")
			return
		}
		reason := "pairing_secret_consume_failed"
		switch {
		case errors.Is(pairErr, trust.ErrPairingTrustPersist):
			reason = "trust_persist_failed"
		case errors.Is(pairErr, trust.ErrPairingTrustUncertain):
			reason = "trust_commit_uncertain"
		}
		s.recordTransportAudit(metadata, audit.Event{Type: "pairing.request", Outcome: "failed", PeerID: clientID, Transport: transport, AttemptID: attemptID, Reason: reason})
		_ = sendError(conn, "server_error", "pairing state unavailable; operator review and new secret required")
		return
	}
	reason := ""
	if reconciled {
		reason = "trust_persist_reconciled"
	}
	completion := audit.Event{
		Time: time.Now().UTC(), Type: "pairing.trust_added", Outcome: "success", ActorID: s.Identity.ID,
		PeerID: clientID, Transport: transport, TransportProvenance: transportAuditProvenance(transport),
		AttemptID: attemptID, Reason: reason,
	}
	appendCompletion := pairingAudit.Append
	if s.pairingCompletionAudit != nil {
		appendCompletion = func(event audit.Event) error {
			return s.pairingCompletionAudit(pairingAudit, event)
		}
	}
	completion = transportAuditEvent(metadata, completion)
	if err := appendCompletion(completion); err != nil {
		// Trust is already committed. Do not fabricate denial or audit proof.
		s.log().Error("pairing success audit could not be completed", "peer_id", clientID, "error", err)
	} else if err := recovery.ConfirmCompletion(pairingAudit, attemptID, completion); err != nil {
		// A completed audit log line may rotate away; the unconfirmed ledger
		// entry remains and requires privileged, independently audited repair.
		s.log().Error("pairing completion proof not durable", "peer_id", clientID, "attempt_id", attemptID, "error", err)
	}
	if err := protocol.WriteFrame(conn, protocol.Frame{Type: protocol.TypePairResponse, Payload: mustJSON(protocol.PairResponse{DeviceID: s.Identity.ID, DeviceName: s.Identity.Name})}); err != nil {
		return
	}
	s.log().Info("paired client", "client_id", clientID, "client_name", name)
}

func (s *Server) handleAuthorizedTerminal(rawConn net.Conn, conn *tls.Conn, first protocol.Frame, metadata TransportMetadata) {
	transport, _ := metadata.auditLabel()
	peerCert, err := identity.PeerCertificate(conn.ConnectionState())
	if err != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", Transport: transport, Reason: "client_certificate_required"})
		_ = sendError(conn, "unauthorized", "client certificate required")
		return
	}
	clientID := identity.CertificateDeviceID(peerCert)
	fp, err := identity.FingerprintPublicKey(peerCert.PublicKey)
	if err != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "invalid_client_certificate"})
		_ = sendError(conn, "unauthorized", "invalid client certificate")
		return
	}
	if !validSessionDeviceID(clientID) {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "client_identity_mismatch"})
		_ = sendError(conn, "unauthorized", "client identity mismatch")
		return
	}
	peer, ok, trustErr := s.Trust.Lookup(clientID)
	if trustErr != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "trust_store_unavailable"})
		_ = sendError(conn, "authorization_unavailable", "terminal client trust is unavailable")
		return
	}
	if !ok {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "client_not_paired"})
		_ = sendError(conn, "unauthorized", "client is not paired")
		return
	}
	if peer.Generation == "" {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "trust_store_unavailable"})
		_ = sendError(conn, "authorization_unavailable", "terminal client trust metadata is unavailable")
		return
	}
	if peer.Fingerprint != fp {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "client_identity_mismatch"})
		_ = sendError(conn, "unauthorized", "client identity mismatch")
		return
	}

	var req protocol.OpenAuthorizedSession
	if err := protocol.ParseJSON(first.Payload, &req); err != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "invalid_request"})
		_ = sendError(conn, "bad_request", "invalid authorized session request")
		return
	}
	grant := strings.TrimSpace(req.ConnectionGrant)
	if grant == "" || len(grant) > 16*1024 || strings.ContainsAny(grant, "\r\n\t ") {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "invalid_connection_grant"})
		_ = sendError(conn, "authorization_denied", "connection authorization failed")
		return
	}
	grantJTI, err := ConnectionGrantJTI(grant)
	if err != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "invalid_connection_grant"})
		_ = sendError(conn, "authorization_denied", "connection authorization failed")
		return
	}
	if s.DirectAuthorizer == nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "authorizer_unavailable"})
		_ = sendError(conn, "authorization_unavailable", "direct connection authorization is not configured")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Raw TCP relay is not the Worker WebSocket ingress. The target must
	// independently submit the in-band grant to its approved authorization origin.
	if err := s.DirectAuthorizer.Authorize(ctx, clientID, s.Identity.ID, grant); err != nil {
		s.log().Warn("in-band session authorization rejected", "client_id", clientID, "error", err)
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "authorization_rejected"})
		_ = sendError(conn, "authorization_denied", "connection authorization failed")
		return
	}
	const flow = "direct"
	provider, ok := s.DirectAuthorizer.(GrantEvidenceProvider)
	if !ok {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "grant_evidence_unavailable"})
		_ = sendError(conn, "authorization_unavailable", "server-side grant evidence is unavailable")
		return
	}
	evidence, err := provider.VerifyConsumptionEvidence(ctx, clientID, s.Identity.ID, grantJTI, flow)
	if err != nil {
		s.log().Warn("direct session grant evidence rejected", "client_id", clientID, "error", err)
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "grant_evidence_rejected"})
		_ = sendError(conn, "authorization_denied", "connection authorization evidence could not be verified")
		return
	}
	s.recordGrantAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "success", PeerID: clientID, Transport: transport}, &evidence)

	payload, _ := protocol.JSON(protocol.OpenSession{Cols: req.Cols, Rows: req.Rows, Term: req.Term, GrantJTI: grantJTI, BuildNonce: req.BuildNonce, Capabilities: req.Capabilities})
	s.handleTerminal(rawConn, conn, protocol.Frame{Type: protocol.TypeOpenSession, Payload: payload}, metadata, &evidence)
}

func (s *Server) signedBuildIdentity(nonce string) (*protocol.AgentBuildIdentity, error) {
	if nonce == "" {
		return nil, nil
	}
	if s.Identity == nil {
		return nil, errors.New("agent identity is unavailable")
	}
	attestation, err := buildinfo.SignIdentity(s.Identity.ID, s.Identity.PrivateKey, nonce)
	if err != nil {
		return nil, err
	}
	return &attestation, nil
}

func (s *Server) handleTerminal(rawConn net.Conn, conn *tls.Conn, first protocol.Frame, metadata TransportMetadata, authorization *GrantConsumptionEvidence) {
	transport, _ := metadata.auditLabel()
	peerCert, err := identity.PeerCertificate(conn.ConnectionState())
	if err != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "denied", Transport: transport, Reason: "client_certificate_required"})
		_ = sendError(conn, "unauthorized", "client certificate required")
		return
	}
	clientID := identity.CertificateDeviceID(peerCert)
	fp, err := identity.FingerprintPublicKey(peerCert.PublicKey)
	if err != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "invalid_client_certificate"})
		_ = sendError(conn, "unauthorized", "invalid client certificate")
		return
	}
	if !validSessionDeviceID(clientID) {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "client_identity_mismatch"})
		_ = sendError(conn, "unauthorized", "client identity mismatch")
		return
	}
	peer, ok, trustErr := s.Trust.Lookup(clientID)
	if trustErr != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "trust_store_unavailable"})
		_ = sendError(conn, "authorization_unavailable", "terminal client trust is unavailable")
		return
	}
	if !ok {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "client_not_paired"})
		_ = sendError(conn, "unauthorized", "client is not paired")
		return
	}
	if peer.Generation == "" {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "trust_store_unavailable"})
		_ = sendError(conn, "authorization_unavailable", "terminal client trust metadata is unavailable")
		return
	}
	if peer.Fingerprint != fp {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "denied", PeerID: clientID, Transport: transport, Reason: "client_identity_mismatch"})
		_ = sendError(conn, "unauthorized", "client identity mismatch")
		return
	}
	if err := s.Policy.Validate(); err != nil {
		s.log().Error("invalid terminal session policy", "error", err)
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "failed", PeerID: peer.ID, Transport: transport, Reason: "session_policy_invalid"})
		_ = sendError(conn, "server_error", "terminal session policy is invalid")
		return
	}
	var open protocol.OpenSession
	if err := protocol.ParseJSON(first.Payload, &open); err != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "denied", PeerID: peer.ID, Transport: transport, Reason: "invalid_request"})
		_ = sendError(conn, "bad_request", "invalid session request")
		return
	}
	if metadata.Kind == TransportWebSocketRelay {
		if !validConnectionGrantJTI(open.GrantJTI) {
			s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: peer.ID, Transport: transport, Reason: "relay_grant_evidence_missing"})
			_ = sendError(conn, "authorization_required", "relay session grant evidence is required")
			return
		}
		provider, ok := s.DirectAuthorizer.(GrantEvidenceProvider)
		if !ok {
			s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: peer.ID, Transport: transport, Reason: "grant_evidence_unavailable"})
			_ = sendError(conn, "authorization_unavailable", "server-side grant evidence is unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		evidence, err := provider.VerifyConsumptionEvidence(ctx, peer.ID, s.Identity.ID, open.GrantJTI, "relay")
		cancel()
		if err != nil {
			s.log().Warn("relay session grant evidence rejected", "client_id", peer.ID, "error", err)
			s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: peer.ID, Transport: transport, Reason: "grant_evidence_rejected"})
			_ = sendError(conn, "authorization_denied", "connection authorization evidence could not be verified")
			return
		}
		authorization = &evidence
		s.recordGrantAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "success", PeerID: peer.ID, Transport: transport}, authorization)
	}
	if metadata.Kind == TransportRawRelay {
		if !validConnectionGrantJTI(open.GrantJTI) || authorization == nil ||
			authorization.JTI != strings.ToLower(open.GrantJTI) ||
			authorization.ClientDeviceID != peer.ID || authorization.TargetDeviceID != s.Identity.ID ||
			authorization.Permission != "terminal.connect" || authorization.Flow != "direct" ||
			authorization.ValidationOutcome != "accepted" || authorization.ConsumptionOutcome != "consumed" {
			s.recordTransportAudit(metadata, audit.Event{Type: "terminal.authorization", Outcome: "denied", PeerID: peer.ID, Transport: transport, Reason: "raw_relay_grant_evidence_missing"})
			_ = sendError(conn, "authorization_denied", "raw relay grant evidence does not match this session")
			return
		}
	}
	buildIdentity, err := s.signedBuildIdentity(open.BuildNonce)
	if err != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "failed", PeerID: peer.ID, Transport: transport, Reason: "build_identity_failed"})
		_ = sendError(conn, "server_error", "agent build identity could not be signed")
		return
	}
	fileReady := s.FileTransfer != nil && s.FileTransfer.Ready()
	capabilities := negotiateSessionCapabilitiesForRuntime(open.Capabilities, true, fileReady)
	if hasSessionCapability(capabilities, protocol.CapabilityTypedStreamsV1) {
		accepted, err := sessionAcceptedFrame(capabilities, buildIdentity)
		if err != nil {
			s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "failed", PeerID: peer.ID, Transport: transport, Reason: "session_accept_encode_failed"})
			return
		}
		if s.beforeSessionAdmission != nil {
			s.beforeSessionAdmission()
		}
		active, err := s.admitTerminalSession(peer.ID, fp, transport, rawConn, nil, func(string) error {
			return writeSessionAccepted(conn, accepted)
		})
		if err != nil {
			code, reason := sessionAdmissionFailure(err)
			s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "denied", PeerID: peer.ID, Transport: transport, Reason: reason})
			_ = sendError(conn, code, "terminal session authorization is unavailable")
			return
		}
		defer active.finish()
		s.handleTypedTerminalSession(conn, peer.ID, peer.Name, metadata, capabilities, buildIdentity, authorization, active)
		return
	}
	if open.Cols == 0 {
		open.Cols = 80
	}
	if open.Rows == 0 {
		open.Rows = 24
	}
	accepted, err := sessionAcceptedFrame(capabilities, buildIdentity)
	if err != nil {
		_ = sendError(conn, "server_error", "session acceptance metadata could not be encoded")
		return
	}
	if s.beforeSessionAdmission != nil {
		s.beforeSessionAdmission()
	}

	// Reserve admission under the trust-store lock before starting a shell.
	// A revocation that wins this boundary prevents PTY creation and shell init.
	active, err := s.admitTerminalSession(peer.ID, fp, transport, rawConn, nil, nil)
	if err != nil {
		code, reason := sessionAdmissionFailure(err)
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "denied", PeerID: peer.ID, Transport: transport, Reason: reason})
		_ = sendError(conn, code, "terminal session authorization is unavailable")
		return
	}
	defer active.finish()
	if active.isTerminated() {
		return
	}

	pty, err := s.startTerminal(s.Shell, open.Cols, open.Rows, open.Term)
	if err != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "failed", PeerID: peer.ID, Transport: transport, Reason: "pty_start_failed"})
		_ = sendError(conn, "pty_error", err.Error())
		return
	}
	active.setCleanup(func() {
		if err := pty.Close(); err != nil {
			s.log().Error("terminal PTY close failed during session revocation", "client_id", peer.ID, "transport", transport, "error", err)
		}
	})
	defer pty.Close()
	if active.isTerminated() {
		return
	}
	if err := writeSessionAccepted(conn, accepted); err != nil {
		s.recordTransportAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "denied", PeerID: peer.ID, Transport: transport, Reason: "session_accept_failed"})
		return
	}

	s.recordGrantAudit(metadata, audit.Event{Type: "terminal.session_opened", Outcome: "success", PeerID: peer.ID, SessionID: active.ID, Transport: transport}, authorization)
	closeReason := "connection_ended"
	defer func() {
		active.finish()
		closeReason = active.reasonOr(closeReason)
		s.recordGrantAudit(metadata, audit.Event{Type: "terminal.session_closed", Outcome: "success", PeerID: peer.ID, SessionID: active.ID, Transport: transport, Reason: closeReason}, authorization)
	}()
	if s.afterSessionAccepted != nil {
		s.afterSessionAccepted()
	}
	if active.isTerminated() {
		closeReason = active.reasonOr("client_revoked")
		return
	}
	s.log().Info("terminal opened", "client_id", peer.ID, "client_name", peer.Name)

	var writeMu sync.Mutex
	writeFrame := func(f protocol.Frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return protocol.WriteFrame(conn, f)
	}

	policyTimers := newSessionPolicyTimers(s.Policy)
	defer policyTimers.Stop()
	activityCh := make(chan struct{}, 1)

	ptyReadDone := make(chan struct{})
	go func() {
		defer close(ptyReadDone)
		buf := make([]byte, 32<<10)
		for {
			n, err := pty.Read(buf)
			if n > 0 {
				data := append([]byte(nil), buf[:n]...)
				if werr := writeFrame(protocol.Frame{Type: protocol.TypeData, StreamID: terminalStreamID, Payload: data}); werr != nil {
					return
				}
				signalSessionActivity(activityCh)
			}
			if err != nil {
				return
			}
		}
	}()

	exitCh := make(chan int, 1)
	go func() { exitCh <- exitCode(pty.Wait()) }()

	done := make(chan struct{})
	defer close(done)
	frameCh := make(chan protocol.Frame, 1)
	readErrCh := make(chan error, 1)
	go func() {
		for {
			frame, err := protocol.ReadFrame(conn)
			if err != nil {
				select {
				case readErrCh <- err:
				case <-done:
				}
				return
			}
			select {
			case frameCh <- frame:
			case <-done:
				return
			}
		}
	}()

	expireSession := func(reason string) {
		s.log().Info("terminal policy expired", "client_id", peer.ID, "reason", reason)
		// Bound terminal-output drain before the final close frame. Setting a
		// write deadline first unblocks a PTY forwarding goroutine stuck on a
		// peer that stopped reading.
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = pty.Close()
		if ptyReadDone != nil {
			drainTimer := time.NewTimer(500 * time.Millisecond)
			select {
			case <-ptyReadDone:
				ptyReadDone = nil
			case <-drainTimer.C:
			case <-readErrCh:
			}
			if !drainTimer.Stop() {
				select {
				case <-drainTimer.C:
				default:
				}
			}
		}
		if err := writeFrame(protocol.Frame{Type: protocol.TypeClose, Payload: mustJSON(protocol.Close{ExitCode: sessionPolicyExitCode, Reason: reason})}); err != nil {
			return
		}
		waitForPeerClose(frameCh, readErrCh, 2*time.Second)
	}

	for {
		select {
		case code := <-exitCh:
			closeReason = "process_exit"
			// Cmd.Wait may return before the PTY reader has forwarded the final
			// bytes written by the shell. Close is the protocol's terminal frame,
			// so send it only after PTY output has drained. If draining does not
			// finish promptly, fail closed by dropping the transport without a
			// terminal close frame rather than letting Close overtake output.
			if ptyReadDone != nil {
				err := waitForTerminalDrain(ptyReadDone, readErrCh, terminalExitDrainTimeout)
				switch {
				case err == nil:
					ptyReadDone = nil
				case errors.Is(err, errTerminalDrainTimeout):
					closeReason = "pty_drain_timeout"
					s.log().Warn("terminal output drain timed out", "client_id", peer.ID)
					return
				default:
					closeReason = "peer_disconnect"
					if !errors.Is(err, io.EOF) {
						s.log().Debug("session read ended", "error", err)
					}
					return
				}
			}
			if err := writeFrame(protocol.Frame{Type: protocol.TypeClose, Payload: mustJSON(protocol.Close{ExitCode: code})}); err != nil {
				closeReason = "transport_write_failed"
				return
			}
			// Do not immediately close the outer relay after sending the final
			// application frame. Wait until the client acknowledges it (new
			// clients) or closes its side after receiving it (older clients).
			waitForPeerClose(frameCh, readErrCh, 2*time.Second)
			return
		case err := <-readErrCh:
			closeReason = "peer_disconnect"
			if !errors.Is(err, io.EOF) {
				s.log().Debug("session read ended", "error", err)
			}
			return
		case frame := <-frameCh:
			switch frame.Type {
			case protocol.TypeData:
				if frame.StreamID == terminalStreamID && len(frame.Payload) > 0 {
					if _, err := pty.Write(frame.Payload); err != nil {
						closeReason = "pty_write_failed"
						return
					}
					policyTimers.Activity()
				}
			case protocol.TypeResize:
				var resize protocol.Resize
				if protocol.ParseJSON(frame.Payload, &resize) == nil {
					if pty.Resize(resize.Cols, resize.Rows) == nil {
						policyTimers.Activity()
					}
				}
			case protocol.TypePing:
				_ = writeFrame(protocol.Frame{Type: protocol.TypePong})
			case protocol.TypeClose:
				closeReason = "peer_close"
				return
			}
		case <-activityCh:
			policyTimers.Activity()
		case <-policyTimers.idleC:
			closeReason = "policy_idle_timeout"
			expireSession("session idle timeout")
			return
		case <-policyTimers.maxC:
			closeReason = "policy_max_duration"
			expireSession("session maximum duration reached")
			return
		case <-ptyReadDone:
			// Wait for Cmd.Wait() to provide the authoritative exit code.
			ptyReadDone = nil
		}
	}
}

func waitForTerminalDrain(ptyReadDone <-chan struct{}, readErrCh <-chan error, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ptyReadDone:
		return nil
	case err := <-readErrCh:
		if err == nil {
			return io.EOF
		}
		return err
	case <-timer.C:
		return errTerminalDrainTimeout
	}
}

func waitForPeerClose(frameCh <-chan protocol.Frame, readErrCh <-chan error, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case frame := <-frameCh:
			if frame.Type == protocol.TypeClose {
				return
			}
		case <-readErrCh:
			return
		case <-timer.C:
			return
		}
	}
}

func transportAuditProvenance(transport string) string {
	// USB NCM attribution is an operator configuration assertion, not
	// hardware attestation. Ordinary transports come from the local adapter.
	switch {
	case strings.HasPrefix(transport, "routed+"):
		return "authenticated_router_link"
	case strings.HasSuffix(transport, "+usb_ncm"):
		return "operator_config_assertion"
	case transport != "":
		return "listener_adapter"
	default:
		return ""
	}
}

func (s *Server) recordGrantAudit(metadata TransportMetadata, event audit.Event, evidence *GrantConsumptionEvidence) {
	if evidence != nil {
		event.AuthorizationRunID = evidence.AuthorizationRunID
		event.ValidationAttemptID = evidence.ValidationAttemptID
		event.ConsumptionAttemptID = evidence.ConsumptionAttemptID
		event.ValidationEventID = evidence.ValidationEventID
		event.ConsumptionEventID = evidence.ConsumptionEventID
	}
	s.recordTransportAudit(metadata, event)
}

func (s *Server) recordTransportAudit(metadata TransportMetadata, event audit.Event) {
	s.recordAudit(transportAuditEvent(metadata, event))
}

func transportAuditEvent(metadata TransportMetadata, event audit.Event) audit.Event {
	label, err := metadata.auditLabel()
	if err != nil {
		return event
	}
	event.Transport = label
	event.TransportProvenance = transportAuditProvenance(label)
	event.UnderlyingTransport = string(metadata.Underlying)
	event.RouteRouterID = metadata.RouteRouterID
	return event
}

func (s *Server) appendAudit(event audit.Event) error {
	if event.TransportProvenance == "" {
		event.TransportProvenance = transportAuditProvenance(event.Transport)
	}
	if strings.TrimSpace(s.StateDir) == "" {
		return errors.New("audit state directory is unavailable")
	}
	if event.ActorID == "" && s.Identity != nil {
		event.ActorID = s.Identity.ID
	}
	log, err := audit.Open(s.StateDir)
	if err != nil {
		return err
	}
	return log.Append(event)
}

func (s *Server) recordAudit(event audit.Event) {
	if strings.TrimSpace(s.StateDir) == "" {
		return
	}
	if err := s.appendAudit(event); err != nil {
		s.log().Warn("persistent audit event failed", "event_type", event.Type, "error", err)
	}
}

func (s *Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) {
		return ec.ExitCode()
	}
	return 255
}

func cleanName(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return identity.SanitizeName(s)
}

func sendError(w io.Writer, code, message string) error {
	return protocol.WriteFrame(w, protocol.Frame{Type: protocol.TypeError, Payload: mustJSON(protocol.Error{Code: code, Message: message})})
}

func mustJSON(v any) []byte {
	b, err := protocol.JSON(v)
	if err != nil {
		panic(fmt.Sprintf("marshal protocol message: %v", err))
	}
	return b
}
