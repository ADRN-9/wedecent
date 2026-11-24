package portforward

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
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

	"wedecent.com/wedecent/internal/account"
)

const checkpointAuditRequestMax = 64 << 10

type CheckpointAuditTrust struct {
	Hostname string
	Port uint16
	SPKISHA256Pins string
}

type SupabaseCheckpointFinalizationAuditor struct {
	trust CheckpointAuditTrust
	mu          sync.Mutex
	client      account.Client
	sessionPath string
	session     *account.Session
	http        *http.Client
}

type finalizationAuditResponse struct {
	RecordID    string `json:"record_id"`
	OperationID string `json:"operation_id"`
	Outcome     string `json:"outcome"`
	CreatedAt   string `json:"created_at"`
	Replayed    *bool  `json:"replayed"`
}

func NewSupabaseCheckpointFinalizationAuditor(client account.Client, path string, trust CheckpointAuditTrust) (*SupabaseCheckpointFinalizationAuditor, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("checkpoint audit session path is required")
	}
	pins, err := parseCheckpointAuditPins(trust.SPKISHA256Pins)
	if err != nil || !validCheckpointAuditAuthority(trust.Hostname, trust.Port) {
		return nil, errors.New("independently provisioned checkpoint audit hostname and SPKI pins are required")
	}
	session, err := account.Load(path)
	if err != nil {
		return nil, fmt.Errorf("load authenticated audit session: %w", err)
	}
	if _, err := auditEndpoint(session, trust); err != nil {
		return nil, err
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("checkpoint audit default HTTP transport is unavailable")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: trust.Hostname}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("checkpoint audit peer certificate missing")
		}
		actual := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		for _, expected := range pins {
			if subtle.ConstantTimeCompare(actual[:], expected[:]) == 1 {
				return nil
			}
		}
		return errors.New("checkpoint audit SPKI pin mismatch")
	}
	transport := defaultTransport.Clone()
	transport.TLSClientConfig = tlsConfig
	return &SupabaseCheckpointFinalizationAuditor{
		trust: trust, client: client, sessionPath: path, session: session,
		http: &http.Client{
			Timeout: 12 * time.Second, Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func validCheckpointAuditAuthority(host string, port uint16) bool {
	if host == "" || strings.TrimSpace(host) != host || strings.ToLower(host) != host ||
		strings.HasSuffix(host, ".") || port == 0 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 { return false }
	for _, label := range strings.Split(host, ".") {
		if len(label)==0 || len(label)>63 || label[0]=='-' || label[len(label)-1]=='-' { return false }
		for _, ch := range label { if !(ch>='a'&&ch<='z'||ch>='0'&&ch<='9'||ch=='-') { return false } }
	}
	return true
}

func parseCheckpointAuditPins(raw string) ([][sha256.Size]byte, error) {
	parts := strings.Split(strings.TrimSpace(raw), ",")
	if len(parts)==0 || len(parts)>4 { return nil, ErrCheckpointUnavailable }
	pins:=make([][sha256.Size]byte,0,len(parts));seen:=make(map[[sha256.Size]byte]bool)
	for _,part:=range parts {
		part=strings.TrimSpace(part)
		if len(part)!=sha256.Size*2 { return nil, ErrCheckpointUnavailable }
		decoded,err:=hex.DecodeString(part);if err!=nil||len(decoded)!=sha256.Size||strings.ToLower(part)!=part{return nil,ErrCheckpointUnavailable}
		var pin [sha256.Size]byte;copy(pin[:],decoded);if seen[pin]{return nil,ErrCheckpointUnavailable};seen[pin]=true;pins=append(pins,pin)
	}
	return pins,nil
}

func auditEndpoint(session *account.Session, trust CheckpointAuditTrust) (string, error) {
	if session == nil { return "", errors.New("checkpoint audit session missing") }
	u, err := url.Parse(session.SupabaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" || strings.HasSuffix(u.Host, ":") {
		return "", errors.New("checkpoint audit requires a strict HTTPS Supabase origin")
	}
	port:=uint64(443)
	if raw:=u.Port();raw!="" { parsed,parseErr:=strconv.ParseUint(raw,10,16);if parseErr!=nil||parsed==0||strconv.FormatUint(parsed,10)!=raw{return "",errors.New("invalid checkpoint audit port")};port=parsed }
	if u.Hostname()!=trust.Hostname || uint16(port)!=trust.Port || !validCheckpointAuditAuthority(trust.Hostname,trust.Port) {
		return "", errors.New("checkpoint audit session origin does not match independent trust configuration")
	}
	return strings.TrimRight(u.String(), "/") + "/functions/v1/port-forward-finalization-audit", nil
}

func checkpointAuditPayload(request CheckpointRequest) (map[string]any, error) {
	if _, err := CheckpointRequestFingerprint(request); err != nil {
		return nil, err
	}
	endpoint := func(value CheckpointEndpoint) map[string]any {
		return map[string]any{
			"device_id":        value.DeviceID,
			"account_id":       value.AccountID,
			"organization_id":  value.OrganizationID,
			"revocation_epoch": value.RevocationEpoch,
		}
	}
	var router any
	if request.Router.DeviceID != "" {
		router = endpoint(request.Router)
	}
	return map[string]any{
		"version":                    1,
		"initiator":                  endpoint(request.Initiator),
		"destination":                endpoint(request.Destination),
		"router":                     router,
		"consuming_device_id":        request.ConsumingDeviceID,
		"jti":                        request.JTI,
		"authorization_sha256":       hex.EncodeToString(request.AuthorizationSHA256[:]),
		"route_authorization_sha256": hex.EncodeToString(request.RouteAuthorizationSHA256[:]),
		"route_authorization_id": request.RouteAuthorizationID,
		"route_authorization_jti": request.RouteAuthorizationJTI,
		"route_authorization_json": request.RouteAuthorizationJSON,
		"device_public_key":          request.DevicePublicKey,
		"device_signature":           request.DeviceSignature,
	}, nil
}

func (a *SupabaseCheckpointFinalizationAuditor) RecordCheckpointFinalization(
	ctx context.Context,
	request CheckpointRequest,
	operationID string,
	outcome string,
	evidence *CheckpointFinalizationEvidence,
) error {
	if a == nil || ctx == nil || a.http == nil {
		return ErrCheckpointUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validFinalizationOutcome(outcome) {
		return errors.New("invalid checkpoint finalization outcome")
	}
	fingerprint, err := CheckpointRequestFingerprint(request)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, _ = io.WriteString(h, "wedecent-checkpoint-finalization-v1\n")
	_, _ = h.Write(fingerprint[:])
	if operationID != hex.EncodeToString(h.Sum(nil)) {
		return ErrCheckpointIntegrity
	}
	payload, err := checkpointAuditPayload(request)
	if err != nil {
		return err
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	payloadDigest := sha256.Sum256(canonical)
	evidencePayload, err := checkpointFinalizationEvidencePayload(evidence)
	if err != nil {
		return err
	}
	evidenceCanonical, err := json.Marshal(evidencePayload)
	if err != nil {
		return err
	}
	evidenceDigest := sha256.Sum256(evidenceCanonical)
	if outcome != CheckpointFinalizationStarted && evidence == nil {
		return errors.New("terminal checkpoint audit requires primary and witness evidence")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	fresh, refreshed, err := a.client.EnsureFresh(ctx, a.session, 45*time.Second)
	if err != nil {
		return fmt.Errorf("refresh audit session: %w", err)
	}
	if refreshed {
		if err := account.Save(a.sessionPath, fresh); err != nil {
			return fmt.Errorf("persist refreshed audit session: %w", err)
		}
		a.session = fresh
	}
	user, err := a.client.VerifyUser(ctx, fresh)
	if err != nil {
		return fmt.Errorf("verify audit session: %w", err)
	}
	if user.ID == "" || user.ID != fresh.UserID {
		return errors.New("authenticated audit user mismatch")
	}
	endpointURL, err := auditEndpoint(fresh, a.trust)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{
		"operation_id":    operationID,
		"outcome":         outcome,
		"payload_version": 1,
		"payload":         payload,
		"payload_sha256":  hex.EncodeToString(payloadDigest[:]),
		"evidence": evidencePayload,
		"evidence_sha256": hex.EncodeToString(evidenceDigest[:]),
	})
	if err != nil {
		return err
	}
	if len(body) == 0 || len(body) > checkpointAuditRequestMax {
		return errors.New("checkpoint audit request exceeds size limit")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+fresh.AccessToken)
	req.Header.Set("apikey", fresh.PublishableKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("checkpoint audit request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("checkpoint audit rejected with HTTP %d", resp.StatusCode)
	}
	var result finalizationAuditResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 16<<10))
	if err := decoder.Decode(&result); err != nil {
		return fmt.Errorf("decode audit response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("checkpoint audit response contains trailing data")
	}
	if result.OperationID != operationID || result.Outcome != outcome || result.Replayed == nil || !canonicalUUID(result.RecordID) {
		return errors.New("checkpoint audit response mismatch")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, result.CreatedAt)
	if err != nil || createdAt.IsZero() || createdAt.After(time.Now().Add(5*time.Minute)) {
		return errors.New("checkpoint audit timestamp invalid")
	}
	return ctx.Err()
}

func checkpointFinalizationEvidencePayload(evidence *CheckpointFinalizationEvidence) (map[string]any, error) {
	if evidence == nil {
		return map[string]any{}, nil
	}
	if len(evidence.WitnessAcknowledgements) > 16 || len(evidence.RevocationProofs) < 2 || len(evidence.RevocationProofs) > 3 {
		return nil, ErrCheckpointIntegrity
	}
	safe := func(v uint64) bool { return v <= 1<<53-1 }
	receipt := evidence.PrimaryReceipt
	if !safe(receipt.Generation) {
		return nil, ErrCheckpointIntegrity
	}
	receiptPayload := map[string]any{
		"version": receipt.Version, "device_id": receipt.DeviceID, "account_id": receipt.AccountID,
		"organization_id": receipt.OrganizationID, "jti": receipt.JTI,
		"authorization_sha256": hex.EncodeToString(receipt.AuthorizationSHA256[:]),
		"request_sha256": hex.EncodeToString(receipt.RequestSHA256[:]), "generation": receipt.Generation,
		"previous_hash": hex.EncodeToString(receipt.PreviousHash[:]), "record_hash": hex.EncodeToString(receipt.RecordHash[:]),
		"provider_key_id": receipt.ProviderKeyID, "signature": base64.StdEncoding.EncodeToString(receipt.Signature),
	}
	acks := make([]any, 0, len(evidence.WitnessAcknowledgements))
	for _, ack := range evidence.WitnessAcknowledgements {
		if len(ack.Signature) != 64 { return nil, ErrCheckpointIntegrity }
		acks = append(acks, map[string]any{
			"witness_id": ack.WitnessID, "scope": map[string]any{
				"device_id": ack.Scope.DeviceID, "account_id": ack.Scope.AccountID, "organization_id": ack.Scope.OrganizationID,
			}, "jti": ack.JTI, "request_sha256": hex.EncodeToString(ack.RequestSHA256[:]),
			"primary_receipt_sha256": hex.EncodeToString(ack.PrimaryReceiptSHA256[:]),
			"decision": ack.Decision, "status": ack.Status, "witness_key_id": ack.WitnessKeyID,
			"signature": base64.StdEncoding.EncodeToString(ack.Signature),
		})
	}
	proofs := make([]any, 0, len(evidence.RevocationProofs))
	for _, proof := range evidence.RevocationProofs {
		if len(proof.WitnessHeads) > 16 { return nil, ErrCheckpointIntegrity }
		head := proof.PrimaryHead
		if len(head.Signature) != 64 { return nil, ErrCheckpointIntegrity }
		if !safe(head.Generation) || !safe(head.RevocationEpoch) {
			return nil, ErrCheckpointIntegrity
		}
		primaryHead := map[string]any{
			"version": head.Version, "device_id": head.DeviceID, "account_id": head.AccountID,
			"organization_id": head.OrganizationID, "generation": head.Generation,
			"record_hash": hex.EncodeToString(head.RecordHash[:]), "revocation_epoch": head.RevocationEpoch,
			"provider_key_id": head.ProviderKeyID, "signature": base64.StdEncoding.EncodeToString(head.Signature),
		}
		witnessHeads := make([]any, 0, len(proof.WitnessHeads))
		for _, witnessHead := range proof.WitnessHeads {
			if len(witnessHead.Signature) != 64 || !safe(witnessHead.Generation) || !safe(witnessHead.PrimaryGeneration) || !safe(witnessHead.RevocationEpoch) {
				return nil, ErrCheckpointIntegrity
			}
			witnessHeads = append(witnessHeads, map[string]any{
				"witness_id": witnessHead.WitnessID, "scope": map[string]any{
					"device_id": witnessHead.Scope.DeviceID, "account_id": witnessHead.Scope.AccountID, "organization_id": witnessHead.Scope.OrganizationID,
				}, "generation": witnessHead.Generation, "record_hash": hex.EncodeToString(witnessHead.RecordHash[:]),
				"primary_generation": witnessHead.PrimaryGeneration, "primary_head": hex.EncodeToString(witnessHead.PrimaryHead[:]),
				"revocation_epoch": witnessHead.RevocationEpoch, "witness_key_id": witnessHead.WitnessKeyID,
				"signature": base64.StdEncoding.EncodeToString(witnessHead.Signature),
			})
		}
		proofs = append(proofs, map[string]any{"primary_head": primaryHead, "witness_heads": witnessHeads})
	}
	return map[string]any{"primary_receipt": receiptPayload, "witness_acknowledgements": acks, "revocation_proofs": proofs}, nil
}

func validFinalizationOutcome(value string) bool {
	switch value {
	case CheckpointFinalizationStarted,
		CheckpointFinalizationComplete,
		CheckpointFinalizationRevoked,
		CheckpointFinalizationMembershipUnavailable,
		CheckpointFinalizationFailed:
		return true
	default:
		return false
	}
}

var _ CheckpointFinalizationAuditor = (*SupabaseCheckpointFinalizationAuditor)(nil)
