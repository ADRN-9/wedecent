package portforward

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/account"
)

type SupabaseCheckpointFinalizationAuditor struct {
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

func NewSupabaseCheckpointFinalizationAuditor(client account.Client, path string) (*SupabaseCheckpointFinalizationAuditor, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("checkpoint audit session path is required")
	}
	session, err := account.Load(path)
	if err != nil {
		return nil, fmt.Errorf("load authenticated audit session: %w", err)
	}
	if _, err := auditEndpoint(session); err != nil {
		return nil, err
	}
	return &SupabaseCheckpointFinalizationAuditor{
		client:      client,
		sessionPath: path,
		session:     session,
		http: &http.Client{
			Timeout: 12 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func auditEndpoint(session *account.Session) (string, error) {
	if session == nil {
		return "", errors.New("checkpoint audit session missing")
	}
	u, err := url.Parse(session.SupabaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("checkpoint audit requires authenticated HTTPS Supabase origin")
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
		"device_public_key":          request.DevicePublicKey,
		"device_signature":           request.DeviceSignature,
	}, nil
}

func (a *SupabaseCheckpointFinalizationAuditor) RecordCheckpointFinalization(
	ctx context.Context,
	request CheckpointRequest,
	operationID string,
	outcome string,
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
	endpointURL, err := auditEndpoint(fresh)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{
		"operation_id":    operationID,
		"outcome":         outcome,
		"payload_version": 1,
		"payload":         payload,
		"payload_sha256":  hex.EncodeToString(payloadDigest[:]),
	})
	if err != nil {
		return err
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
	if _, err := time.Parse(time.RFC3339Nano, result.CreatedAt); err != nil {
		return errors.New("checkpoint audit timestamp invalid")
	}
	return ctx.Err()
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
