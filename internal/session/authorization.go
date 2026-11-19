package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/relayauth"
)

const (
	connectionGrantHeader           = "X-WeDecent-Connection-Grant"
	maxDirectAuthorizationBodyBytes = 1024
	maxGrantEvidenceBodyBytes       = 4096
	productionAuthorizationOrigin   = "https://relay.wedecent.com"
)

type GrantEventEvidence struct {
	EventID        string `json:"event_id"`
	RunID          string `json:"run_id"`
	AttemptID      string `json:"attempt_id"`
	Type           string `json:"type"`
	Outcome        string `json:"outcome"`
	GrantID        string `json:"grant_id"`
	JTI            string `json:"jti"`
	ClientDeviceID string `json:"client_device_id"`
	TargetDeviceID string `json:"target_device_id"`
	Permission     string `json:"permission"`
	Flow           string `json:"flow"`
	OccurredAt     string `json:"occurred_at"`
	RetainUntilMS  int64  `json:"retain_until_ms"`
}

type GrantConsumptionEvidence struct {
	Version               int                `json:"version"`
	AuthorizationRunID    string             `json:"authorization_run_id"`
	ValidationAttemptID   string             `json:"validation_attempt_id"`
	ConsumptionAttemptID  string             `json:"consumption_attempt_id"`
	ValidationEventID     string             `json:"validation_event_id"`
	ConsumptionEventID    string             `json:"consumption_event_id"`
	ValidationEvent       GrantEventEvidence `json:"validation_event"`
	ConsumptionEvent      GrantEventEvidence `json:"consumption_event"`
	GrantID               string             `json:"grant_id"`
	JTI                   string             `json:"jti"`
	ClientDeviceID        string             `json:"client_device_id"`
	TargetDeviceID        string             `json:"target_device_id"`
	Permission            string             `json:"permission"`
	Flow                  string             `json:"flow"`
	ValidationOutcome     string             `json:"validation_outcome"`
	ConsumptionOutcome    string             `json:"consumption_outcome"`
	ValidatedAt           string             `json:"validated_at"`
	ConsumedAt            string             `json:"consumed_at"`
	ExpiresAt             string             `json:"expires_at"`
	RetainUntilMS         int64              `json:"retain_until_ms"`
}

type GrantEvidenceVerifier interface {
	VerifyConsumption(context.Context, string, string, string, string) error
}

type GrantEvidenceProvider interface {
	VerifyConsumptionEvidence(context.Context, string, string, string, string) (GrantConsumptionEvidence, error)
}

type RelayDirectAuthorizer struct {
	BaseURL               string
	Identity              *identity.Identity
	TicketSource          relayauth.TicketSource
	HTTP                  *http.Client
	allowLoopbackForTests bool
}

func (a RelayDirectAuthorizer) Authorize(ctx context.Context, clientDeviceID, targetDeviceID, connectionGrant string) error {
	if a.Identity == nil || targetDeviceID != a.Identity.ID {
		return errors.New("direct authorization identity mismatch")
	}
	if !validSessionDeviceID(clientDeviceID) || !validSessionDeviceID(targetDeviceID) {
		return errors.New("direct authorization device ID is invalid")
	}
	connectionGrant = strings.TrimSpace(connectionGrant)
	if connectionGrant == "" || len(connectionGrant) > 16*1024 || strings.ContainsAny(connectionGrant, "\r\n\t ") {
		return errors.New("direct authorization grant is invalid")
	}

	origin, err := directAuthorizationOrigin(a.BaseURL, a.allowLoopbackForTests)
	if err != nil {
		return err
	}
	endpoint := origin + "/v1/direct-authorize/" + targetDeviceID
	ticketSource := a.TicketSource
	if ticketSource == nil {
		ticketSource = relayauth.NewTicketSource(a.Identity)
	}
	ticket, err := ticketSource(ctx, origin, targetDeviceID, "authorize", 0)
	if err != nil {
		return fmt.Errorf("create direct authorization proof: %w", err)
	}

	body, err := json.Marshal(struct {
		ClientDeviceID string `json:"client_device_id"`
	}{ClientDeviceID: clientDeviceID})
	if err != nil {
		return fmt.Errorf("encode direct authorization request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build direct authorization request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+ticket)
	req.Header.Set(connectionGrantHeader, connectionGrant)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")

	client := http.Client{Timeout: 10 * time.Second}
	if a.HTTP != nil {
		client = *a.HTTP
		if client.Timeout == 0 {
			client.Timeout = 10 * time.Second
		}
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("direct authorization request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDirectAuthorizationBodyBytes))
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusConflict:
		return errors.New("connection grant has already been used")
	case http.StatusUnauthorized, http.StatusForbidden:
		return errors.New("connection authorization was rejected")
	case http.StatusServiceUnavailable:
		return errors.New("connection authorization service is unavailable")
	default:
		return fmt.Errorf("connection authorization failed with HTTP %d", resp.StatusCode)
	}
}

func directAuthorizationURL(baseURL, targetDeviceID string) (string, error) {
	if !validSessionDeviceID(targetDeviceID) {
		return "", errors.New("invalid direct authorization target device ID")
	}
	origin, err := directAuthorizationOrigin(baseURL, false)
	if err != nil {
		return "", err
	}
	return origin + "/v1/direct-authorize/" + targetDeviceID, nil
}

func directAuthorizationOrigin(baseURL string, allowLoopbackForTests bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u == nil || u.Host == "" || u.Opaque != "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("direct authorization service must use the approved HTTPS origin https://relay.wedecent.com")
	}

	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if u.Scheme == "https" && host == "relay.wedecent.com" && (port == "" || port == "443") {
		return productionAuthorizationOrigin, nil
	}

	ip := net.ParseIP(host)
	loopback := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
	if allowLoopbackForTests && loopback && (u.Scheme == "http" || u.Scheme == "https") && port != "" {
		return u.Scheme + "://" + u.Host, nil
	}
	return "", errors.New("direct authorization service must use the approved HTTPS origin https://relay.wedecent.com; only explicit loopback URLs are allowed for local testing")
}

func ConnectionGrantJTI(connectionGrant string) (string, error) {
	parts := strings.Split(strings.TrimSpace(connectionGrant), ".")
	if len(parts) != 3 || parts[1] == "" {
		return "", errors.New("connection grant is malformed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("connection grant payload is malformed")
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || !validConnectionGrantJTI(claims.JTI) {
		return "", errors.New("connection grant identifier is malformed")
	}
	return strings.ToLower(claims.JTI), nil
}

func validConnectionGrantJTI(jti string) bool {
	if len(jti) != 36 {
		return false
	}
	for i, r := range jti {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
	}
	return true
}

func (a RelayDirectAuthorizer) VerifyConsumption(ctx context.Context, clientDeviceID, targetDeviceID, jti, flow string) error {
	_, err := a.VerifyConsumptionEvidence(ctx, clientDeviceID, targetDeviceID, jti, flow)
	return GrantConsumptionEvidence{}, err
}

func (a RelayDirectAuthorizer) VerifyConsumptionEvidence(ctx context.Context, clientDeviceID, targetDeviceID, jti, flow string) (GrantConsumptionEvidence, error) {
	if a.Identity == nil || targetDeviceID != a.Identity.ID ||
		!validSessionDeviceID(clientDeviceID) || !validSessionDeviceID(targetDeviceID) ||
		!validConnectionGrantJTI(jti) || (flow != "direct" && flow != "relay") {
		return GrantConsumptionEvidence{}, errors.New("grant evidence query identity is invalid")
	}
	origin, err := directAuthorizationOrigin(a.BaseURL, a.allowLoopbackForTests)
	if err != nil {
		return GrantConsumptionEvidence{}, err
	}
	ticketSource := a.TicketSource
	if ticketSource == nil {
		ticketSource = relayauth.NewTicketSource(a.Identity)
	}
	ticket, err := ticketSource(ctx, origin, targetDeviceID, "authorize", 0)
	if err != nil {
		return GrantConsumptionEvidence{}, fmt.Errorf("create grant evidence proof: %w", err)
	}

	endpoint := origin + "/v1/grant-evidence/" + targetDeviceID + "/" + strings.ToLower(jti)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return GrantConsumptionEvidence{}, fmt.Errorf("build grant evidence request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+ticket)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")

	client := http.Client{Timeout: 10 * time.Second}
	if a.HTTP != nil {
		client = *a.HTTP
		if client.Timeout == 0 {
			client.Timeout = 10 * time.Second
		}
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return GrantConsumptionEvidence{}, fmt.Errorf("grant evidence request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return GrantConsumptionEvidence{}, fmt.Errorf("grant validation/consumption evidence unavailable (HTTP %d)", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGrantEvidenceBodyBytes+1))
	if err != nil {
		return GrantConsumptionEvidence{}, fmt.Errorf("read grant evidence: %w", err)
	}
	if len(body) == 0 || len(body) > maxGrantEvidenceBodyBytes {
		return GrantConsumptionEvidence{}, errors.New("grant evidence response has an invalid size")
	}
	var evidence GrantConsumptionEvidence
	if err := json.Unmarshal(body, &evidence); err != nil {
		return GrantConsumptionEvidence{}, errors.New("grant evidence response is malformed")
	}
	if evidence.Version != 1 || evidence.JTI != strings.ToLower(jti) ||
		evidence.ClientDeviceID != clientDeviceID || evidence.TargetDeviceID != targetDeviceID ||
		evidence.Permission != "terminal.connect" || evidence.Flow != flow ||
		evidence.ValidationOutcome != "accepted" || evidence.ConsumptionOutcome != "consumed" ||
		evidence.GrantID == "" || evidence.RetainUntilMS <= time.Now().UnixMilli() ||
		!validConnectionGrantJTI(evidence.AuthorizationRunID) ||
		!validConnectionGrantJTI(evidence.ValidationAttemptID) ||
		!validConnectionGrantJTI(evidence.ConsumptionAttemptID) ||
		!validConnectionGrantJTI(evidence.ValidationEventID) ||
		!validConnectionGrantJTI(evidence.ConsumptionEventID) ||
		evidence.ValidationAttemptID == evidence.ConsumptionAttemptID ||
		evidence.ValidationEventID == evidence.ConsumptionEventID {
		return GrantConsumptionEvidence{}, errors.New("grant validation/consumption evidence does not match this session")
	}
	if !grantEventMatches(evidence.ValidationEvent, evidence, evidence.ValidationEventID,
		evidence.ValidationAttemptID, "authorization.validation", "accepted", evidence.ValidatedAt) ||
		!grantEventMatches(evidence.ConsumptionEvent, evidence, evidence.ConsumptionEventID,
			evidence.ConsumptionAttemptID, "authorization.consumption", "consumed", evidence.ConsumedAt) {
		return GrantConsumptionEvidence{}, errors.New("grant validation/consumption event records are incomplete or inconsistent")
	}
	for _, stamp := range []string{evidence.ValidatedAt, evidence.ConsumedAt, evidence.ExpiresAt} {
		if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
			return GrantConsumptionEvidence{}, errors.New("grant evidence timestamps are invalid")
		}
	}
	return evidence, nil
}

func validSessionDeviceID(s string) bool {
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

func grantEventMatches(
	event GrantEventEvidence,
	evidence GrantConsumptionEvidence,
	eventID, attemptID, eventType, outcome, occurredAt string,
) bool {
	return validConnectionGrantJTI(event.EventID) &&
		event.EventID == eventID &&
		event.RunID == evidence.AuthorizationRunID &&
		event.AttemptID == attemptID &&
		event.Type == eventType &&
		event.Outcome == outcome &&
		event.GrantID == evidence.GrantID &&
		event.JTI == evidence.JTI &&
		event.ClientDeviceID == evidence.ClientDeviceID &&
		event.TargetDeviceID == evidence.TargetDeviceID &&
		event.Permission == evidence.Permission &&
		event.Flow == evidence.Flow &&
		event.OccurredAt == occurredAt &&
		event.RetainUntilMS == evidence.RetainUntilMS
}
