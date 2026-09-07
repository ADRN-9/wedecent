package session

import (
	"bytes"
	"context"
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
)

type RelayDirectAuthorizer struct {
	BaseURL      string
	Identity     *identity.Identity
	TicketSource relayauth.TicketSource
	HTTP         *http.Client
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

	endpoint, err := directAuthorizationURL(a.BaseURL, targetDeviceID)
	if err != nil {
		return err
	}
	ticketSource := a.TicketSource
	if ticketSource == nil {
		ticketSource = relayauth.NewTicketSource(a.Identity)
	}
	ticket, err := ticketSource(ctx, a.BaseURL, targetDeviceID, "authorize", 0)
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
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Host == "" {
		return "", errors.New("direct authorization service must be a valid URL")
	}
	switch u.Scheme {
	case "https":
	case "wss":
		u.Scheme = "https"
	case "http", "ws":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("direct authorization service requires HTTPS except on loopback")
		}
		u.Scheme = "http"
	default:
		return "", errors.New("direct authorization service must use https or wss")
	}
	u.User = nil
	u.Path = "/v1/direct-authorize/" + targetDeviceID
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
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
