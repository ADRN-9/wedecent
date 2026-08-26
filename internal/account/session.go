package account

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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	SessionVersion = 1
	maxSessionSize = 64 << 10
)

var ErrNoSession = errors.New("WeDecent account session not found")

type Session struct {
	Version        int    `json:"version"`
	SupabaseURL    string `json:"supabase_url"`
	PublishableKey string `json:"publishable_key"`
	UserID         string `json:"user_id"`
	Email          string `json:"email"`
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	ExpiresAt      int64  `json:"expires_at"`
}

type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type Client struct {
	HTTP *http.Client
	Now  func() time.Time
}

type authResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at"`
	User         User   `json:"user"`
}

func SessionPath(stateDir string) string {
	return filepath.Join(stateDir, "account-session.json")
}

func Load(path string) (*Session, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoSession
		}
		return nil, fmt.Errorf("stat account session: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("account session file must not be a symbolic link")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read account session: %w", err)
	}
	if len(data) == 0 || len(data) > maxSessionSize {
		return nil, errors.New("account session file has an invalid size")
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("account session permissions are too broad: %o (want 600)", info.Mode().Perm())
		}
	}
	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("decode account session: %w", err)
	}
	if err := session.validate(); err != nil {
		return nil, fmt.Errorf("invalid account session: %w", err)
	}
	return &session, nil
}

func Save(path string, session *Session) error {
	if session == nil {
		return errors.New("account session is nil")
	}
	if err := session.validate(); err != nil {
		return fmt.Errorf("invalid account session: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create account session directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("protect account session directory: %w", err)
	}
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fmt.Errorf("encode account session: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".account-session-*")
	if err != nil {
		return fmt.Errorf("create account session temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("protect account session temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write account session: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync account session: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close account session: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		// Windows does not replace an existing destination with os.Rename.
		if _, statErr := os.Stat(path); statErr != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("install account session: %w", err)
		}
		if removeErr := os.Remove(path); removeErr != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("replace account session: %w", removeErr)
		}
		if err := os.Rename(tmpPath, path); err != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("install account session: %w", err)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("protect account session: %w", err)
	}
	return nil
}

func Delete(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove account session: %w", err)
	}
	return nil
}

func (c Client) Login(ctx context.Context, supabaseURL, publishableKey, email, password string) (*Session, error) {
	baseURL, err := normalizeSupabaseURL(supabaseURL)
	if err != nil {
		return nil, err
	}
	publishableKey = strings.TrimSpace(publishableKey)
	email = strings.TrimSpace(email)
	if publishableKey == "" {
		return nil, errors.New("Supabase publishable key is required")
	}
	if email == "" {
		return nil, errors.New("account email is required")
	}
	if password == "" {
		return nil, errors.New("account password is required")
	}

	var response authResponse
	if err := c.doJSON(ctx, http.MethodPost, baseURL+"/auth/v1/token?grant_type=password", publishableKey, "", map[string]string{
		"email": email, "password": password,
	}, &response); err != nil {
		return nil, fmt.Errorf("Supabase login: %w", err)
	}
	session, err := c.sessionFromAuthResponse(baseURL, publishableKey, response, email)
	if err != nil {
		return nil, err
	}
	if session.UserID == "" {
		return nil, errors.New("Supabase auth response did not contain a user ID")
	}
	return session, nil
}

func (c Client) Refresh(ctx context.Context, session *Session) (*Session, error) {
	if session == nil {
		return nil, errors.New("account session is nil")
	}
	if err := session.validate(); err != nil {
		return nil, fmt.Errorf("invalid account session: %w", err)
	}
	var response authResponse
	if err := c.doJSON(ctx, http.MethodPost, session.SupabaseURL+"/auth/v1/token?grant_type=refresh_token", session.PublishableKey, "", map[string]string{
		"refresh_token": session.RefreshToken,
	}, &response); err != nil {
		return nil, fmt.Errorf("refresh Supabase session: %w", err)
	}
	refreshed, err := c.sessionFromAuthResponse(session.SupabaseURL, session.PublishableKey, response, session.Email)
	if err != nil {
		return nil, err
	}
	if refreshed.UserID == "" {
		refreshed.UserID = session.UserID
	}
	if refreshed.Email == "" {
		refreshed.Email = session.Email
	}
	return refreshed, nil
}

func (c Client) EnsureFresh(ctx context.Context, session *Session, minValidity time.Duration) (*Session, bool, error) {
	if session == nil {
		return nil, false, errors.New("account session is nil")
	}
	if err := session.validate(); err != nil {
		return nil, false, fmt.Errorf("invalid account session: %w", err)
	}
	if minValidity < 0 {
		minValidity = 0
	}
	if time.Unix(session.ExpiresAt, 0).After(c.now().Add(minValidity)) {
		return session, false, nil
	}
	refreshed, err := c.Refresh(ctx, session)
	if err != nil {
		return nil, false, err
	}
	return refreshed, true, nil
}

func (c Client) VerifyUser(ctx context.Context, session *Session) (User, error) {
	if session == nil {
		return User{}, errors.New("account session is nil")
	}
	if err := session.validate(); err != nil {
		return User{}, fmt.Errorf("invalid account session: %w", err)
	}
	var user User
	if err := c.doJSON(ctx, http.MethodGet, session.SupabaseURL+"/auth/v1/user", session.PublishableKey, session.AccessToken, nil, &user); err != nil {
		return User{}, fmt.Errorf("verify Supabase session: %w", err)
	}
	if strings.TrimSpace(user.ID) == "" {
		return User{}, errors.New("Supabase user response is missing an ID")
	}
	return user, nil
}

func (c Client) Logout(ctx context.Context, session *Session) error {
	if session == nil {
		return errors.New("account session is nil")
	}
	if err := session.validate(); err != nil {
		return fmt.Errorf("invalid account session: %w", err)
	}
	if err := c.doJSON(ctx, http.MethodPost, session.SupabaseURL+"/auth/v1/logout?scope=local", session.PublishableKey, session.AccessToken, map[string]any{}, nil); err != nil {
		return fmt.Errorf("Supabase logout: %w", err)
	}
	return nil
}

func (c Client) sessionFromAuthResponse(baseURL, publishableKey string, response authResponse, fallbackEmail string) (*Session, error) {
	if strings.TrimSpace(response.AccessToken) == "" || strings.TrimSpace(response.RefreshToken) == "" {
		return nil, errors.New("Supabase auth response did not contain access and refresh tokens")
	}
	expiresAt := response.ExpiresAt
	if expiresAt <= 0 && response.ExpiresIn > 0 {
		expiresAt = c.now().Add(time.Duration(response.ExpiresIn) * time.Second).Unix()
	}
	if expiresAt <= 0 {
		return nil, errors.New("Supabase auth response did not contain a usable expiry")
	}
	email := strings.TrimSpace(response.User.Email)
	if email == "" {
		email = strings.TrimSpace(fallbackEmail)
	}
	session := &Session{
		Version:        SessionVersion,
		SupabaseURL:    baseURL,
		PublishableKey: strings.TrimSpace(publishableKey),
		UserID:         strings.TrimSpace(response.User.ID),
		Email:          email,
		AccessToken:    strings.TrimSpace(response.AccessToken),
		RefreshToken:   strings.TrimSpace(response.RefreshToken),
		ExpiresAt:      expiresAt,
	}
	if err := session.validate(); err != nil {
		return nil, fmt.Errorf("invalid Supabase auth response: %w", err)
	}
	return session, nil
}

func (s *Session) validate() error {
	if s.Version != SessionVersion {
		return fmt.Errorf("unsupported version %d", s.Version)
	}
	baseURL, err := normalizeSupabaseURL(s.SupabaseURL)
	if err != nil {
		return err
	}
	if baseURL != s.SupabaseURL {
		return errors.New("Supabase URL is not normalized")
	}
	if strings.TrimSpace(s.PublishableKey) == "" {
		return errors.New("publishable key is missing")
	}
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("access token is missing")
	}
	if strings.TrimSpace(s.RefreshToken) == "" {
		return errors.New("refresh token is missing")
	}
	if s.ExpiresAt <= 0 {
		return errors.New("expiry is missing")
	}
	return nil
}

func normalizeSupabaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("Supabase URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", errors.New("Supabase URL must be an absolute URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("Supabase URL must not contain credentials, query parameters, or a fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("Supabase URL must not contain a path")
	}
	if u.Scheme != "https" {
		if u.Scheme != "http" || !loopbackHost(u.Hostname()) {
			return "", errors.New("Supabase URL must use https")
		}
	}
	u.Path = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c Client) doJSON(ctx context.Context, method, rawURL, publishableKey, accessToken string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return err
	}
	req.Header.Set("apikey", publishableKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return supabaseError(resp)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
		return nil
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 64<<10))
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode Supabase response: %w", err)
	}
	return nil
}

func supabaseError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	var payload struct {
		Message string `json:"message"`
		Msg     string `json:"msg"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(data, &payload)
	message := strings.TrimSpace(payload.Message)
	if message == "" {
		message = strings.TrimSpace(payload.Msg)
	}
	if message == "" {
		message = strings.TrimSpace(payload.Error)
	}
	if message == "" {
		message = http.StatusText(resp.StatusCode)
	}
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, message)
}

func (c Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (c Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
