package account

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoginSaveLoadRefreshVerifyLogout(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var refreshCalls atomic.Int32
	var logoutCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("apikey"); got != "publishable-test" {
			t.Fatalf("apikey = %q", got)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/auth/v1/token" && r.URL.Query().Get("grant_type") == "password":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["email"] != "admin@example.com" || body["password"] != "correct horse" {
				t.Fatalf("unexpected login body: %#v", body)
			}
			writeJSON(t, w, map[string]any{
				"access_token": "access-1", "refresh_token": "refresh-1", "expires_in": 30,
				"user": map[string]any{"id": "user-1", "email": "admin@example.com"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/auth/v1/token" && r.URL.Query().Get("grant_type") == "refresh_token":
			refreshCalls.Add(1)
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["refresh_token"] != "refresh-1" {
				t.Fatalf("refresh token = %q", body["refresh_token"])
			}
			writeJSON(t, w, map[string]any{
				"access_token": "access-2", "refresh_token": "refresh-2", "expires_in": 3600,
				"user": map[string]any{"id": "user-1", "email": "admin@example.com"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/auth/v1/user":
			if r.Header.Get("Authorization") != "Bearer access-2" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			writeJSON(t, w, map[string]any{"id": "user-1", "email": "admin@example.com"})
		case r.Method == http.MethodPost && r.URL.Path == "/auth/v1/logout":
			if r.URL.Query().Get("scope") != "local" {
				t.Fatalf("logout scope = %q", r.URL.Query().Get("scope"))
			}
			logoutCalls.Add(1)
			if r.Header.Get("Authorization") != "Bearer access-2" {
				t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := Client{HTTP: server.Client(), Now: func() time.Time { return now }}
	session, err := client.Login(context.Background(), server.URL, "publishable-test", "admin@example.com", "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if session.AccessToken != "access-1" || session.RefreshToken != "refresh-1" || session.UserID != "user-1" {
		t.Fatalf("unexpected login session: %#v", session)
	}

	path := SessionPath(filepath.Join(t.TempDir(), "client"))
	if err := Save(path, session); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("session permissions = %o", info.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	refreshed, changed, err := client.EnsureFresh(context.Background(), loaded, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || refreshed.AccessToken != "access-2" || refreshed.RefreshToken != "refresh-2" {
		t.Fatalf("unexpected refreshed session: changed=%v %#v", changed, refreshed)
	}
	if refreshCalls.Load() != 1 {
		t.Fatalf("refresh calls = %d", refreshCalls.Load())
	}
	user, err := client.VerifyUser(context.Background(), refreshed)
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != "user-1" {
		t.Fatalf("user = %#v", user)
	}
	if err := client.Logout(context.Background(), refreshed); err != nil {
		t.Fatal(err)
	}
	if logoutCalls.Load() != 1 {
		t.Fatalf("logout calls = %d", logoutCalls.Load())
	}
	if err := Delete(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != ErrNoSession {
		t.Fatalf("Load after Delete error = %v", err)
	}
}

func TestLoadRejectsBroadUnixPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows permission bits do not model ACL access")
	}
	path := filepath.Join(t.TempDir(), "account-session.json")
	session := validSession("https://example.supabase.co", time.Now().Add(time.Hour).Unix())
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	// The test process inherits the caller's umask. Force the deliberately
	// broad mode after creation so this test is deterministic even under
	// security-conscious shells using umask 077.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "permissions are too broad") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	session := validSession("https://example.supabase.co", time.Now().Add(time.Hour).Unix())
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "account-session.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("error = %v", err)
	}
}

func TestEnsureFreshKeepsValidSession(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	session := validSession("https://example.supabase.co", now.Add(10*time.Minute).Unix())
	client := Client{Now: func() time.Time { return now }}
	got, changed, err := client.EnsureFresh(context.Background(), session, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if changed || got != session {
		t.Fatalf("changed=%v got=%p want=%p", changed, got, session)
	}
}

func TestLoginRejectsInsecureRemoteURL(t *testing.T) {
	client := Client{}
	_, err := client.Login(context.Background(), "http://example.com", "key", "a@example.com", "password")
	if err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("error = %v", err)
	}
}

func TestSupabaseErrorDoesNotEchoRawBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Invalid login credentials","secret":"do-not-echo"}`))
	}))
	defer server.Close()
	client := Client{HTTP: server.Client()}
	_, err := client.Login(context.Background(), server.URL, "key", "a@example.com", "wrong")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "do-not-echo") {
		t.Fatalf("error leaked raw body: %v", err)
	}
}

func validSession(baseURL string, expiresAt int64) *Session {
	return &Session{
		Version: SessionVersion, SupabaseURL: baseURL, PublishableKey: "publishable-test",
		UserID: "user-1", Email: "admin@example.com", AccessToken: "access", RefreshToken: "refresh", ExpiresAt: expiresAt,
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatal(err)
	}
}

func TestIssueConnectionGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/functions/v1/connection-grant" {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("apikey"); got != "publishable-test" {
			t.Fatalf("apikey = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access" {
			t.Fatalf("authorization = %q", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["client_device_id"] != "wd_aaaaaaaaaaaaaaaa" || body["target_device_id"] != "wd_bbbbbbbbbbbbbbbb" {
			t.Fatalf("body = %#v", body)
		}
		writeJSON(t, w, map[string]any{
			"grant": "header.payload.signature",
			"claims": map[string]any{
				"client_device_id": "wd_aaaaaaaaaaaaaaaa",
				"target_device_id": "wd_bbbbbbbbbbbbbbbb",
				"permission":       "terminal.connect",
			},
		})
	}))
	defer server.Close()

	session := validSession(server.URL, time.Now().Add(time.Hour).Unix())
	client := Client{HTTP: server.Client()}
	grant, err := client.IssueConnectionGrant(context.Background(), session, "wd_aaaaaaaaaaaaaaaa", "wd_bbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	if grant != "header.payload.signature" {
		t.Fatalf("grant = %q", grant)
	}
}

func TestIssueConnectionGrantRejectsMismatchedClaims(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{
			"grant": "header.payload.signature",
			"claims": map[string]any{
				"client_device_id": "wd_cccccccccccccccc",
				"target_device_id": "wd_bbbbbbbbbbbbbbbb",
				"permission":       "terminal.connect",
			},
		})
	}))
	defer server.Close()

	session := validSession(server.URL, time.Now().Add(time.Hour).Unix())
	client := Client{HTTP: server.Client()}
	if _, err := client.IssueConnectionGrant(context.Background(), session, "wd_aaaaaaaaaaaaaaaa", "wd_bbbbbbbbbbbbbbbb"); err == nil || !strings.Contains(err.Error(), "mismatched claims") {
		t.Fatalf("error = %v", err)
	}
}
