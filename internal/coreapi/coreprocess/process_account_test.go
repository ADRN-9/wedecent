package coreprocess

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/coreapi/ipc"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
	"wedecent.com/wedecent/internal/identity"
)

type fakeProcessAccountClient struct {
	session *account.Session
	calls   int
}

func (f *fakeProcessAccountClient) Login(_ context.Context, supabaseURL, publishableKey, email, password string) (*account.Session, error) {
	f.calls++
	if supabaseURL != "https://example.supabase.co" || publishableKey != "publishable-test-key" || email != "person@example.test" || password != "test-password" {
		return nil, context.Canceled
	}
	return f.session, nil
}

func (f *fakeProcessAccountClient) EnsureFresh(_ context.Context, session *account.Session, _ time.Duration) (*account.Session, bool, error) {
	return session, false, nil
}

func (f *fakeProcessAccountClient) Logout(context.Context, *account.Session) error { return nil }

func processAccountSession() *account.Session {
	return &account.Session{
		Version:        account.SessionVersion,
		SupabaseURL:    "https://example.supabase.co",
		PublishableKey: "publishable-test-key",
		UserID:         "user-123",
		Email:          "person@example.test",
		AccessToken:    "access-token-secret",
		RefreshToken:   "refresh-token-secret",
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
	}
}

func TestOpenWiresAccountSignInWithoutExposingTokens(t *testing.T) {
	dir := t.TempDir()
	if _, err := identity.Ensure(dir, "core-test"); err != nil {
		t.Fatal(err)
	}
	fake := &fakeProcessAccountClient{session: processAccountSession()}
	server, err := Open(Config{
		ClientStateDir: dir,
		SupabaseURL:    "https://example.supabase.co",
		PublishableKey: "publishable-test-key",
		AccountClient:  fake,
	})
	if err != nil {
		t.Fatal(err)
	}

	params, err := json.Marshal(v1.SignInRequest{Email: "person@example.test", Password: "test-password"})
	if err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ServeOne(context.Background(), serverConn) }()
	if err := ipc.WriteRequest(clientConn, ipc.Request{
		Version: v1.Version,
		ID:      "account-1",
		Method:  v1.MethodAccountSignIn,
		Params:  params,
	}); err != nil {
		t.Fatal(err)
	}
	response, err := ipc.ReadResponse(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if response.Error != nil {
		t.Fatalf("response error = %#v", response.Error)
	}
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}
	if fake.calls != 1 {
		t.Fatalf("login calls = %d, want 1", fake.calls)
	}

	var status v1.Status
	if err := json.Unmarshal(response.Result, &status); err != nil {
		t.Fatal(err)
	}
	if !status.SignedIn || status.UserID != "user-123" || status.Email != "person@example.test" {
		t.Fatalf("status = %#v", status)
	}
	if _, err := account.Load(filepath.Join(dir, "account-session.json")); err != nil {
		t.Fatalf("persisted account session: %v", err)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, secret := range []string{"access-token-secret", "refresh-token-secret", "test-password"} {
		if strings.Contains(text, secret) {
			t.Fatalf("IPC response leaked credential material: %s", text)
		}
	}
}

func TestOpenRejectsPartialSupabaseConfiguration(t *testing.T) {
	dir := t.TempDir()
	if _, err := identity.Ensure(dir, "core-test"); err != nil {
		t.Fatal(err)
	}
	if err := account.Save(account.SessionPath(dir), processAccountSession()); err != nil {
		t.Fatal(err)
	}

	cases := []Config{
		{ClientStateDir: dir, SupabaseURL: "https://other.supabase.co"},
		{ClientStateDir: dir, PublishableKey: "other-publishable-key"},
	}
	for _, cfg := range cases {
		if _, err := Open(cfg); err == nil || !strings.Contains(err.Error(), "configured together") {
			t.Fatalf("Open(%+v) error = %v, want paired-configuration rejection", cfg, err)
		}
	}
}
