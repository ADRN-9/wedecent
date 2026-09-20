package coreapi

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/account"
	v1 "wedecent.com/wedecent/internal/coreapi/v1"
)

type fakeAccountClient struct {
	loginSession  *account.Session
	loginErr      error
	ensureSession *account.Session
	ensureErr     error
	logoutErr     error

	loginCalls  int
	ensureCalls int
	logoutCalls int

	sawSupabaseURL    bool
	sawPublishableKey bool
	sawEmail          bool
	sawPassword       bool
}

func (f *fakeAccountClient) Login(_ context.Context, supabaseURL, publishableKey, email, password string) (*account.Session, error) {
	f.loginCalls++
	f.sawSupabaseURL = supabaseURL == "https://example.supabase.co"
	f.sawPublishableKey = publishableKey == "publishable-test-key"
	f.sawEmail = email == "person@example.test"
	f.sawPassword = password == "correct horse battery staple"
	return f.loginSession, f.loginErr
}

func (f *fakeAccountClient) EnsureFresh(_ context.Context, session *account.Session, _ time.Duration) (*account.Session, bool, error) {
	f.ensureCalls++
	if f.ensureErr != nil {
		return nil, false, f.ensureErr
	}
	if f.ensureSession != nil {
		return f.ensureSession, f.ensureSession != session, nil
	}
	return session, false, nil
}

func (f *fakeAccountClient) Logout(context.Context, *account.Session) error {
	f.logoutCalls++
	return f.logoutErr
}

func validAccountSession() *account.Session {
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

func newAccountStatusService() *ReadService {
	return &ReadService{
		deviceID:   "wd_aaaaaaaaaaaaaaaa",
		deviceName: "local",
	}
}

func TestNewAccountServiceValidatesDependencies(t *testing.T) {
	status := newAccountStatusService()
	client := &fakeAccountClient{}
	path := filepath.Join(t.TempDir(), "account-session.json")

	cases := []AccountServiceConfig{
		{SessionPath: path, Status: status},
		{Client: client, Status: status},
		{Client: client, SessionPath: path},
		{Client: client, SessionPath: path, Status: status, InitialSession: &account.Session{}},
	}
	for _, cfg := range cases {
		if _, err := NewAccountService(cfg); err == nil {
			t.Fatalf("NewAccountService(%+v) succeeded", cfg)
		}
	}
}

func TestAccountServiceSignInPersistsBeforePublishingStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account-session.json")
	status := newAccountStatusService()
	client := &fakeAccountClient{loginSession: validAccountSession()}
	service, err := NewAccountService(AccountServiceConfig{
		Client:         client,
		SupabaseURL:    " https://example.supabase.co ",
		PublishableKey: " publishable-test-key ",
		SessionPath:    path,
		Status:         status,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := service.SignIn(context.Background(), v1.SignInRequest{
		Email:    " person@example.test ",
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.loginCalls != 1 || !client.sawSupabaseURL || !client.sawPublishableKey || !client.sawEmail || !client.sawPassword {
		t.Fatalf("unexpected login call state: %#v", client)
	}
	if !got.SignedIn || got.UserID != "user-123" || got.Email != "person@example.test" {
		t.Fatalf("sign-in status = %#v", got)
	}

	persisted, err := account.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.AccessToken != "access-token-secret" || persisted.RefreshToken != "refresh-token-secret" {
		t.Fatal("persisted session did not contain the authenticated credentials")
	}

	current, err := status.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if current != got {
		t.Fatalf("published status = %#v, want %#v", current, got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "token-secret") || strings.Contains(string(encoded), "correct horse") {
		t.Fatalf("status leaked credential material: %s", encoded)
	}
}

func TestAccountServiceSignInFailureIsSanitizedAndDoesNotPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account-session.json")
	status := newAccountStatusService()
	client := &fakeAccountClient{loginErr: errors.New("remote rejected password=super-secret")}
	service, err := NewAccountService(AccountServiceConfig{
		Client:         client,
		SupabaseURL:    "https://example.supabase.co",
		PublishableKey: "publishable-test-key",
		SessionPath:    path,
		Status:         status,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.SignIn(context.Background(), v1.SignInRequest{
		Email:    "person@example.test",
		Password: "correct horse battery staple",
	})
	if !errors.Is(err, ErrAccountOperation) {
		t.Fatalf("SignIn error = %v, want ErrAccountOperation", err)
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("SignIn error leaked backend detail: %v", err)
	}
	if _, err := account.Load(path); !errors.Is(err, account.ErrNoSession) {
		t.Fatalf("account.Load after failed sign-in = %v, want ErrNoSession", err)
	}
	current, err := status.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if current.SignedIn || current.UserID != "" || current.Email != "" {
		t.Fatalf("failed sign-in changed status: %#v", current)
	}
}

func TestAccountServiceRejectsInvalidLoginSessionBeforePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account-session.json")
	status := newAccountStatusService()
	invalid := validAccountSession()
	invalid.UserID = ""
	client := &fakeAccountClient{loginSession: invalid}
	service, err := NewAccountService(AccountServiceConfig{
		Client:         client,
		SupabaseURL:    "https://example.supabase.co",
		PublishableKey: "publishable-test-key",
		SessionPath:    path,
		Status:         status,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.SignIn(context.Background(), v1.SignInRequest{
		Email:    "person@example.test",
		Password: "correct horse battery staple",
	})
	if !errors.Is(err, ErrAccountOperation) {
		t.Fatalf("SignIn error = %v, want ErrAccountOperation", err)
	}
	if _, err := account.Load(path); !errors.Is(err, account.ErrNoSession) {
		t.Fatalf("invalid session was persisted: %v", err)
	}
}

func TestAccountServiceSignInRequiresConfigurationWithoutCallingNetwork(t *testing.T) {
	client := &fakeAccountClient{loginSession: validAccountSession()}
	service, err := NewAccountService(AccountServiceConfig{
		Client:      client,
		SessionPath: filepath.Join(t.TempDir(), "account-session.json"),
		Status:      newAccountStatusService(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.SignIn(context.Background(), v1.SignInRequest{
		Email:    "person@example.test",
		Password: "correct horse battery staple",
	})
	if !errors.Is(err, ErrAccountNotConfigured) {
		t.Fatalf("SignIn error = %v, want ErrAccountNotConfigured", err)
	}
	if client.loginCalls != 0 {
		t.Fatalf("login calls = %d, want 0", client.loginCalls)
	}
}

func TestAccountServiceSignOutIsLocallyAuthoritative(t *testing.T) {
	for _, tc := range []struct {
		name            string
		ensureErr       error
		logoutErr       error
		wantLogoutCalls int
	}{
		{name: "refresh failure", ensureErr: errors.New("network unavailable"), wantLogoutCalls: 0},
		{name: "remote logout failure", logoutErr: errors.New("remote logout failed"), wantLogoutCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "account-session.json")
			initial := validAccountSession()
			if err := account.Save(path, initial); err != nil {
				t.Fatal(err)
			}
			status := newAccountStatusService()
			client := &fakeAccountClient{ensureErr: tc.ensureErr, logoutErr: tc.logoutErr}
			service, err := NewAccountService(AccountServiceConfig{
				Client:         client,
				SupabaseURL:    initial.SupabaseURL,
				PublishableKey: initial.PublishableKey,
				SessionPath:    path,
				Status:         status,
				InitialSession: initial,
			})
			if err != nil {
				t.Fatal(err)
			}

			if err := service.SignOut(context.Background()); err != nil {
				t.Fatal(err)
			}
			if client.ensureCalls != 1 || client.logoutCalls != tc.wantLogoutCalls {
				t.Fatalf("remote calls: ensure=%d logout=%d", client.ensureCalls, client.logoutCalls)
			}
			if _, err := account.Load(path); !errors.Is(err, account.ErrNoSession) {
				t.Fatalf("local session still exists: %v", err)
			}
			current, err := status.GetStatus(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if current.SignedIn || current.UserID != "" || current.Email != "" {
				t.Fatalf("sign-out status = %#v", current)
			}
		})
	}
}

func TestAccountServiceCanceledSignOutPreservesLocalSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account-session.json")
	initial := validAccountSession()
	if err := account.Save(path, initial); err != nil {
		t.Fatal(err)
	}
	status := newAccountStatusService()
	client := &fakeAccountClient{}
	service, err := NewAccountService(AccountServiceConfig{
		Client:         client,
		SupabaseURL:    initial.SupabaseURL,
		PublishableKey: initial.PublishableKey,
		SessionPath:    path,
		Status:         status,
		InitialSession: initial,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := service.SignOut(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("SignOut error = %v, want context.Canceled", err)
	}
	if _, err := account.Load(path); err != nil {
		t.Fatalf("local session removed on canceled sign-out: %v", err)
	}
	current, err := status.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !current.SignedIn || current.UserID != initial.UserID {
		t.Fatalf("canceled sign-out changed status: %#v", current)
	}
}
