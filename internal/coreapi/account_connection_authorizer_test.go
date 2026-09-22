package coreapi

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"wedecent.com/wedecent/internal/account"
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
	"wedecent.com/wedecent/internal/trust"
)

type authorizationAccountClient struct {
	freshSession *account.Session
	grant        string
	route        mesh.Route
	auth         mesh.RouteAuthorization
	grantErr     error
	routeErr     error
}

func (c *authorizationAccountClient) Login(context.Context, string, string, string, string) (*account.Session, error) {
	return nil, errors.New("unused")
}
func (c *authorizationAccountClient) EnsureFresh(context.Context, *account.Session, time.Duration) (*account.Session, bool, error) {
	return c.freshSession, false, nil
}
func (c *authorizationAccountClient) Logout(context.Context, *account.Session) error { return nil }
func (c *authorizationAccountClient) IssueConnectionGrant(context.Context, *account.Session, string, string) (string, error) {
	return c.grant, c.grantErr
}
func (c *authorizationAccountClient) IssueRouteAuthorization(context.Context, *account.Session, account.RouteAuthorizationRequest) (mesh.Route, mesh.RouteAuthorization, error) {
	return c.route, c.auth, c.routeErr
}

func TestAccountServiceConnectionAuthorizationKeepsSessionInternal(t *testing.T) {
	dir := t.TempDir()
	id, err := identity.Ensure(dir, "account-authorizer")
	if err != nil {
		t.Fatal(err)
	}
	devices, err := trust.Open(filepath.Join(dir, "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	session := &account.Session{
		Version: 1, SupabaseURL: "https://example.supabase.co", PublishableKey: "publishable",
		UserID: "user-1", Email: "user@example.test", AccessToken: "secret-access", RefreshToken: "secret-refresh",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	status, err := NewReadService(id, session, devices)
	if err != nil {
		t.Fatal(err)
	}
	client := &authorizationAccountClient{freshSession: session, grant: "header.payload.signature"}
	service, err := NewAccountService(AccountServiceConfig{
		Client: client, SessionPath: account.SessionPath(dir), Status: status, InitialSession: session,
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.IssueConnectionGrant(context.Background(), id.ID, "wd_bbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	if grant != client.grant {
		t.Fatalf("grant = %q", grant)
	}
	public, err := status.GetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if public.UserID != session.UserID || public.Email != session.Email {
		t.Fatalf("status = %#v", public)
	}
}

func TestAccountServiceConnectionAuthorizationRequiresSignedInSession(t *testing.T) {
	dir := t.TempDir()
	id, err := identity.Ensure(dir, "account-authorizer")
	if err != nil {
		t.Fatal(err)
	}
	devices, err := trust.Open(filepath.Join(dir, "trusted-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	status, err := NewReadService(id, nil, devices)
	if err != nil {
		t.Fatal(err)
	}
	client := &authorizationAccountClient{grant: "header.payload.signature"}
	service, err := NewAccountService(AccountServiceConfig{Client: client, SessionPath: account.SessionPath(dir), Status: status})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueConnectionGrant(context.Background(), id.ID, "wd_bbbbbbbbbbbbbbbb"); !errors.Is(err, ErrAccountNotConfigured) {
		t.Fatalf("IssueConnectionGrant error = %v", err)
	}
}
