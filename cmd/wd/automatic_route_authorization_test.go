package main

import (
	"context"
	"strings"
	"testing"

	"wedecent.com/wedecent/internal/account"
)

func TestAutomaticRouteAuthorizationRequiresLogin(t *testing.T) {
	_, _, err := automaticRouteAuthorization(
		context.Background(),
		t.TempDir(),
		account.RouteAuthorizationRequest{},
		account.Client{},
	)
	if err == nil || !strings.Contains(err.Error(), "wd account login") {
		t.Fatalf("error = %v", err)
	}
}
