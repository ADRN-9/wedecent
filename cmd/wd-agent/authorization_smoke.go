//go:build wedecent_smoke_test && !wedecent_release

package main

import (
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/session"
)

func newRelayDirectAuthorizer(baseURL string, id *identity.Identity) session.DirectAuthorizer {
	return session.NewSmokeRelayDirectAuthorizer(baseURL, id)
}

func validateRelayAuthorizationOrigin(baseURL string) error {
	return session.ValidateSmokeDirectAuthorizationOrigin(baseURL)
}
