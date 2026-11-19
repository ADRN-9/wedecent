//go:build !smoke

package main

import (
	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/session"
)

func newRelayDirectAuthorizer(baseURL string, id *identity.Identity) session.DirectAuthorizer {
	return session.RelayDirectAuthorizer{BaseURL: baseURL, Identity: id}
}
