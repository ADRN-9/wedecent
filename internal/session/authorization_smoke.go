//go:build smoke

package session

import "wedecent.com/wedecent/internal/identity"

// NewSmokeRelayDirectAuthorizer is available only in explicitly tagged smoke-test binaries.
func NewSmokeRelayDirectAuthorizer(baseURL string, id *identity.Identity) DirectAuthorizer {
	return RelayDirectAuthorizer{
		BaseURL:               baseURL,
		Identity:              id,
		allowLoopbackForTests: true,
	}
}
