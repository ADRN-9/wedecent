//go:build wedecent_smoke_test && !wedecent_release

package session

import "wedecent.com/wedecent/internal/identity"

// ValidateSmokeDirectAuthorizationOrigin permits loopback only in explicitly tagged smoke binaries.
func ValidateSmokeDirectAuthorizationOrigin(baseURL string) error {
	_, err := directAuthorizationOrigin(baseURL, true)
	return err
}

// NewSmokeRelayDirectAuthorizer is available only in explicitly tagged smoke-test binaries.
func NewSmokeRelayDirectAuthorizer(baseURL string, id *identity.Identity) DirectAuthorizer {
	return RelayDirectAuthorizer{
		BaseURL:               baseURL,
		Identity:              id,
		allowLoopbackForTests: true,
	}
}
