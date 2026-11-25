package portforward

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"io"
	"time"
)

// AuthorizationIssuer creates short-lived, single-use forwarding capabilities.
// Its crypto.Signer must be provisioned independently of device and route keys.
type AuthorizationIssuer struct {
	Signer   crypto.Signer
	Lifetime time.Duration
	Now      func() time.Time
	Random   io.Reader
}

func (i AuthorizationIssuer) Issue(ctx context.Context, claims Claims) (Authorization, error) {
	if ctx == nil || i.Signer == nil {
		return Authorization{}, ErrAuthorizationInvalid
	}
	if err := ctx.Err(); err != nil {
		return Authorization{}, err
	}
	if claims.JTI != "" || claims.IssuedAtUnixMS != 0 || claims.ExpiresAtUnixMS != 0 {
		return Authorization{}, ErrAuthorizationInvalid
	}

	lifetime := i.Lifetime
	if lifetime == 0 {
		lifetime = MaxAuthorizationLifetime
	}
	if lifetime < time.Second || lifetime > MaxAuthorizationLifetime {
		return Authorization{}, ErrAuthorizationInvalid
	}
	now := time.Now().UTC()
	if i.Now != nil {
		now = i.Now().UTC()
	}
	if now.IsZero() {
		return Authorization{}, ErrAuthorizationInvalid
	}
	expires := now.Add(lifetime).UTC().Truncate(time.Millisecond)
	now = now.UTC().Truncate(time.Millisecond)

	random := i.Random
	if random == nil {
		random = rand.Reader
	}
	jtiBytes := make([]byte, 16)
	if _, err := io.ReadFull(random, jtiBytes); err != nil {
		return Authorization{}, ErrAuthorizationInvalid
	}
	if err := ctx.Err(); err != nil {
		return Authorization{}, err
	}

	claims = cloneClaims(claims)
	claims.JTI = base64.RawURLEncoding.EncodeToString(jtiBytes)
	claims.IssuedAtUnixMS = now.UnixMilli()
	claims.ExpiresAtUnixMS = expires.UnixMilli()
	claims.Route.ExpiresAt = expires
	return SignAuthorization(i.Signer, claims)
}
