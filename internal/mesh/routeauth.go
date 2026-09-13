package mesh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	RouteAuthorizationVersion    = 1
	RouteAuthorizationIssuer     = "wedecent-control-plane"
	RouteAuthorizationAudience   = "wedecent-mesh-router"
	RouteAuthorizationPermission = "mesh.forward"

	MaxRouteAuthorizationLifetime = 120 * time.Second
)

var (
	ErrRouteAuthorizationInvalid       = errors.New("mesh: invalid route authorization")
	ErrRouteAuthorizationSignature     = errors.New("mesh: invalid route authorization signature")
	ErrRouteAuthorizationExpired       = errors.New("mesh: route authorization expired")
	ErrRouteAuthorizationNotYetValid   = errors.New("mesh: route authorization is not yet valid")
	ErrRouteAuthorizationMismatch      = errors.New("mesh: route authorization does not match route")
	ErrRouteAuthorizationReplay        = errors.New("mesh: route authorization has already been used")
	ErrRouteAuthorizationReplayMissing = errors.New("mesh: route authorization replay protection is unavailable")
)

const routeAuthorizationDomain = "wedecent-mesh-forward-v1"

// RouteAuthorizationClaims are control-plane authorization claims for one
// exact A -> B -> C forwarding attempt.
//
// Route is embedded deliberately: authorization binds the exact route ID,
// source, destination, hops, transports, costs and route expiry. Router binds
// the intermediate forwarding device independently.
//
// IssuedAtUnixMS and ExpiresUnixMS use millisecond precision so the profile is
// safe to issue from JavaScript control-plane code without 64-bit nanosecond
// precision problems.
type RouteAuthorizationClaims struct {
	Version        int      `json:"v"`
	Issuer         string   `json:"iss"`
	Audience       string   `json:"aud"`
	Permission     string   `json:"permission"`
	JTI            string   `json:"jti"`
	Router         DeviceID `json:"router"`
	Route          Route    `json:"route"`
	IssuedAtUnixMS int64    `json:"iat_unix_ms"`
	ExpiresUnixMS  int64    `json:"exp_unix_ms"`
}

// RouteAuthorization is a signed single-use forwarding capability.
//
// KeyID identifies the configured control-plane verification key. Signature is
// unpadded base64url Ed25519 over a domain-separated canonical message.
type RouteAuthorization struct {
	KeyID     string                   `json:"kid"`
	Claims    RouteAuthorizationClaims `json:"claims"`
	Signature string                   `json:"signature"`
}

// RouteAuthorizationReplay consumes a JTI atomically.
//
// Implementations used by production listeners must retain consumed JTIs
// through their expiry. The in-memory implementation below is intended for
// library use and tests; production wiring may substitute durable state.
type RouteAuthorizationReplay interface {
	ConsumeRouteAuthorization(
		context.Context,
		string,
		time.Time,
	) error
}

// MemoryRouteAuthorizationReplay provides process-local atomic replay
// protection. Concurrent attempts to consume the same JTI yield exactly one
// success.
type MemoryRouteAuthorizationReplay struct {
	mu   sync.Mutex
	used map[string]time.Time
	now  func() time.Time
}

// NewMemoryRouteAuthorizationReplay constructs an in-memory replay guard.
func NewMemoryRouteAuthorizationReplay() *MemoryRouteAuthorizationReplay {
	return &MemoryRouteAuthorizationReplay{
		used: make(map[string]time.Time),
	}
}

func (r *MemoryRouteAuthorizationReplay) ConsumeRouteAuthorization(
	ctx context.Context,
	jti string,
	expiresAt time.Time,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r == nil {
		return ErrRouteAuthorizationReplayMissing
	}

	now := time.Now().UTC()
	if r.now != nil {
		now = r.now().UTC()
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.used == nil {
		r.used = make(map[string]time.Time)
	}

	for usedJTI, expiry := range r.used {
		if !expiry.After(now) {
			delete(r.used, usedJTI)
		}
	}

	if _, exists := r.used[jti]; exists {
		return ErrRouteAuthorizationReplay
	}

	r.used[jti] = expiresAt.UTC()
	return nil
}

// RouteAuthorizationVerifier verifies the dedicated control-plane Ed25519
// signature, exact route binding, expiry and single-use JTI.
//
// KeyID and PublicKey are deployment configuration. A source endpoint cannot
// make itself authorized to route merely by signing with its device key.
type RouteAuthorizationVerifier struct {
	KeyID     string
	PublicKey ed25519.PublicKey
	Replay    RouteAuthorizationReplay

	// Now exists for deterministic tests. Production callers leave it nil.
	Now func() time.Time
}

// NewRouteAuthorizationJTI returns a 128-bit unpadded base64url identifier.
func NewRouteAuthorizationJTI() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("mesh: generate route authorization jti: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// NewRouteAuthorizationClaims creates claims bound to an exact route.
//
// The caller chooses the JTI because issuance normally occurs in the control
// plane. expiresAt must equal the route expiry at millisecond precision.
func NewRouteAuthorizationClaims(
	route Route,
	router DeviceID,
	jti string,
	issuedAt time.Time,
) RouteAuthorizationClaims {
	route = cloneAuthorizationRoute(route)
	route.ExpiresAt = time.UnixMilli(
		route.ExpiresAt.UTC().UnixMilli(),
	).UTC()

	return RouteAuthorizationClaims{
		Version:        RouteAuthorizationVersion,
		Issuer:         RouteAuthorizationIssuer,
		Audience:       RouteAuthorizationAudience,
		Permission:     RouteAuthorizationPermission,
		JTI:            jti,
		Router:         router,
		Route:          route,
		IssuedAtUnixMS: issuedAt.UTC().UnixMilli(),
		ExpiresUnixMS:  route.ExpiresAt.UnixMilli(),
	}
}

// SignRouteAuthorization signs claims with a dedicated authorization key.
//
// The returned authorization owns a clone of the route hop slice so later
// mutation by the caller cannot change what the object claims to authorize.
func SignRouteAuthorization(
	privateKey ed25519.PrivateKey,
	keyID string,
	claims RouteAuthorizationClaims,
) (RouteAuthorization, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return RouteAuthorization{}, ErrRouteAuthorizationInvalid
	}

	auth := RouteAuthorization{
		KeyID:  strings.TrimSpace(keyID),
		Claims: cloneAuthorizationClaims(claims),
	}
	if err := validateRouteAuthorizationSyntax(auth); err != nil {
		return RouteAuthorization{}, err
	}

	message, err := routeAuthorizationMessage(auth)
	if err != nil {
		return RouteAuthorization{}, err
	}

	auth.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(privateKey, message),
	)
	return auth, nil
}

// VerifyAndConsume verifies authorization for one exact route and atomically
// consumes its JTI before the caller proceeds to destination dialing.
func (v RouteAuthorizationVerifier) VerifyAndConsume(
	ctx context.Context,
	auth RouteAuthorization,
	route Route,
	router DeviceID,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(v.PublicKey) != ed25519.PublicKeySize ||
		strings.TrimSpace(v.KeyID) == "" {
		return ErrRouteAuthorizationInvalid
	}
	if v.Replay == nil {
		return ErrRouteAuthorizationReplayMissing
	}

	auth = cloneRouteAuthorization(auth)
	if err := validateRouteAuthorizationSyntax(auth); err != nil {
		return err
	}

	if auth.KeyID != strings.TrimSpace(v.KeyID) {
		return ErrRouteAuthorizationSignature
	}

	signature, err := base64.RawURLEncoding.DecodeString(auth.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrRouteAuthorizationSignature
	}

	message, err := routeAuthorizationMessage(auth)
	if err != nil {
		return err
	}
	if !ed25519.Verify(v.PublicKey, message, signature) {
		return ErrRouteAuthorizationSignature
	}

	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	nowMS := now.UnixMilli()

	if auth.Claims.IssuedAtUnixMS > nowMS {
		return ErrRouteAuthorizationNotYetValid
	}
	if auth.Claims.ExpiresUnixMS <= nowMS {
		return ErrRouteAuthorizationExpired
	}
	if auth.Claims.ExpiresUnixMS-auth.Claims.IssuedAtUnixMS >
		MaxRouteAuthorizationLifetime.Milliseconds() {
		return ErrRouteAuthorizationInvalid
	}

	if err := route.Validate(now); err != nil {
		return fmt.Errorf("%w: %v", ErrRouteAuthorizationMismatch, err)
	}

	if !authorizationMatchesRoute(auth.Claims, route, router) {
		return ErrRouteAuthorizationMismatch
	}

	expiresAt := time.UnixMilli(auth.Claims.ExpiresUnixMS).UTC()
	if err := v.Replay.ConsumeRouteAuthorization(
		ctx,
		auth.Claims.JTI,
		expiresAt,
	); err != nil {
		return err
	}

	return nil
}

func validateRouteAuthorizationSyntax(auth RouteAuthorization) error {
	if strings.TrimSpace(auth.KeyID) == "" ||
		len(auth.KeyID) > 128 ||
		strings.ContainsAny(auth.KeyID, "\r\n\t") {
		return ErrRouteAuthorizationInvalid
	}

	c := auth.Claims
	if c.Version != RouteAuthorizationVersion ||
		c.Issuer != RouteAuthorizationIssuer ||
		c.Audience != RouteAuthorizationAudience ||
		c.Permission != RouteAuthorizationPermission ||
		strings.TrimSpace(string(c.Router)) == "" ||
		c.IssuedAtUnixMS <= 0 ||
		c.ExpiresUnixMS <= c.IssuedAtUnixMS {
		return ErrRouteAuthorizationInvalid
	}

	rawJTI, err := base64.RawURLEncoding.DecodeString(c.JTI)
	if err != nil || len(rawJTI) != 16 {
		return ErrRouteAuthorizationInvalid
	}

	// Validate route structure against a point immediately before its signed
	// expiry. Runtime freshness is checked separately by VerifyAndConsume.
	validateAt := time.UnixMilli(c.ExpiresUnixMS).Add(-time.Millisecond)
	if err := c.Route.Validate(validateAt); err != nil {
		return fmt.Errorf("%w: %v", ErrRouteAuthorizationInvalid, err)
	}
	if len(c.Route.Hops) != 2 {
		return ErrRouteAuthorizationInvalid
	}

	first := c.Route.Hops[0]
	second := c.Route.Hops[1]
	if first.From != c.Route.Source ||
		first.To != c.Router ||
		second.From != c.Router ||
		second.To != c.Route.Destination {
		return ErrRouteAuthorizationInvalid
	}

	canonicalRouteExpiry := time.UnixMilli(c.ExpiresUnixMS).UTC()
	if c.Route.ExpiresAt != canonicalRouteExpiry {
		return ErrRouteAuthorizationInvalid
	}
	if c.ExpiresUnixMS-c.IssuedAtUnixMS >
		MaxRouteAuthorizationLifetime.Milliseconds() {
		return ErrRouteAuthorizationInvalid
	}

	return nil
}

func authorizationMatchesRoute(
	claims RouteAuthorizationClaims,
	route Route,
	router DeviceID,
) bool {
	if claims.Router != router ||
		claims.Route.ID != route.ID ||
		claims.Route.Source != route.Source ||
		claims.Route.Destination != route.Destination ||
		claims.Route.ExpiresAt.UTC().UnixMilli() != route.ExpiresAt.UTC().UnixMilli() ||
		len(claims.Route.Hops) != len(route.Hops) {
		return false
	}

	for index := range route.Hops {
		want := claims.Route.Hops[index]
		got := route.Hops[index]
		if want.From != got.From ||
			want.To != got.To ||
			want.Transport != got.Transport ||
			want.Cost != got.Cost {
			return false
		}
	}

	return true
}

func routeAuthorizationMessage(
	auth RouteAuthorization,
) ([]byte, error) {
	if err := validateRouteAuthorizationSyntax(RouteAuthorization{
		KeyID:  auth.KeyID,
		Claims: auth.Claims,
	}); err != nil {
		return nil, err
	}

	c := auth.Claims
	var b bytes.Buffer

	// The encoding below is deliberately positional rather than textual.
	// Every variable-length field is uint32-length-prefixed and every integer
	// has a fixed network-byte-order width. Consequently, arbitrary string
	// contents can never inject, remove, or shift a signed field boundary.
	//
	// Changing this schema requires a new authorization domain/version.
	if err := writeRouteAuthorizationString(
		&b,
		routeAuthorizationDomain,
	); err != nil {
		return nil, err
	}

	writeRouteAuthorizationUint32(&b, uint32(c.Version))

	stringFields := []string{
		auth.KeyID,
		c.Issuer,
		c.Audience,
		c.Permission,
		c.JTI,
		string(c.Router),
		c.Route.ID,
		string(c.Route.Source),
		string(c.Route.Destination),
	}

	for _, value := range stringFields {
		if err := writeRouteAuthorizationString(
			&b,
			value,
		); err != nil {
			return nil, err
		}
	}

	writeRouteAuthorizationInt64(&b, c.IssuedAtUnixMS)
	writeRouteAuthorizationInt64(&b, c.ExpiresUnixMS)
	writeRouteAuthorizationInt64(
		&b,
		c.Route.ExpiresAt.UTC().UnixMilli(),
	)

	writeRouteAuthorizationUint32(
		&b,
		uint32(len(c.Route.Hops)),
	)

	for _, hop := range c.Route.Hops {
		if err := writeRouteAuthorizationString(
			&b,
			string(hop.From),
		); err != nil {
			return nil, err
		}

		if err := writeRouteAuthorizationString(
			&b,
			string(hop.To),
		); err != nil {
			return nil, err
		}

		if err := writeRouteAuthorizationString(
			&b,
			string(hop.Transport),
		); err != nil {
			return nil, err
		}

		writeRouteAuthorizationUint64(
			&b,
			uint64(hop.Cost),
		)
	}

	return append([]byte(nil), b.Bytes()...), nil
}

func writeRouteAuthorizationString(
	b *bytes.Buffer,
	value string,
) error {
	if uint64(len(value)) > uint64(^uint32(0)) {
		return ErrRouteAuthorizationInvalid
	}

	writeRouteAuthorizationUint32(
		b,
		uint32(len(value)),
	)

	_, _ = b.WriteString(value)
	return nil
}

func writeRouteAuthorizationUint32(
	b *bytes.Buffer,
	value uint32,
) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	_, _ = b.Write(encoded[:])
}

func writeRouteAuthorizationUint64(
	b *bytes.Buffer,
	value uint64,
) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = b.Write(encoded[:])
}

func writeRouteAuthorizationInt64(
	b *bytes.Buffer,
	value int64,
) {
	writeRouteAuthorizationUint64(
		b,
		uint64(value),
	)
}

func cloneRouteAuthorization(auth RouteAuthorization) RouteAuthorization {
	auth.Claims = cloneAuthorizationClaims(auth.Claims)
	return auth
}

func cloneAuthorizationClaims(
	claims RouteAuthorizationClaims,
) RouteAuthorizationClaims {
	claims.Route = cloneAuthorizationRoute(claims.Route)
	return claims
}

func cloneAuthorizationRoute(route Route) Route {
	route.Hops = append([]RouteHop(nil), route.Hops...)
	return route
}
