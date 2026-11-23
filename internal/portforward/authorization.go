package portforward

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"wedecent.com/wedecent/internal/mesh"
)

const (
	AuthorizationVersion     = 1
	AuthorizationIssuer      = "wedecent-control-plane"
	AuthorizationAudience    = "wedecent-port-forwarder"
	PermissionLocal          = "port_forward.local"
	PermissionRemote         = "port_forward.remote"
	ProtocolTCP              = "tcp"
	MaxAuthorizationLifetime = time.Hour
	MaxRouteHops             = 2
)

const authorizationDomain = "wedecent-port-forward-v1"

var (
	ErrAuthorizationInvalid     = errors.New("portforward: invalid authorization")
	ErrAuthorizationSignature   = errors.New("portforward: invalid authorization signature")
	ErrAuthorizationExpired     = errors.New("portforward: authorization expired")
	ErrAuthorizationNotYetValid = errors.New("portforward: authorization is not yet valid")
	ErrAuthorizationMismatch    = errors.New("portforward: authorization does not match local endpoint")
	ErrAuthorizationReplay      = errors.New("portforward: authorization has already been used")
	ErrReplayUnavailable        = errors.New("portforward: replay protection is unavailable")
)

var (
	deviceIDPattern  = regexp.MustCompile(\`^wd_[a-z2-7]{16}$\`)
	forwardIDPattern = regexp.MustCompile(\`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$\`)
	jtiPattern       = regexp.MustCompile(\`^[A-Za-z0-9_-]{22}$\`)
	dnsLabelPattern  = regexp.MustCompile(\`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$\`)
)

type Direction string

const (
	DirectionLocal  Direction = "local"
	DirectionRemote Direction = "remote"
)

type ListenerExposure string

const (
	ExposureLoopback ListenerExposure = "loopback"
	ExposurePrivate  ListenerExposure = "private"
	ExposurePublic   ListenerExposure = "public"
)

func DefaultListenerPolicy(port uint16) ListenerPolicy {
	return ListenerPolicy{Address: "127.0.0.1", Port: port, Exposure: ExposureLoopback}
}

type ListenerPolicy struct {
	Address  string           \`json:"address"\`
	Port     uint16           \`json:"port"\`
	Exposure ListenerExposure \`json:"exposure"\`
}

type ResourceLimits struct {
	MaxConnections     uint16 \`json:"max_connections"\`
	MaxDurationSeconds uint32 \`json:"max_duration_seconds"\`
	IdleTimeoutSeconds uint32 \`json:"idle_timeout_seconds"\`
}

type Claims struct {
	Version            int            \`json:"v"\`
	Issuer             string         \`json:"iss"\`
	Audience           string         \`json:"aud"\`
	Permission         string         \`json:"permission"\`
	JTI                string         \`json:"jti"\`
	ForwardingID       string         \`json:"forwarding_id"\`
	Direction          Direction      \`json:"direction"\`
	InitiatingDevice   mesh.DeviceID  \`json:"initiating_device"\`
	DestinationDevice  mesh.DeviceID  \`json:"destination_device"\`
	Router             mesh.DeviceID  \`json:"router,omitempty"\`
	Route              mesh.Route     \`json:"route"\`
	DestinationAddress string         \`json:"destination_address"\`
	DestinationPort    uint16         \`json:"destination_port"\`
	Listener           ListenerPolicy \`json:"listener"\`
	Protocol           string         \`json:"protocol"\`
	IssuedAtUnixMS     int64          \`json:"iat_unix_ms"\`
	ExpiresAtUnixMS    int64          \`json:"exp_unix_ms"\`
	Limits             ResourceLimits \`json:"limits"\`
}

type Authorization struct {
	KeyID     string \`json:"kid"\`
	Claims    Claims \`json:"claims"\`
	Signature string \`json:"signature"\`
}

type ReplayStore interface {
	ConsumePortForwardAuthorization(context.Context, string, time.Time) error
}

type Verifier interface {
	VerifyAndConsume(context.Context, Authorization) (Claims, error)
}

type AuthorizationVerifier struct {
	PublicKey ed25519.PublicKey
	Replay    ReplayStore
	Now       func() time.Time
}

// AuthorizationKeyID derives the key identifier from public material only.
func AuthorizationKeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", ErrAuthorizationInvalid
	}
	digest := sha256.Sum256(publicKey)
	return "ed25519-" + base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

// SignAuthorization accepts a non-exporting crypto.Signer, not private-key bytes.
func SignAuthorization(signer crypto.Signer, claims Claims) (Authorization, error) {
	if signer == nil {
		return Authorization{}, ErrAuthorizationInvalid
	}
	publicKey, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return Authorization{}, ErrAuthorizationInvalid
	}
	claims = cloneClaims(claims)
	if err := ValidateClaims(claims); err != nil {
		return Authorization{}, err
	}
	keyID, err := AuthorizationKeyID(publicKey)
	if err != nil {
		return Authorization{}, err
	}
	message, err := canonicalMessage(keyID, claims)
	if err != nil {
		return Authorization{}, err
	}
	signature, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, message, signature) {
		return Authorization{}, fmt.Errorf("%w: signer/public-key mismatch", ErrAuthorizationSignature)
	}
	return Authorization{KeyID: keyID, Claims: claims, Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func (v AuthorizationVerifier) VerifyAndConsume(ctx context.Context, auth Authorization) (Claims, error) {
	if err := ctx.Err(); err != nil {
		return Claims{}, err
	}
	if len(v.PublicKey) != ed25519.PublicKeySize {
		return Claims{}, ErrAuthorizationInvalid
	}
	if v.Replay == nil {
		return Claims{}, ErrReplayUnavailable
	}
	claims := cloneClaims(auth.Claims)
	if err := ValidateClaims(claims); err != nil {
		return Claims{}, err
	}
	keyID, err := AuthorizationKeyID(v.PublicKey)
	if err != nil || auth.KeyID != keyID {
		return Claims{}, ErrAuthorizationSignature
	}
	signature, err := base64.RawURLEncoding.DecodeString(auth.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Claims{}, ErrAuthorizationSignature
	}
	message, err := canonicalMessage(auth.KeyID, claims)
	if err != nil || !ed25519.Verify(v.PublicKey, message, signature) {
		return Claims{}, ErrAuthorizationSignature
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	nowMS := now.UnixMilli()
	if claims.IssuedAtUnixMS > nowMS {
		return Claims{}, ErrAuthorizationNotYetValid
	}
	if claims.ExpiresAtUnixMS <= nowMS {
		return Claims{}, ErrAuthorizationExpired
	}
	if err := v.Replay.ConsumePortForwardAuthorization(ctx, claims.JTI, time.UnixMilli(claims.ExpiresAtUnixMS).UTC()); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

// MemoryReplay is suitable for tests and single-process development only.
type MemoryReplay struct {
	mu         sync.Mutex
	used       map[string]time.Time
	MaxEntries int
	Now        func() time.Time
}

func NewMemoryReplay(maxEntries int) *MemoryReplay {
	return &MemoryReplay{used: make(map[string]time.Time), MaxEntries: maxEntries}
}

func (r *MemoryReplay) ConsumePortForwardAuthorization(ctx context.Context, jti string, expiresAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r == nil {
		return ErrReplayUnavailable
	}
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.used == nil {
		r.used = make(map[string]time.Time)
	}
	for key, expiry := range r.used {
		if !expiry.After(now) {
			delete(r.used, key)
		}
	}
	if _, exists := r.used[jti]; exists {
		return ErrAuthorizationReplay
	}
	if r.MaxEntries < 1 || len(r.used) >= r.MaxEntries {
		return ErrReplayUnavailable
	}
	r.used[jti] = expiresAt.UTC()
	return nil
}

func ValidateClaims(c Claims) error {
	if c.Version != AuthorizationVersion || c.Issuer != AuthorizationIssuer || c.Audience != AuthorizationAudience || c.Protocol != ProtocolTCP {
		return ErrAuthorizationInvalid
	}
	if !forwardIDPattern.MatchString(c.ForwardingID) || !jtiPattern.MatchString(c.JTI) {
		return ErrAuthorizationInvalid
	}
	rawJTI, err := base64.RawURLEncoding.DecodeString(c.JTI)
	if err != nil || len(rawJTI) != 16 {
		return ErrAuthorizationInvalid
	}
	if !deviceIDPattern.MatchString(string(c.InitiatingDevice)) || !deviceIDPattern.MatchString(string(c.DestinationDevice)) || c.InitiatingDevice == c.DestinationDevice {
		return ErrAuthorizationInvalid
	}
	if c.Direction != DirectionLocal && c.Direction != DirectionRemote {
		return ErrAuthorizationInvalid
	}
	wantPermission := PermissionLocal
	if c.Direction == DirectionRemote {
		wantPermission = PermissionRemote
	}
	if c.Permission != wantPermission {
		return ErrAuthorizationInvalid
	}
	if c.Router != "" && (!deviceIDPattern.MatchString(string(c.Router)) || c.Router == c.InitiatingDevice || c.Router == c.DestinationDevice) {
		return ErrAuthorizationInvalid
	}
	if c.IssuedAtUnixMS <= 0 || c.ExpiresAtUnixMS <= c.IssuedAtUnixMS || c.ExpiresAtUnixMS-c.IssuedAtUnixMS > MaxAuthorizationLifetime.Milliseconds() {
		return ErrAuthorizationInvalid
	}
	if c.DestinationPort == 0 || c.Listener.Port == 0 || c.Limits.MaxConnections == 0 || c.Limits.MaxConnections > 64 || c.Limits.MaxDurationSeconds == 0 || c.Limits.MaxDurationSeconds > 3600 || c.Limits.IdleTimeoutSeconds < 5 || c.Limits.IdleTimeoutSeconds > 900 {
		return ErrAuthorizationInvalid
	}
	if c.Listener.Exposure != ExposureLoopback && c.Listener.Exposure != ExposurePrivate && c.Listener.Exposure != ExposurePublic {
		return ErrAuthorizationInvalid
	}
	if c.DestinationAddress != canonicalDestinationHost(c.DestinationAddress) || c.DestinationAddress == "" {
		return ErrAuthorizationInvalid
	}
	listenerIP, err := netip.ParseAddr(c.Listener.Address)
	if err != nil || listenerIP.Zone() != "" || listenerIP.String() != c.Listener.Address || listenerIP.Is4In6() {
		return ErrAuthorizationInvalid
	}
	if err := validateListenerExposure(listenerIP, c.Listener.Exposure); err != nil {
		return err
	}
	if c.Route.ExpiresAt.IsZero() || c.Route.ExpiresAt.UnixMilli() != c.ExpiresAtUnixMS || c.Route.ExpiresAt.Nanosecond()%1_000_000 != 0 {
		return ErrAuthorizationInvalid
	}
	if len(c.Route.Hops) < 1 || len(c.Route.Hops) > MaxRouteHops {
		return ErrAuthorizationInvalid
	}
	routeSource, routeDestination := c.InitiatingDevice, c.DestinationDevice
	if c.Direction == DirectionRemote {
		routeSource, routeDestination = c.DestinationDevice, c.InitiatingDevice
	}
	if c.Route.Source != routeSource || c.Route.Destination != routeDestination {
		return ErrAuthorizationInvalid
	}
	if len(c.Route.Hops) == 1 {
		if c.Router != "" {
			return ErrAuthorizationInvalid
		}
	} else {
		if c.Router == "" || c.Route.Hops[0].From != routeSource || c.Route.Hops[0].To != c.Router || c.Route.Hops[1].From != c.Router || c.Route.Hops[1].To != routeDestination {
			return ErrAuthorizationInvalid
		}
	}
	validateAt := time.UnixMilli(c.ExpiresAtUnixMS).Add(-time.Millisecond)
	if err := c.Route.Validate(validateAt); err != nil {
		return fmt.Errorf("%w: route: %v", ErrAuthorizationInvalid, err)
	}
	return nil
}

func ListenerDevice(c Claims) mesh.DeviceID {
	if c.Direction == DirectionLocal {
		return c.InitiatingDevice
	}
	return c.DestinationDevice
}

func canonicalDestinationHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\r\n\t %/\\@") {
		return ""
	}
	if ip, err := netip.ParseAddr(raw); err == nil {
		if ip.Zone() != "" {
			return ""
		}
		return ip.Unmap().String()
	}
	if len(raw) > 253 || raw != strings.ToLower(raw) || strings.HasSuffix(raw, ".") {
		return ""
	}
	if raw == "localhost" || strings.HasSuffix(raw, ".localhost") || strings.HasSuffix(raw, ".local") || strings.HasSuffix(raw, ".internal") || strings.HasSuffix(raw, ".home") || strings.HasSuffix(raw, ".lan") || strings.HasSuffix(raw, ".test") || strings.HasSuffix(raw, ".invalid") || strings.HasSuffix(raw, ".example") {
		return ""
	}
	for _, label := range strings.Split(raw, ".") {
		if !dnsLabelPattern.MatchString(label) {
			return ""
		}
	}
	return raw
}

func validateListenerExposure(ip netip.Addr, exposure ListenerExposure) error {
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return ErrAuthorizationInvalid
	}
	switch exposure {
	case ExposureLoopback:
		if !ip.IsLoopback() {
			return ErrAuthorizationInvalid
		}
	case ExposurePrivate:
		if !ip.IsPrivate() || ip.IsLoopback() {
			return ErrAuthorizationInvalid
		}
	case ExposurePublic:
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || isCloudMetadataIP(ip) || isReservedAddress(ip) {
			return ErrAuthorizationInvalid
		}
	default:
		return ErrAuthorizationInvalid
	}
	return nil
}

func canonicalMessage(keyID string, c Claims) ([]byte, error) {
	if err := ValidateClaims(c); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	writeString := func(value string) error {
		if uint64(len(value)) > uint64(^uint32(0)) {
			return ErrAuthorizationInvalid
		}
		if err := binary.Write(&b, binary.BigEndian, uint32(len(value))); err != nil {
			return err
		}
		_, err := b.WriteString(value)
		return err
	}
	writeUint64 := func(value uint64) error { return binary.Write(&b, binary.BigEndian, value) }
	if err := writeString(authorizationDomain); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.BigEndian, uint32(c.Version)); err != nil {
		return nil, err
	}
	for _, value := range []string{
		keyID, c.Issuer, c.Audience, c.Permission, c.JTI, c.ForwardingID,
		string(c.Direction), string(c.InitiatingDevice), string(c.DestinationDevice),
		string(c.Router), c.Route.ID, string(c.Route.Source), string(c.Route.Destination),
		c.DestinationAddress, c.Listener.Address, string(c.Listener.Exposure), c.Protocol,
	} {
		if err := writeString(value); err != nil {
			return nil, err
		}
	}
	for _, value := range []uint64{
		uint64(c.IssuedAtUnixMS), uint64(c.ExpiresAtUnixMS), uint64(c.DestinationPort),
		uint64(c.Listener.Port), uint64(c.Limits.MaxConnections),
		uint64(c.Limits.MaxDurationSeconds), uint64(c.Limits.IdleTimeoutSeconds),
	} {
		if err := writeUint64(value); err != nil {
			return nil, err
		}
	}
	if err := binary.Write(&b, binary.BigEndian, uint32(len(c.Route.Hops))); err != nil {
		return nil, err
	}
	for _, hop := range c.Route.Hops {
		for _, value := range []string{string(hop.From), string(hop.To), string(hop.Transport)} {
			if err := writeString(value); err != nil {
				return nil, err
			}
		}
		if err := writeUint64(hop.Cost); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

func cloneClaims(c Claims) Claims {
	c.Route.Hops = append([]mesh.RouteHop(nil), c.Route.Hops...)
	return c
}
