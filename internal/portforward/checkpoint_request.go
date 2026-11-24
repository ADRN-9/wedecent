package portforward

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
)

type CheckpointRouteAuthorizationVerifier interface {
	VerifyCheckpointRouteAuthorization(context.Context, Authorization) error
}

// CheckpointRouteFinalizationVerifier authenticates the historical route binding
// without checking current expiry or consuming the route JTI.
type CheckpointRouteFinalizationVerifier interface {
	VerifyCheckpointRouteAuthorizationForFinalization(context.Context, Authorization) error
}

// MeshCheckpointRouteAuthorizationVerifier adapts the dedicated route trust
// domain for normal consumption and historical finalization.
type MeshCheckpointRouteAuthorizationVerifier struct {
	Verifier mesh.RouteAuthorizationVerifier
}

func (v MeshCheckpointRouteAuthorizationVerifier) VerifyCheckpointRouteAuthorization(ctx context.Context, authorization Authorization) error {
	return v.Verifier.VerifyAndConsume(ctx, authorization.RouteAuthorization, authorization.Claims.Route, authorization.Claims.Router)
}

func (v MeshCheckpointRouteAuthorizationVerifier) VerifyCheckpointRouteAuthorizationForFinalization(ctx context.Context, authorization Authorization) error {
	return v.Verifier.VerifyHistorical(ctx, authorization.RouteAuthorization, authorization.Claims.Route, authorization.Claims.Router)
}

type CheckpointMembershipResolver interface {
	ResolveCheckpointMembership(context.Context, mesh.DeviceID) (CheckpointEndpoint, error)
}

// BuildCheckpointRequest derives JTI, authorization digest, endpoints and current
// membership epochs from one independently verified signed forwarding capability.
func checkpointRouteAuthorizationFingerprint(authorization mesh.RouteAuthorization) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(authorization)
	if err != nil {
		return [sha256.Size]byte{}, ErrRouteAuthorizationMismatch
	}
	return sha256.Sum256(encoded), nil
}

func BuildCheckpointRequest(
	ctx context.Context,
	authorization Authorization,
	controlPlaneKey ed25519.PublicKey,
	localDeviceID mesh.DeviceID,
	deviceSigner crypto.Signer,
	memberships CheckpointMembershipResolver,
	routeVerifier CheckpointRouteAuthorizationVerifier,
	now time.Time,
) (CheckpointRequest, error) {
	if ctx == nil || memberships == nil || deviceSigner == nil ||
		len(controlPlaneKey) != ed25519.PublicKeySize || !deviceIDPattern.MatchString(string(localDeviceID)) {
		return CheckpointRequest{}, ErrCheckpointIntegrity
	}
	if err := ctx.Err(); err != nil {
		return CheckpointRequest{}, err
	}
	claims := cloneClaims(authorization.Claims)
	if err := ValidateClaims(claims); err != nil {
		return CheckpointRequest{}, ErrAuthorizationInvalid
	}
	keyID, err := AuthorizationKeyID(controlPlaneKey)
	if err != nil || authorization.KeyID != keyID {
		return CheckpointRequest{}, ErrAuthorizationSignature
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(authorization.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != authorization.Signature {
		return CheckpointRequest{}, ErrAuthorizationSignature
	}
	message, err := canonicalMessage(authorization.KeyID, claims)
	if err != nil || !ed25519.Verify(controlPlaneKey, message, signature) {
		return CheckpointRequest{}, ErrAuthorizationSignature
	}
	if err := ValidateRouteAuthorizationBinding(authorization); err != nil {
		return CheckpointRequest{}, err
	}
	var routeAuthorizationHash [sha256.Size]byte
	var routeAuthorizationID, routeAuthorizationJTI, routeAuthorizationJSON string
	var routerMembership CheckpointEndpoint
	if claims.Router != "" {
		if routeVerifier == nil {
			return CheckpointRequest{}, ErrRouteAuthorizationRequired
		}
		if err := routeVerifier.VerifyCheckpointRouteAuthorization(ctx, authorization); err != nil {
			return CheckpointRequest{}, errors.Join(ErrRouteAuthorizationMismatch, err)
		}
		routeBytes, marshalErr := json.Marshal(authorization.RouteAuthorization)
		if marshalErr != nil {
			return CheckpointRequest{}, ErrRouteAuthorizationMismatch
		}
		routeAuthorizationHash = sha256.Sum256(routeBytes)
		routeAuthorizationJSON = string(routeBytes)
		routeAuthorizationID = authorization.RouteAuthorization.Claims.Route.ID
		routeAuthorizationJTI = authorization.RouteAuthorization.Claims.JTI
		routerMembership, err = memberships.ResolveCheckpointMembership(ctx, claims.Router)
		if err != nil {
			return CheckpointRequest{}, errors.Join(ErrCheckpointUnavailable, err)
		}
		if routerMembership.DeviceID != string(claims.Router) || !validCheckpointEndpoint(routerMembership) {
			return CheckpointRequest{}, ErrCheckpointRevoked
		}
	}
	if localDeviceID != claims.InitiatingDevice && localDeviceID != claims.DestinationDevice {
		return CheckpointRequest{}, ErrAuthorizationMismatch
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	if claims.IssuedAtUnixMS > now.UnixMilli() {
		return CheckpointRequest{}, ErrAuthorizationNotYetValid
	}
	if claims.ExpiresAtUnixMS <= now.UnixMilli() {
		return CheckpointRequest{}, ErrAuthorizationExpired
	}
	initiator, err := memberships.ResolveCheckpointMembership(ctx, claims.InitiatingDevice)
	if err != nil {
		return CheckpointRequest{}, errors.Join(ErrCheckpointRevoked, err)
	}
	destination, err := memberships.ResolveCheckpointMembership(ctx, claims.DestinationDevice)
	if err != nil {
		return CheckpointRequest{}, errors.Join(ErrCheckpointRevoked, err)
	}
	if initiator.DeviceID != string(claims.InitiatingDevice) ||
		destination.DeviceID != string(claims.DestinationDevice) ||
		initiator.OrganizationID != destination.OrganizationID ||
		!validCheckpointEndpoint(initiator) || !validCheckpointEndpoint(destination) {
		return CheckpointRequest{}, ErrCheckpointRevoked
	}
	publicKey, ok := deviceSigner.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize || identity.DeviceID(publicKey) != string(localDeviceID) {
		return CheckpointRequest{}, ErrCheckpointIntegrity
	}
	digestInput := make([]byte, 0, len(message)+len(signature))
	digestInput = append(digestInput, message...)
	digestInput = append(digestInput, signature...)
	request := CheckpointRequest{
		Initiator: initiator, Destination: destination, ConsumingDeviceID: string(localDeviceID),
		JTI: claims.JTI, AuthorizationSHA256: sha256.Sum256(digestInput), RouteAuthorizationSHA256: routeAuthorizationHash,
		RouteAuthorizationID: routeAuthorizationID, RouteAuthorizationJTI: routeAuthorizationJTI,
		RouteAuthorizationJSON: routeAuthorizationJSON, Router: routerMembership,
	}
	return SignCheckpointRequest(deviceSigner, request)
}
