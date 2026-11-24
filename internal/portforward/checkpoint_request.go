package portforward

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
)

type CheckpointRouteAuthorizationVerifier interface {
	VerifyCheckpointRouteAuthorization(context.Context, Authorization) error
}

type CheckpointMembershipResolver interface {
	ResolveCheckpointMembership(context.Context, mesh.DeviceID) (CheckpointEndpoint, error)
}

// BuildCheckpointRequest derives JTI, authorization digest, endpoints and current
// membership epochs from one independently verified signed forwarding capability.
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
	if claims.Router != "" {
		if routeVerifier == nil {
			return CheckpointRequest{}, ErrRouteAuthorizationRequired
		}
		if err := routeVerifier.VerifyCheckpointRouteAuthorization(ctx, authorization); err != nil {
			return CheckpointRequest{}, errors.Join(ErrRouteAuthorizationMismatch, err)
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
		JTI: claims.JTI, AuthorizationSHA256: sha256.Sum256(digestInput),
	}
	return SignCheckpointRequest(deviceSigner, request)
}
