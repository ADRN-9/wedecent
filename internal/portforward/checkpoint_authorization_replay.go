package portforward

import (
	"bytes"
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

// CheckpointAuthorizationReplay binds Local Core's verified capability to the
// witnessed checkpoint transaction. Bare-JTI replay calls are never accepted.
type CheckpointAuthorizationReplay struct {
	Provider            *WitnessedReplayCheckpointProvider
	ControlPlaneKey     ed25519.PublicKey
	LocalDeviceID       mesh.DeviceID
	DeviceSigner        crypto.Signer
	Memberships         CheckpointMembershipResolver
	RouteVerifier       CheckpointRouteAuthorizationVerifier
	FinalizationAuditor CheckpointFinalizationAuditor
	Now                 func() time.Time
}

// CheckpointFinalizationAuditor durably records historical-finalization outcomes.
type CheckpointFinalizationAuditor interface {
	RecordCheckpointFinalization(context.Context, CheckpointRequest, string) error
}

const (
	CheckpointFinalizationStarted               = "finalization_started"
	CheckpointFinalizationComplete              = "finalized"
	CheckpointFinalizationRevoked               = "rejected_revocation"
	CheckpointFinalizationMembershipUnavailable = "membership_unavailable"
	CheckpointFinalizationFailed                = "finalization_failed"
)

// FinalizeExpiredPortForwardAuthorization completes an already-consumed capability without creating a new authorization.
// The exact signed request must already exist in the durable pending journal.
func (r *CheckpointAuthorizationReplay) FinalizeExpiredPortForwardAuthorization(ctx context.Context, authorization Authorization) error {
	if r == nil || r.Provider == nil || r.DeviceSigner == nil || r.Memberships == nil || r.FinalizationAuditor == nil || len(r.ControlPlaneKey) != ed25519.PublicKeySize {
		return ErrCheckpointUnavailable
	}
	if ctx == nil {
		return ErrAuthorizationInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	devicePublicKey, ok := r.DeviceSigner.Public().(ed25519.PublicKey)
	if !ok || len(devicePublicKey) != ed25519.PublicKeySize || identity.DeviceID(devicePublicKey) != string(r.LocalDeviceID) ||
		bytes.Equal(devicePublicKey, r.ControlPlaneKey) || bytes.Equal(r.Provider.PrimaryKey, r.ControlPlaneKey) ||
		bytes.Equal(r.Provider.PrimaryKey, devicePublicKey) {
		return ErrCheckpointIntegrity
	}
	for _, witness := range r.Provider.Witnesses {
		if bytes.Equal(witness.PublicKey, r.ControlPlaneKey) || bytes.Equal(witness.PublicKey, devicePublicKey) {
			return ErrCheckpointIntegrity
		}
	}
	if err := r.Provider.ValidateConfiguration(); err != nil {
		return err
	}
	claims := cloneClaims(authorization.Claims)
	if err := ValidateClaims(claims); err != nil {
		return ErrAuthorizationInvalid
	}
	keyID, err := AuthorizationKeyID(r.ControlPlaneKey)
	if err != nil || authorization.KeyID != keyID {
		return ErrAuthorizationSignature
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(authorization.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != authorization.Signature {
		return ErrAuthorizationSignature
	}
	message, err := canonicalMessage(authorization.KeyID, claims)
	if err != nil || !ed25519.Verify(r.ControlPlaneKey, message, signature) {
		return ErrAuthorizationSignature
	}
	if err := ValidateRouteAuthorizationBinding(authorization); err != nil {
		return err
	}
	if claims.Router != "" {
		if r.RouteVerifier == nil {
			return ErrRouteAuthorizationRequired
		}
		historicalVerifier, ok := r.RouteVerifier.(CheckpointRouteFinalizationVerifier)
		if !ok {
			return ErrRouteAuthorizationRequired
		}
		if err := historicalVerifier.VerifyCheckpointRouteAuthorizationForFinalization(ctx, authorization); err != nil {
			return errors.Join(ErrRouteAuthorizationMismatch, err)
		}
	}
	if r.LocalDeviceID != claims.InitiatingDevice && r.LocalDeviceID != claims.DestinationDevice {
		return ErrAuthorizationMismatch
	}
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	if now.IsZero() || claims.IssuedAtUnixMS > now.UnixMilli() {
		return ErrAuthorizationNotYetValid
	}
	digestInput := make([]byte, 0, len(message)+len(signature))
	digestInput = append(digestInput, message...)
	digestInput = append(digestInput, signature...)
	authorizationHash := sha256.Sum256(digestInput)
	store, ok := r.Provider.Pending.(interface {
		LoadFinalization(context.Context, string, string, [sha256.Size]byte) (CheckpointRequest, CheckpointReceipt, bool, bool, error)
	})
	if !ok {
		return ErrCheckpointUnavailable
	}
	request, _, found, _, err := store.LoadFinalization(ctx, string(r.LocalDeviceID), claims.JTI, authorizationHash)
	if err != nil {
		return err
	}
	if !found {
		return ErrCheckpointHistorical
	}
	var routeAuthorizationHash [sha256.Size]byte
	if claims.Router != "" {
		routeAuthorizationHash, err = checkpointRouteAuthorizationFingerprint(authorization.RouteAuthorization)
		if err != nil {
			return err
		}
	}
	if request.AuthorizationSHA256 != authorizationHash || request.RouteAuthorizationSHA256 != routeAuthorizationHash ||
		request.JTI != claims.JTI || request.ConsumingDeviceID != string(r.LocalDeviceID) ||
		request.Initiator.DeviceID != string(claims.InitiatingDevice) ||
		request.Destination.DeviceID != string(claims.DestinationDevice) ||
		!bytes.Equal(request.DevicePublicKey, devicePublicKey) {
		return ErrCheckpointIntegrity
	}
	if _, err := CheckpointRequestFingerprint(request); err != nil {
		return err
	}

	initiator, initiatorErr := r.Memberships.ResolveCheckpointMembership(ctx, claims.InitiatingDevice)
	destination, destinationErr := r.Memberships.ResolveCheckpointMembership(ctx, claims.DestinationDevice)
	if errors.Is(initiatorErr, ErrCheckpointRevoked) || errors.Is(destinationErr, ErrCheckpointRevoked) {
		if err := r.FinalizationAuditor.RecordCheckpointFinalization(ctx, request, CheckpointFinalizationRevoked); err != nil {
			return errors.Join(ErrCheckpointRevoked, initiatorErr, destinationErr, err)
		}
		return errors.Join(ErrCheckpointRevoked, initiatorErr, destinationErr)
	}
	if initiatorErr != nil || destinationErr != nil {
		if err := r.FinalizationAuditor.RecordCheckpointFinalization(ctx, request, CheckpointFinalizationMembershipUnavailable); err != nil {
			return errors.Join(ErrCheckpointUnavailable, initiatorErr, destinationErr, err)
		}
		return errors.Join(ErrCheckpointUnavailable, initiatorErr, destinationErr)
	}
	if initiator != request.Initiator || destination != request.Destination ||
		initiator.DeviceID != string(claims.InitiatingDevice) ||
		destination.DeviceID != string(claims.DestinationDevice) ||
		initiator.OrganizationID != destination.OrganizationID ||
		!validCheckpointEndpoint(initiator) || !validCheckpointEndpoint(destination) {
		if err := r.FinalizationAuditor.RecordCheckpointFinalization(ctx, request, CheckpointFinalizationRevoked); err != nil {
			return errors.Join(ErrCheckpointRevoked, err)
		}
		return ErrCheckpointRevoked
	}
	if err := r.FinalizationAuditor.RecordCheckpointFinalization(ctx, request, CheckpointFinalizationStarted); err != nil {
		return errors.Join(ErrCheckpointUnavailable, err)
	}
	if err := r.Provider.Finalize(ctx, request); err != nil {
		auditErr := r.FinalizationAuditor.RecordCheckpointFinalization(ctx, request, CheckpointFinalizationFailed)
		return errors.Join(err, auditErr)
	}
	if err := r.FinalizationAuditor.RecordCheckpointFinalization(ctx, request, CheckpointFinalizationComplete); err != nil {
		return errors.Join(ErrCheckpointUnavailable, err)
	}
	return nil
}
func (r *CheckpointAuthorizationReplay) ConsumePortForwardAuthorization(context.Context, string, time.Time) error {
	return ErrCheckpointUnavailable
}

func (r *CheckpointAuthorizationReplay) ConsumeVerifiedPortForwardAuthorization(ctx context.Context, authorization Authorization) error {
	if r == nil || r.Provider == nil || r.Memberships == nil || r.DeviceSigner == nil ||
		len(r.ControlPlaneKey) != ed25519.PublicKeySize {
		return ErrCheckpointUnavailable
	}
	devicePublicKey, ok := r.DeviceSigner.Public().(ed25519.PublicKey)
	if !ok || len(devicePublicKey) != ed25519.PublicKeySize ||
		identity.DeviceID(devicePublicKey) != string(r.LocalDeviceID) ||
		bytes.Equal(devicePublicKey, r.ControlPlaneKey) ||
		bytes.Equal(r.Provider.PrimaryKey, r.ControlPlaneKey) ||
		bytes.Equal(r.Provider.PrimaryKey, devicePublicKey) {
		return ErrCheckpointIntegrity
	}
	for _, witness := range r.Provider.Witnesses {
		if bytes.Equal(witness.PublicKey, r.ControlPlaneKey) || bytes.Equal(witness.PublicKey, devicePublicKey) {
			return ErrCheckpointIntegrity
		}
	}
	if err := r.Provider.ValidateConfiguration(); err != nil {
		return err
	}
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	request, err := BuildCheckpointRequest(
		ctx, authorization, r.ControlPlaneKey, r.LocalDeviceID,
		r.DeviceSigner, r.Memberships, r.RouteVerifier, now,
	)
	if err != nil {
		return err
	}
	_, err = r.Provider.Consume(ctx, request)
	if err != nil {
		return err
	}
	return nil
}
