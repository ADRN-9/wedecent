package portforward

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"time"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/mesh"
)

// CheckpointAuthorizationReplay binds Local Core's verified capability to the
// witnessed checkpoint transaction. Bare-JTI replay calls are never accepted.
type CheckpointAuthorizationReplay struct {
	Provider        *WitnessedReplayCheckpointProvider
	ControlPlaneKey ed25519.PublicKey
	LocalDeviceID   mesh.DeviceID
	DeviceSigner    crypto.Signer
	Memberships     CheckpointMembershipResolver
	RouteVerifier   CheckpointRouteAuthorizationVerifier
	Now             func() time.Time
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
