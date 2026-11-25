package portforward

import (
	"bytes"
	"crypto/ed25519"
	"errors"
)

// SupabaseWitnessedReplayCheckpointConfig is server-side composition only.
// Its dedicated authority JWT, primary signer and proof-verification key must never be
// copied into Local Core, wd-agent, desktop, or installer configuration.
type SupabaseWitnessedReplayCheckpointConfig struct {
	ReplayPrimary                ReplayCheckpointProvider
	ReplayPrimaryKey             ed25519.PublicKey
	ReplayWitnesses              []CheckpointWitnessTrust
	ReplayQuorum                 int
	Pending                      CheckpointPendingStore
	FencePrimary                 SupabaseCheckpointFenceConfig
	FenceWitnesses               []CheckpointFenceWitnessClient
	RevocationProofs             CheckpointRevocationProofProvider
	ControlPlaneAuthorizationKey ed25519.PublicKey
}

// NewSupabaseWitnessedReplayCheckpointProvider wires the PostgreSQL atomic
// primary into the witnessed provider on a trusted server-side authority host.
// It deliberately does not configure Local Core or endpoint binaries.
func NewSupabaseWitnessedReplayCheckpointProvider(
	config SupabaseWitnessedReplayCheckpointConfig,
) (*WitnessedReplayCheckpointProvider, error) {
	if config.ReplayPrimary == nil || config.Pending == nil || config.RevocationProofs == nil ||
		len(config.ReplayPrimaryKey) != ed25519.PublicKeySize ||
		len(config.ControlPlaneAuthorizationKey) != ed25519.PublicKeySize ||
		!bytes.Equal(config.FencePrimary.CheckpointHeadKey, config.ReplayPrimaryKey) ||
		!validWitnessConfiguration(config.ReplayWitnesses, config.ReplayQuorum, config.ReplayPrimaryKey) {
		return nil, ErrCheckpointUnavailable
	}

	primary, err := NewSupabaseCheckpointFencePrimary(config.FencePrimary)
	if err != nil {
		return nil, err
	}
	if !sameStringSet(checkpointFenceClientIDs(config.FenceWitnesses), primary.witnessIDs) {
		return nil, ErrCheckpointIntegrity
	}
	trustedFenceWitnesses := make(map[string]ed25519.PublicKey, len(primary.witnesses))
	for id, key := range primary.witnesses {
		trustedFenceWitnesses[id] = key
	}
	for _, witness := range config.FenceWitnesses {
		key, ok := trustedFenceWitnesses[witness.ID]
		if !ok || !bytes.Equal(key, witness.PublicKey) {
			return nil, ErrCheckpointIntegrity
		}
		if _, fileOnly := witness.Witness.(*FileCheckpointFenceWitness); fileOnly {
			return nil, ErrCheckpointUnavailable
		}
	}

	for _, key := range [][]byte{
		config.ControlPlaneAuthorizationKey,
		config.FencePrimary.RevocationAuthorizationKey,
		config.FencePrimary.CheckpointHeadKey,
		config.FencePrimary.PrimarySigner.Public().(ed25519.PublicKey),
	} {
		if len(key) != ed25519.PublicKeySize {
			return nil, ErrCheckpointIntegrity
		}
	}
	trustKeys := [][]byte{
		config.ControlPlaneAuthorizationKey,
		config.FencePrimary.RevocationAuthorizationKey,
		config.FencePrimary.CheckpointHeadKey,
		config.FencePrimary.PrimarySigner.Public().(ed25519.PublicKey),
	}
	for _, witness := range config.ReplayWitnesses {
		trustKeys = append(trustKeys, witness.PublicKey)
	}
	for _, witness := range config.FenceWitnesses {
		trustKeys = append(trustKeys, witness.PublicKey)
	}
	for i := range trustKeys {
		if len(trustKeys[i]) != ed25519.PublicKeySize {
			return nil, ErrCheckpointIntegrity
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(trustKeys[i], trustKeys[j]) {
				return nil, ErrCheckpointIntegrity
			}
		}
	}

	coordinator := &CheckpointFenceCoordinator{
		Primary:           primary,
		PrimaryKey:        append(ed25519.PublicKey(nil), primary.primaryKey...),
		WitnessSetVersion: config.FencePrimary.WitnessSetVersion,
		Witnesses:         append([]CheckpointFenceWitnessClient(nil), config.FenceWitnesses...),
		Quorum:            primary.quorum,
	}
	provider := &WitnessedReplayCheckpointProvider{
		Primary:          config.ReplayPrimary,
		PrimaryKey:       append(ed25519.PublicKey(nil), config.ReplayPrimaryKey...),
		Witnesses:        append([]CheckpointWitnessTrust(nil), config.ReplayWitnesses...),
		Quorum:           config.ReplayQuorum,
		Pending:          config.Pending,
		Fencing:          coordinator,
		RevocationProofs: config.RevocationProofs,
	}
	if err := provider.ValidateConfiguration(); err != nil {
		return nil, errors.Join(ErrCheckpointUnavailable, err)
	}
	return provider, nil
}
