# C212 — independent pairing recovery authority integration

## Scope

This change adds an opt-in independent authority path for pairing recovery. It does not provision or claim a production authority. The primary signer, witnesses, migration-proof issuer, endpoint identities, TLS pins, credentials and operator controls must be supplied by a separately administered deployment.

The port-forward witness service is not reused. Pairing recovery has its own `RecoveryAuthority` interface, scope, primary trust anchor and witness trust set.

## Trust and checkpoint validation

`RecoveryAuthorityTrust` pins the primary Ed25519 public key, a map of distinct witness IDs to Ed25519 public keys, and a strict-majority quorum. Validation rejects:

- fewer than three configured witnesses;
- a quorum that is not a strict majority;
- malformed or empty witness IDs and keys;
- duplicate witness public keys under different IDs;
- reuse of the primary signing key as a witness key.

`ValidateRecoveryCheckpointWithTrust` is the complete verification path. It verifies the pinned primary signature, exact operation/scope/generation/previous-digest/state-digest binding, and distinct witness signatures. Callers must not use the lower-level structural validator as a complete authorization decision.

## Pairing archive integration

Use `audit.OpenPairingRecoveryWithAuthority(stateDir, scope, authority, trust)` for normal startup. It requires:

1. A reachable independent authority and the exact current scope head.
2. An independently signed archive payload.
3. A primary-signed monotonic checkpoint matching the archive digest.
4. A valid strict-majority witness proof.
5. The remote authority head to equal the archive checkpoint exactly.

The archive publication path signs the canonical archive payload, atomically advances the remote checkpoint, then publishes the local archive and synchronizes the containing directory. The local HMAC remains an additional local corruption check; it is never accepted as independent authority. Authority unavailability, stale heads, signature errors, quorum loss and ambiguous commits fail closed.

An uncertain checkpoint commit is resolved only by reloading the exact scope head and matching the complete operation binding. If that cannot be proven, `ErrRecoveryCommitUncertain` is returned. Retrying the same archive is deterministic and uses the same checkpoint operation ID.

Startup reconciliation compares the complete independently authenticated archive checkpoint to the remote head before exposing records. A restored older local archive cannot override an advanced remote head.

## Legacy migration

Legacy local-MAC archives are not silently upgraded. Use `audit.OpenPairingRecoveryForMigration` to obtain a migration-only recovery handle, then call `MigrateLegacyArchive(ctx, authenticatedCheckpoint)` with an out-of-band proof issued by the trusted recovery/migration authority.

The migration request binds the exact raw legacy archive SHA-256, authority scope, expected generation and a deterministic migration operation ID. The resulting checkpoint must bind the complete canonical archive state, preserve the existing record sequence/checkpoint, verify under the pinned primary and witness keys, and match the authority's current head before the new archive is published.

A failed or ambiguous migration does not rewrite the legacy archive. Retry with the same proof and archive; the provider must deduplicate the migration operation ID. Missing, stale, forged or conflicting proofs require operator-assisted reconciliation. No indefinite V1 compatibility is introduced.

## Tests added

- Duplicate witness public keys under distinct IDs.
- Primary/witness key reuse.
- Invalid primary signature rejection in the complete validation path.
- Independent archive signing and witness checkpoint verification.
- Lost commit response followed by exact-head recovery.
- Restart verification against the remote monotonic head.
- Local archive-key replacement rejection.
- Legacy archive rejection without migration proof.
- Legacy migration with lost response recovery.
- Forged migration state-digest rejection.

## Session pairing enforcement

`internal/session.Server.handlePair` now requires an injected `RecoveryAuthority` and derives the checkpoint scope as `pairing-recovery/<local-device-id>`. A configured scope override must match that exact device-bound scope. If the provider or pinned trust is unavailable, pairing returns `recovery_authority_unavailable` before trust admission. The local-only opener is reachable from the server only through an explicitly named test-fixture flag; production construction does not enable it.

The current `cmd/wd-agent` composition does not yet provide a production `RecoveryAuthority` implementation. Therefore new pairing attempts intentionally fail closed until the independent service/provider is provisioned and injected. Existing trusted-device sessions are not downgraded or re-paired through the local HMAC path.

## Production acceptance still blocked

This implementation is an integration contract and provider seam, not a deployed authority. Before production use, operators must provide and independently review:

- an implementation of `RecoveryAuthority` hosted outside the local account/device security boundary;
- independently administered primary and witness services, with separate non-exportable Ed25519 keys and durable anti-rollback state;
- authenticated endpoint identities, TLS 1.3 and exact SPKI pins for each authority endpoint;
- a production witness set with independent administration, regions, backups, quorum and restore drills;
- a migration-proof issuer that verifies historical archive provenance rather than trusting the local MAC;
- authenticated key rotation, revocation, backup/restore, audit retention and incident recovery procedures;
- a production caller configuration that uses `OpenPairingRecoveryWithAuthority` and never treats `OpenPairingRecovery` as independent protection.

No production key, witness, endpoint, pin, credential, or migration proof is included in this repository change. The existing local-only opener remains for compatibility and tests; it is not production evidence of independent rollback protection.
