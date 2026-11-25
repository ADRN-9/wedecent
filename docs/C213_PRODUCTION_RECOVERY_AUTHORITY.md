# C213 — production recovery authority and active-ledger protection

## Implementation status

This change introduces the `HTTPRecoveryAuthority` client and wires `cmd/wd-agent serve` to require it before starting listeners. The client uses:

- TLS 1.3 only;
- normal WebPKI certificate and hostname validation;
- constant-time comparison of the leaf certificate SPKI SHA-256 pin;
- the existing Ed25519 device certificate as a mutual-TLS client identity;
- a separately provisioned short-lived bearer token;
- a pinned Ed25519 primary key and distinct witness keys with strict-majority verification;
- bounded JSON bodies, strict response decoding, no redirects and fail-closed HTTP handling.

The authority's primary and witness private keys are not present in this repository. This client is not itself a production authority service or a claim that production keys have been provisioned.

## Agent configuration

The following are mandatory for `wd-agent serve`:

- `--pairing-recovery-authority-url=https://authority.example`
- `--pairing-recovery-authority-spki-sha256=<64 hex characters>`
- `--pairing-recovery-trust=/absolute/path/recovery-trust.json`
- `WEDECENT_PAIRING_RECOVERY_AUTHORITY_TOKEN=<short-lived per-device token>`

The authority token is never accepted as a command-line argument. The TLS client certificate is the existing device identity certificate. The service must authenticate and authorize both the enrolled device certificate and the token; it must not trust an IP address, hostname or transport identifier.

Trust file format (public keys are standard base64 Ed25519 public keys):

```json
{
  "primary_key": "<base64 Ed25519 public key>",
  "witnesses": {
    "witness-region-a": "<base64 Ed25519 public key>",
    "witness-region-b": "<base64 Ed25519 public key>",
    "witness-region-c": "<base64 Ed25519 public key>"
  },
  "quorum": 2
}
```

The trust file must be a regular non-symlink file and not group/world writable. It rejects malformed keys, duplicate witness keys under different IDs, and primary/witness key reuse.

## HTTP service contract

The client expects JSON responses with `Content-Type: application/json`. Go byte slices are encoded as standard base64; fixed 32-byte digests are JSON arrays of 32 unsigned bytes. `RecoveryCheckpoint` fields are serialized using their exported Go field names.

| Method and path | Request | Response |
|---|---|---|
| GET `/v1/pairing-recovery/checkpoints?scope=<url-encoded-scope>` | none | one `RecoveryCheckpoint` |
| POST `/v1/pairing-recovery/archives/sign` | `{"payload":"<base64>" }` | `{"key_id":"ed25519:<sha256-public-key>","signature":"<base64>" }` |
| POST `/v1/pairing-recovery/checkpoints/commit` | `RecoveryCheckpointRequest` | one `RecoveryCheckpoint` |
| POST `/v1/pairing-recovery/migrations` | `LegacyRecoveryMigrationRequest` | one `RecoveryCheckpoint` |

A `RecoveryCheckpoint` contains `Scope`, `Generation`, `StateDigest`, `PreviousDigest`, `OperationID`, `SignerKeyID`, `Signature` and `Witnesses`. Each witness contains `ID` and `Signature`.

The server must implement atomic compare-and-advance on (scope, expected generation, previous digest), exact operation-ID deduplication, monotonic generations, state-digest binding, primary Ed25519 signatures and strict-majority signatures from independently administered witnesses. It must return the same signed receipt for exact retries, reject stale/conflicting/replayed requests, and persist state independently of the device's account and filesystem. HTTP 409 is treated as stale; every other non-2xx response fails closed.

The migration endpoint must authenticate the out-of-band proof, exact raw legacy object SHA-256, canonical state digest, sequence continuity, scope, expected generation and deterministic migration operation ID. The client additionally checks that the proof's `state_digest` matches the canonical state digest. A JSON digest field alone is not proof of historical authenticity; the service must verify the issuer's signature and provenance.

## Active-ledger checkpointing

The active pairing snapshot uses a separate `/active-ledger` authority scope from the compacted archive scope. Every active-ledger write commits a canonical digest that includes version, records, archive sequence boundary and archive checkpoint. The snapshot persists the independently signed checkpoint.

Before a mutation, the current snapshot checkpoint must exactly equal the remote head. A restored snapshot, stale generation, malformed receipt, unavailable authority or conflicting operation is rejected. The implementation writes a durable pending-intent file before committing remotely. On restart, it resolves only the exact prior-head or exact committed operation, validates the primary and witness signatures, publishes the snapshot and removes the pending marker. An unrelated or advanced head fails closed.

Legacy active snapshots have no independent checkpoint. They are not silently adopted. Use `OpenPairingRecoveryForMigration` and `MigrateLegacyActiveLedger` with an authenticated proof for the exact raw snapshot and canonical state digest. Archive migration and active-ledger migration are separate, proof-gated operations. The migration opener is read-only: it does not reconcile, compact or rewrite the active snapshot before the independent proof is accepted.

## December 1, 2026 UTC migration readiness

The cutoff remains **2026-12-01 00:00:00 UTC**. Repository inspection did not expose a production fleet inventory, last-seen agent version telemetry, authority provisioning status, or per-device pairing/revocation counts. These are missing production inputs, not evidence that the fleet is empty or migrated.

Required rollout procedure:

1. Inventory enrolled devices, agent versions, last-seen timestamps, pairing ledger/archive presence, and device identity fingerprints from production telemetry.
2. Provision the independent service, separate primary/witness custody, witness quorum, endpoint certificate, exact SPKI pin, per-device mTLS enrollment and short-lived tokens.
3. Stage the new agent and public trust file; verify the authority service with independent primary/witness test vectors and backup/restore drills.
4. For each existing device, authenticate the exact archive and active snapshot digests and sequence continuity. Migrate only with an issuer-signed proof. Escalate devices with missing or unverifiable historical provenance for operator-assisted reconciliation; do not manufacture a proof or infer authenticity from the local HMAC.
5. Confirm the new agent uses the authority-backed path, verify restart/revocation and snapshot-rollback rejection, and record telemetry before the cutoff.
6. At the cutoff, remove any temporary migration path or legacy compatibility permitted by the deployment plan. Do not extend V1 compatibility indefinitely.

## Human-controlled production dependencies

- A separately administered recovery-authority service implementing the API above.
- Non-exportable primary signing key custody and independently administered witness signing/state custody, with strict-majority quorum and anti-rollback persistence.
- Production HTTPS origin, CA-valid TLS certificate, exact leaf-SPKI pin and pin-rotation procedure.
- Device mTLS enrollment and short-lived per-device bearer token issuance/rotation/revocation.
- Signed historical migration-proof issuer and an operator-assisted exception process.
- Production fleet inventory, telemetry and December 1 migration ownership.
- Verified backups, restore drills, key rotation/revocation, audit retention and incident response.

No production endpoint, bearer token, primary/witness private key, trust file, migration proof, fleet telemetry or infrastructure credential is included or claimed. The existing device identity currently uses the repository's existing key-storage behavior; non-exportable Ed25519 identity storage remains a separate production hardening dependency.
