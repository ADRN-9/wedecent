# C208 — Pairing credential expiration, admission and durable revocation

## Credential format and expiry

The wire protocol is unchanged: clients continue sending the existing 24-byte random base64url pairing secret. The server continues storing only its SHA-256 digest, in the existing pairing-secret hash file.

A separate versioned metadata record (V2) binds that digest to:
- a monotonically increasing credential generation;
- UTC issuance and expiration timestamps;
- consumed state.

New credentials expire after 15 minutes. Issuance timestamps more than 30 seconds in the future are rejected. Expiration, version, generation, digest, and consumed state are checked while the cross-process pairing credential lock is held in the consume transaction.

V1 hash-only records are migrated on first valid check or consumption. The migration is allowed only before 2026-12-01 00:00:00 UTC and gives the migrated credential a maximum 15-minute lifetime. A legacy file with a future modification timestamp is rejected. After the cutoff, an unmigrated V1 secret is rejected rather than silently retaining indefinite validity.

The hash and metadata are separate durable files. Rotation writes and synchronizes both before returning the new secret. If interruption leaves them inconsistent, the next pairing attempt fails closed; operator rotation is required. If the durable hash tombstone was written but the metadata consumed marker was not, the next rotation recognizes the exact tombstone, reconciles metadata to consumed, and advances the generation.

## Generation-bound admission and lock ordering

The one-time transaction holds the pairing credential cross-process lock while it:
1. reads and validates the V2 metadata and exact secret digest;
2. reserves one recovery record for the credential generation;
3. appends the pending audit event;
4. writes and synchronizes the consumed hash tombstone;
5. marks the metadata record consumed and synchronizes it;
6. persists the trusted peer.

The recovery ledger migrates its previous V1 snapshot to V2 with monotonic per-attempt sequence numbers. The recovery reservation binds credential generation to authenticated actor ID, certificate-derived device ID and public-key fingerprint. Generation uniqueness is checked against both active records and the authenticated archive, so compaction cannot make a consumed generation reusable. A retry for the same identity and a still-pending generation reuses the existing attempt ID. A different identity or a resolved record cannot reuse that generation. Recovery capacity remains bounded; unresolved entries are never silently evicted.

Lock acquisition sequence is credential lock → recovery-ledger lock → audit-log lock → trust-store lock. Subsystem locks are released before acquiring the next subsystem lock; the credential lock remains held through reservation and consumption. Completion/audit reconciliation occurs after the credential transaction has released its lock.

## Durable trust deletion

DeletePeer now uses the durable trust-store replacement path, for both trusted-clients.json and trusted-devices.json. The replacement file is written with private permissions, synced, atomically replaced, and followed by parent-directory synchronization on supported Unix filesystems. Windows retains MoveFileEx write-through replacement and the existing local fixed NTFS restrictions.

Errors before replacement are pre-commit failures. Errors after replacement, including directory-sync failures, are reported through ErrTrustStoreCommitUncertain. In this state the API does not claim that revocation is durably complete or that the previous snapshot remains authoritative; callers must re-read the store and reconcile. The in-memory snapshot is rolled back locally, and subsequent operations reload from disk.

## Authenticated recovery archive

The active recovery ledger remains bounded to 64 records. Compaction archives only a contiguous prefix of success/denial records that have:
- an independently verified completion audit proof;
- an explicit acknowledgement;
- a valid sequence number.

Successful and denied outcomes are archived automatically after independently verified audit completion and explicit acknowledgement; the Records API continues to return both archived and active evidence. The archive has per-record sequence continuity, a SHA-256 checkpoint chain, and HMAC-SHA256 authentication. The random 32-byte HMAC key is stored as a 0600 file in the protected state directory. The archive is written to a same-directory temporary file, synced, atomically replaced, directory-synced and read back for verification before the active ledger is compacted.

If interruption occurs after archive synchronization but before active-ledger compaction, startup verifies the archive and the exact active prefix, then reconciles the duplicate prefix. Missing keys, missing archives after compaction, HMAC failures, checkpoint mismatches, sequence gaps, inconsistent active/archive prefixes, and archive capacity exhaustion fail closed. Unresolved records remain active and cannot be compacted.

The archive is bounded to 4 MiB; capacity exhaustion requires operator intervention rather than evidence deletion.

## Integration and verification

This branch is based on the current C203 checkpoint-authority branch and retains the forwarding runtime, router identity, capability negotiation, and context-aware IsTrusted changes from PR #186. It overlays PR #176's pairing recovery and filesystem durability changes. The four shared files are merged semantically:
- internal/audit/log.go: pairing AttemptID and durable directory sync plus forwarding audit fields;
- internal/audit/log_test.go: pairing durability tests plus forwarding-field regression;
- internal/session/server.go: pairing recovery/admission plus router-aware forwarding session handling;
- internal/trust/store.go: pairing durable write/delete plus context-aware IsTrusted.

PR #176 and PR #186 original branches and histories remain untouched.

Regression tests cover credential expiry, future/malformed records, V1 migration cutoff, generation increments, interrupted tombstone reconciliation, concurrent generation reservations, both trust-store deletion paths, pre-commit and uncertain post-commit failure, archive authentication, sequence continuity, and interrupted archive compaction.

## Remaining limitations

- The HMAC archive key is protected by the local state-directory permissions and ownership model. It detects tampering by actors who cannot read the key, but does not protect against compromise of the same OS account that can read/replace the key. A platform-backed key boundary is a remaining hardening dependency.
- Archive capacity is bounded; the system fails closed instead of deleting evidence.
- The legacy V1 migration cutoff is fixed at 2026-12-01 UTC. Deployments must rotate credentials before that deadline if migration has not occurred.
- A post-replacement directory-sync failure remains an uncertain durability outcome and requires authoritative re-read/operator reconciliation.
- CI, race tests, Windows/macOS/Linux exact-HEAD results, and physical power-loss tests must be recorded separately. Software tests do not prove actual power-loss behavior.
