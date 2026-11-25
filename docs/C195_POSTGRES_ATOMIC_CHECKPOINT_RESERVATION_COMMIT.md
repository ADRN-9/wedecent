# C195 — PostgreSQL atomic checkpoint reservation and commit

## Status

Implementation candidate on feat/secure-port-forwarding-foundation. This document describes repository code and intended CI gates; it does not claim that the new migration or tests have passed. Production acceptance remains explicitly out of scope.

## Authority model

**public.port_forward_replay_authority** remains the sole mutable per-device authority row. The migration adds checkpoint_head_generation and checkpoint_head_hash to that existing row. It does not modify the legacy replay generation or state_hash values, nor the append-only port_forward_replay_entries chain.

The new tables have deliberately different responsibilities:

- **checkpoint_operations**: immutable operation identity, actor, request digest, participant digest and canonical fingerprint.
- **checkpoint_operation_participants**: immutable expected and target participant snapshots. These rows are evidence and recovery metadata, never current heads.
- **checkpoint_operation_events**: append-only reservation, expiry and committed-receipt events with canonical SHA-256 digests.
- **checkpoint_active_reservations**: expiring per-device coordination leases. It contains no head or head hash and cannot authorize a transition by itself.

Immutable tables reject UPDATE and DELETE through database triggers. Direct table privileges, including service_role, are revoked; callers use the narrow security-definer RPCs.

## Reservation protocol

public.reserve_checkpoint_operation:

1. Validates the operation ID, action, actor, request digest, participant vector and bounded lease (5–120 seconds).
2. Canonicalizes participants and rejects duplicates, malformed identities, cross-organization participants and unsupported schemas.
3. Computes an immutable SHA-256 operation fingerprint over canonical JSON.
4. Acquires the same operation-scoped advisory lock used by record_checkpoint_finalization.
5. Locks the organization and membership rows, then participant device rows in device-ID order.
6. Confirms device ownership, organization, membership, revocation epoch and active status.
7. Creates missing authority rows with the existing replay-chain initialization, then locks the authority rows in device-ID order.
8. Compares every expected checkpoint generation and hash with the authoritative values and preserves the existing v1 transition checks.
9. Computes each target event hash using the existing v2 participant/event encoding.
10. Persists immutable participant snapshots and per-device reservation leases atomically.

A competing operation that overlaps an active reservation fails with SQLSTATE 55P03. A stale participant snapshot fails with SQLSTATE 40001. No partial reservation survives a failed transaction.

Exact retries with the same operation ID and fingerprint return the existing reservation or committed receipt. Reusing an operation ID with different action, actor, request digest or participant vector fails with SQLSTATE 23505.

## Commit protocol

public.commit_checkpoint_operation accepts the operation ID, exact stored fingerprint and a structurally validated acknowledgement array.

It revalidates:

- actor membership and revoke role;
- participant membership and device ownership;
- device revocation epochs and active status;
- all participant authority rows;
- expected generation/hash values;
- the complete unexpired reservation set;
- acknowledgement field shape, operation/action binding, unique witness IDs and shared token/generation digests.

All participant head updates happen in one PostgreSQL transaction. The commit event is appended in that same transaction and active leases are removed. If any participant update, evidence insert or revocation update fails, PostgreSQL rolls back the entire transaction.

For revoke, the commit also advances each participant device's revocation epoch in the same transaction as its checkpoint head. For finalize, revocation epochs remain unchanged.

A durable committed event is the idempotency receipt. If the caller loses the response after commit, an exact retry returns the stored receipt without advancing any head again.

## Revocation and finalization ordering

Checkpoint reservation and commit lock participant devices before authority rows, matching the replay-consumption and finalization audit ordering. Device revocation takes an exclusive device-row lock and advances revocation_epoch; it therefore serializes against checkpoint commit. If revocation wins first, commit sees a stale/revoked participant and fails closed. If checkpoint commit wins first, revocation runs afterward and advances the epoch for the next operation.

The reservation and commit RPCs use pg_advisory_xact_lock(hashtextextended(operation_id, 0)), the same operation lock used by record_checkpoint_finalization. This serializes same-operation finalization audit and checkpoint protocol phases. It does not make separate RPC calls one transaction; the durable operation/event ledger and exact retry semantics bridge that boundary.

## Witness and cryptographic boundary

PostgreSQL checks acknowledgement structure and binding only. It does not verify Ed25519 signatures, establish witness identity, prove independent administration, or establish quorum membership. The trusted Go primary must verify each signature against independently configured witness keys and enforce the configured witness set and strict-majority quorum before calling the commit RPC.

PostgreSQL transaction atomicity is not Ed25519 authenticity. Ed25519 authenticity is not independent witness consensus. A compromised service_role caller can fabricate structurally valid acknowledgement JSON; production must not expose this RPC to untrusted callers or treat its structural checks as cryptographic proof.

## Verification added

- supabase/tests/database/checkpoint_atomic_reservation_commit.test.sql
  - canonical multi-participant reservation and commit;
  - exact retries and conflicting fingerprints;
  - duplicate participants and stale head rejection;
  - malformed and duplicate acknowledgements;
  - immutable operation, participant and event evidence;
  - rollback, overlapping reservations, replay-chain compatibility;
  - atomic revocation epoch and checkpoint-head advancement;
  - no partial advancement after a concurrent revocation.
- scripts/test-checkpoint-reservation-concurrency.sh
  - independent PostgreSQL sessions competing for identical and overlapping participant sets;
  - process/backend interruption before transaction commit;
  - revocation racing a pending finalization;
  - same-operation advisory-lock ordering with finalization;
  - exact retry after intentionally discarding the first commit receipt;
  - PostgreSQL container restart and durable receipt/head recovery.
- .github/workflows/ci.yml runs the new database concurrency/recovery script after pgTAP and the existing port-forward transaction-race suite.

The concurrency script's discarded first response is an idempotent-retry test, not a network fault-injection proof of a TCP response being lost after COMMIT. The backend-termination test is a PostgreSQL backend interruption test, not physical power-loss evidence.

## Remaining gates

- Obtain successful pgTAP and independent-session execution at the exact final SHA.
- Obtain exact-HEAD Linux, Windows and macOS Go CI and all three Desktop CI jobs.
- Validate actual production Go-to-Supabase RPC serialization and the production trusted-witness adapter.
- Independently review SQL lock ordering, trigger interactions, RLS/grants, schema rollback and service-role exposure.
- Verify database backup/restore and restart behavior in the production Supabase project.
- Verify external witness signatures and strict quorum independently of PostgreSQL.
- Production credentials, trust anchors and infrastructure configuration remain separately protected.

No production deployment, signing, merge or activation is authorized by this repository implementation alone.
