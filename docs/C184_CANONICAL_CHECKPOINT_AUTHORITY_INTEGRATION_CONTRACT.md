# C184-B — Canonical checkpoint authority integration contract

## Decision

**Do not implement a PostgreSQL `CheckpointFenceAtomicPrimary` against the current schema.** The existing PostgreSQL replay authority is authoritative for port-forward capability consumption and per-device replay protection, but it is not the canonical checkpoint-head authority required by `ReplayCheckpointProvider`, `CheckpointFenceAtomicPrimary`, or `CheckpointFenceHeadReader`.

No new checkpoint-head table is proposed or created in this investigation. No production atomicity or independent-consensus claim is made.

## Repository reconciliation

- Repository: `ADRN-9/wedecent`
- Branch: `feat/secure-port-forwarding-foundation`
- Starting and final HEAD: `02ce406bfc1f226c00873e5e3c3fdb14de47f4e2`
- PR #186: open, draft, unmerged
- No source or migration files were changed by C184-B. This document is the sole deliverable.

## Source-of-truth findings

### 1. Capability replay authority

Migration `supabase/migrations/20261123080000_port_forward_replay_authority.sql` creates:

- `public.port_forward_replay_authority(device_id, generation, state_hash, updated_at)`
- `public.port_forward_replay_entries(device_id, jti, generation, authorization_sha256, previous_state_hash, state_hash, expires_at, consumed_at)`

The canonical writer is `public.consume_port_forward_authorization(...)`, replaced/extended by `20261124070000_atomic_port_forward_authorization.sql`. The Edge Function `supabase/functions/port-forward-replay/index.ts` validates the signed capability and device proof, then invokes that RPC using the service-role client. Direct table privileges are revoked from API roles.

Within that RPC's PostgreSQL transaction:

1. It discovers the initiator, destination and optional router.
2. It locks organizations, memberships, device-access rows, route grant, then participant device rows in deterministic order and rechecks the discovered snapshots.
3. It inserts or exact-retry-validates `port_forward_authorization_transactions`, which records the complete participant/account/organization/revocation-epoch snapshot.
4. It locks only the replay-authority row for the *consuming device* with `FOR UPDATE`.
5. It validates the per-device replay hash chain, rejects conflicting JTI reuse, appends one replay entry and advances that device's replay generation/hash.

The authorization transaction and that consuming device's replay mutation commit or roll back together. A second endpoint consuming the same forwarding transaction updates its own per-device replay row in its own RPC transaction. Thus there is not one atomic participant-vector checkpoint generation for the forwarding operation.

The generation/hash chain is a replay-consumption chain. It advances on accepted capability consumption. It does not advance for every revocation or finalization event, and its rows do not store the signed `CheckpointReceipt` / `CheckpointHead` records used by the Go checkpoint protocol.

### 2. Revocation authority

Migration `20261124070000_atomic_port_forward_authorization.sql` adds `devices.revocation_epoch` and triggers that increment it when device identity/ownership/revocation, organization membership, or device-access state changes.

Those mutations occur in PostgreSQL transactions and serialize against authorization issuance through row locks and the documented lock order. The authorization RPC records the observed participant epochs in `port_forward_authorization_transactions`.

This is a real database revocation fence for the control-plane authorization snapshot. It is not a checkpoint generation/hash writer. There is no shared database function that advances the replay hash chain and participant checkpoint heads for a revocation operation.

### 3. Finalization authority

Migration `20261124120000_checkpoint_finalization_audit.sql` creates:

- `checkpoint_finalization_operations`: immutable operation ID, payload, payload digest and actor.
- `checkpoint_finalization_audit`: append-only per-outcome evidence and evidence digest.

The canonical writer is `public.record_checkpoint_finalization(...)`, called through `supabase/functions/port-forward-finalization-audit/index.ts` after server-side signature/quorum verification.

The audit RPC runs in its own PostgreSQL transaction. It serializes a particular operation using an advisory transaction lock, locks and rechecks participant organizations, memberships, access, route grant, device rows and the stored authorization transaction, then inserts/validates the operation and evidence event. Exact operation/outcome retries are idempotent; conflicting payload/evidence and contradictory terminal outcomes are rejected.

This is durable audit evidence and participant-state revalidation at the audit boundary. It is not a mutation of the replay authority's generation/hash, and it is not in the same transaction as capability consumption or external primary/witness operations. The advisory lock is operation-local deduplication, not a distributed fencing authority.

### 4. Go checkpoint/fence interfaces

- `internal/portforward/replay_checkpoint.go` defines `ReplayCheckpointProvider` with `Consume`, `Revoke`, and `Head`, and signed checkpoint receipt/head structures.
- `internal/portforward/checkpoint_fence.go` and `checkpoint_fence_coordinator.go` define the fence primary and head-reader contracts.
- The concrete `testAtomicCheckpointPrimary` is a test fixture in `replay_witness_test.go`; it wraps a deterministic provider and file-backed fence primary. It is not a PostgreSQL implementation.
- `internal/portforward/replay_remote.go` explicitly refuses the single-provider production adapter. The production path requires the independently administered witnessed provider; no SQL-backed implementation of the checkpoint/fence interfaces was found.

## Mapping: current database operations vs Go contracts

| Go contract | Closest existing database operation | Gap |
|---|---|---|
| `ReplayCheckpointProvider.Consume` | `consume_port_forward_authorization` | Validates and consumes a capability, but does not produce/persist the signed Go checkpoint receipt or one complete participant-head transition. |
| `ReplayCheckpointProvider.Head` | Read of `port_forward_replay_authority` plus `devices` | No authenticated checkpoint-head RPC, no signed `CheckpointHead`, and no consistent multi-participant vector read. |
| `ReplayCheckpointProvider.Revoke` | Device/membership/access updates and revocation-epoch triggers | Advances authorization epoch, but does not append a checkpoint-chain event or fence finalization with a common operation generation. |
| `CheckpointFenceAtomicPrimary.ReserveFenceWithCheckpointHeads` | None | No stable fence-operation reservation, participant head CAS, or monotonic shared fence generation. |
| `CheckpointFenceAtomicPrimary.CommitFenceWithCheckpointHeads` | `record_checkpoint_finalization` | Persists proof-bearing audit evidence after independent proof verification, but does not revalidate/update a canonical checkpoint head or coordinate witness fence generation. |
| `CheckpointFenceHeadReader.FenceHead` | No equivalent | No durable primary fence head/action/operation record. |

## Required implementation contract (proposed, not implemented)

The safest migration path is to **extend the existing per-device `port_forward_replay_authority` rows as the one canonical participant-head records**, rather than create a second participant-head table. This is a schema/contract change, not something the present columns and writer already guarantee.

### A. Canonical row and event history

1. Keep one authoritative row per device in `port_forward_replay_authority`. Define its `generation/state_hash` as the canonical participant checkpoint head, not merely the capability replay counter.
2. Add the minimal participant identity binding needed to validate a head: account ID, organization ID and revocation epoch. Bind device identity to the enrolled Ed25519 public key through the existing `devices` record and verified request.
3. Extend the append-only event persistence so every accepted checkpoint consume, revoke and fence/finalization transition has a durable event with:
   - participant device ID;
   - monotonically increasing generation;
   - previous and resulting state hashes;
   - stable operation ID and immutable operation fingerprint;
   - action/event type and complete participant-vector digest;
   - exact authorization/checkpoint receipt or evidence digest;
   - creation timestamp and key/signature metadata where applicable.
4. Preserve the existing replay uniqueness rules for (device, JTI), exact retry semantics and append-only permissions. A retry with the same operation ID and fingerprint returns the original outcome; any changed participant, action, expected head, or fingerprint is a hard conflict.
5. No API/service role receives direct mutation rights. All transitions are made through narrowly granted SECURITY DEFINER RPCs with fixed search paths and explicit input validation.

The existing replay entry table may be extended only if its constraints and semantics can represent every event without ambiguous/null overloading. Otherwise the migration must introduce an append-only **event ledger**, not a parallel head table. The single head remains the existing `port_forward_replay_authority` row. This choice requires a migration review and backfill/compatibility plan before implementation.

### B. One transaction owner and lock order

The Supabase PostgreSQL primary is the transaction owner for the database portion. It must own three narrowly defined RPC transitions, all sharing the same participant lock order:

1. Discover participant device IDs and organization IDs without locks only to establish lock targets.
2. Lock organization rows in sorted UUID order.
3. Lock membership rows in sorted (organization ID, user ID) order.
4. Lock device-access rows in sorted (device ID, permission) order.
5. Lock route-grant row, when present.
6. Lock participant `devices` rows in sorted device-ID order and revalidate identity, organization, key, revocation epoch, revoked state and authorization snapshot.
7. Lock existing canonical participant-head rows in sorted device-ID order.
8. Lock/insert the operation row by stable operation ID and verify immutable fingerprint.
9. Validate expected generations/hashes for the *entire* participant vector before any head update.
10. Append all participant event rows and update all participant head rows in the same PostgreSQL transaction.

No local mutex or file journal participates in production authority. Advisory locks may be used only as supplemental operation-ID serialization; row locks and transactional compare-and-update remain authoritative.

### C. Reservation

The reservation RPC must accept the stable operation ID, action, immutable fingerprint, complete sorted participant vector, expected generation/hash for every participant, and the canonical request digest.

It must atomically:

- reject missing, duplicate, reordered/substituted or unexpected participants;
- verify each current canonical head exactly equals the expected generation and hash;
- reject stale generations, epoch regression, hash substitution and overflow;
- reserve the operation ID/fingerprint exactly once;
- allocate monotonic next fence generation(s) and append the reservation state to each participant head/event chain;
- return a signed primary token binding the operation ID, action, participant vector, expected and resulting generations/hashes, revocation epochs, fingerprint, witness-set version and primary key ID.

A lost response is recovered by querying the exact operation ID and fingerprint. It must never allocate a second generation for an exact retry.

### D. Witness quorum and commit

The database can validate persisted signed witness acknowledgements, but it cannot make independently administered witness services commit atomically with PostgreSQL. The existing independent witness protocol must therefore provide durable idempotent fence reservations/acks keyed by the same operation ID, action, participant-vector digest and generation.

Before terminal commit, the server-side verifier must validate:
- primary signature against a provisioned primary trust anchor;
- distinct witness identities and signatures against the configured witness set;
- strict-majority quorum (never a single-provider fallback);
- matching operation ID, immutable fingerprint, participant vector, action, generation and witness-set version;
- no duplicate witness IDs, stale acknowledgements or mismatched head digests.

The commit RPC then locks and revalidates every participant device and canonical head against the reservation's post-reservation values, validates quorum evidence, and atomically writes the immutable terminal event/operation result. A concurrent revoke uses the same head rows and lock order. Exactly one order wins: if revoke advances first, stale finalization fails; if finalization commits first, the later revoke receives a higher generation. Exact retries return the original terminal result; conflicting retries fail closed.

**Important distributed limit:** this database transaction orders the PostgreSQL primary. It does not itself prove atomic commit across independent witnesses. That claim remains blocked until witness services implement and demonstrate the matching durable protocol, quorum intersection, crash recovery and partition behavior.

### E. Revocation integration

Revocation must stop being only a `devices.revocation_epoch` trigger side effect. The mutation path must use the same canonical head transition: lock the same participant and head rows, compare the expected epoch/head, append a revoke operation and advance the canonical generation/hash in the same transaction as the underlying device/membership/access revocation. Triggers that currently bump epochs must either call a carefully designed common transition or be integrated into an explicit mutation RPC; avoid recursive trigger behavior and lock-order inversions.

The `devices.revocation_epoch` remains the authorization epoch and is included in the checkpoint head. The canonical generation/hash is separate monotonic history; neither is inferred from IP/network transport.

### F. Signer and recovery

The SQL transaction must not invent or store private Ed25519 keys. A production signer interface signs the canonical primary token/receipt outside SQL, with the signed bytes and key ID durably bound to the operation. The design must specify what happens if the DB transaction commits but signing response is lost: signer operation must be idempotent for the stable operation ID, or the system must durably persist a pre-signed token before making it visible. Key provisioning/rotation remains an explicit protected operation.

Recovery tests must cover:
- identical concurrent reservation requests in independent PostgreSQL sessions;
- stale/substituted participant heads;
- concurrent finalization/revocation in both lock orderings;
- commit-time head changes;
- duplicate and conflicting operation IDs/fingerprints;
- dropped RPC response after commit and restart recovery;
- partial/invalid/non-majority witness quorum;
- transaction rollback and process/database crash recovery;
- generation overflow and participant-vector mismatch.

## Transaction guarantees that exist today

- Capability transaction insert and the consuming device's replay chain append are atomic within one PostgreSQL RPC transaction.
- Device revocation-epoch changes, membership/access changes and their triggers are transactional and serialize with authorization issuance through the existing row-lock order.
- Finalization operation/evidence insertion and participant-state revalidation are atomic within a separate audit RPC transaction.
- Finalization exact retry/conflict handling is durable at the audit-operation level.

## Guarantees that do not exist today

- One authoritative checkpoint generation/hash for each participant covering consume, revoke and finalize.
- One atomic participant-vector checkpoint reservation/commit.
- Commit-time compare-and-update of canonical checkpoint heads.
- A common database fence generation ordering revocation against finalization.
- A PostgreSQL implementation of the Go atomic-primary/head-reader interfaces.
- Atomic transaction semantics across PostgreSQL and independently operated witness services.

## Verification and dependencies

No local command execution, Go test execution, Supabase CLI, psql, disposable PostgreSQL, or independent witness service was available through the repository tools in this assignment. No tests were executed by C184-B. Existing SQL test files and the independent-session script were inspected, not run. Any historical CI result applies only to the commit it ran against; this task produced no new CI evidence.

Before implementing the proposed adapter, the project must approve the canonical head/event schema extension and migration compatibility/backfill plan, confirm the production primary signer interface and key custody, and provide independently administered witness endpoints/trust-set provisioning. Production migration deployment and credentials remain protected operations. PR #186 and PR #176 were not merged.
