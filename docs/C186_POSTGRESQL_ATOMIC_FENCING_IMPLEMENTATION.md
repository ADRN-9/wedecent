# C186-D1 — canonical event encoding groundwork

## Reconciliation

- Repository: `ADRN-9/wedecent`
- Branch: `feat/secure-port-forwarding-foundation`
- Exact starting HEAD: `7f64614f45bce5d5d9c6a27b8e50d3489430065e`
- PR #186: open, draft, unmerged.
- PR #176: not modified.
- The C184 contract remains the architecture authority; no competing mutable checkpoint-head table is introduced.

## Delivered in this increment

A versioned canonical event preimage is defined identically in Go and PostgreSQL. The encoding is:

`"wedecent-checkpoint-event-v2" || 0x00 || fields`

Each of six UTF-8 strings (action, scope kind, device ID, account ID, organization ID, operation ID) is prefixed with a four-byte big-endian byte length. Three 32-byte digests follow (request, participant vector, previous hash), followed by generation and revocation epoch as unsigned eight-byte big-endian values. The Go helper limits counters to PostgreSQL's signed-bigint range.

The SQL migration exposes immutable encoding/hash helpers. The Go package exposes `CheckpointEventV2Encoding` and `CheckpointEventV2Hash`. A shared golden vector is consumed by a Go regression and a SQL pgTAP regression.

This is a new encoding version. Existing replay history and its legacy hash formula are not reinterpreted or rewritten.

## Critical implementation boundary

This increment does **not** yet provide the PostgreSQL authority adapter or activate the v2 event encoding in the existing replay writer. It intentionally does not create or update a participant head, reserve/commit a fence, or represent database commit as witness consensus.

The C184 integration contract identifies why a pure helper cannot be safely layered as a second writer: the existing `consume_port_forward_authorization` function must participate in the new versioned head chain, and revocation/finalization must lock and advance that same per-device row set. Until the consume RPC is migrated atomically, another writer could produce incompatible head transitions. This migration therefore installs only pure, non-authoritative encoding functions.

## Remaining P0

1. Design and review an append-only event ledger and immutable operation/fingerprint records, with the existing `port_forward_replay_authority` rows remaining the sole mutable per-device heads.
2. Upgrade capability consumption to append a v2 event while preserving old replay entries as historical anchors.
3. Implement PostgreSQL transaction RPCs for reservation and commit with deterministic organization/membership/access/route/device/head lock order, all-participant compare-before-write, commit-time revalidation, exact-operation recovery, and atomic all-head updates.
4. Integrate revocation epoch mutations and finalization into the same head transitions, including explicit durable pending-operation supersession/abort semantics. A timeout or local process must never cancel a distributed reservation.
5. Implement production Go adapters for `ReplayCheckpointProvider`, `CheckpointFenceAtomicPrimary`, `CheckpointFenceHeadReader`, and `CheckpointAuthorityBinding`; retain Ed25519 primary signing and independently verified strict-majority witness receipts.
6. Add independent PostgreSQL-session races and failure/restart tests, then run exact-SHA CI and Desktop workflows.

## Verification status

No local Go, PostgreSQL, or Supabase CLI execution is claimed. The shared-vector regressions and SQL migration are committed as groundwork only; they require exact-HEAD CI and database workflow confirmation before being considered verified.

No production credentials, signing keys, witness endpoints, or trust anchors were created. No migration was applied to a live database.
