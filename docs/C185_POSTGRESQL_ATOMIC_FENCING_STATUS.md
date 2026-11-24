# C185 — PostgreSQL atomic fencing implementation status

## Reconciliation

- Repository: `ADRN-9/wedecent`
- Branch: `feat/secure-port-forwarding-foundation`
- Starting HEAD (C184): `9c1e46eeab9a261fa15b093f8d06c64315a0dc58`
- PR #186: open, draft, unmerged; head was reconciled to the branch before this task's changes.
- C184 contract: `docs/C184_CANONICAL_CHECKPOINT_AUTHORITY_INTEGRATION_CONTRACT.md` (present and unchanged).

The existing migrations are:
- `20261123080000_port_forward_replay_authority.sql`
- `20261124070000_atomic_port_forward_authorization.sql`
- `20261124120000_checkpoint_finalization_audit.sql`

No PostgreSQL checkpoint/fencing migration or database implementation of `CheckpointFenceAtomicPrimary` / `CheckpointFenceHeadReader` exists in the branch at the reconciled starting revision.

## C185 implementation decision

**The production PostgreSQL atomic primary is not implemented in this cycle.** The repository source does not yet provide a complete canonical database contract that a correct adapter can implement, and no real PostgreSQL integration environment was available to this worker outside GitHub Actions. It would be unsafe to label a mock, file journal, or caller-provided head digest as the PostgreSQL authority.

The missing database contract is not simply a missing Go struct:

1. The existing `port_forward_replay_authority` row advances for one consuming device's replay JTI. It does not represent a shared operation across the complete participant vector.
2. `devices.revocation_epoch` changes in device/membership/access transactions but does not append to that replay generation/hash chain.
3. `record_checkpoint_finalization` persists immutable audit outcomes and revalidates participant membership/revocation in a separate transaction. It does not compare-and-advance the canonical replay head.
4. Existing durable fence primary/witness implementations are file-journal implementations, and the coordinator is not a PostgreSQL adapter wired into the authorization lifecycle.
5. The SQL transaction cannot atomically commit with independently administered witness services. Witness acknowledgements must remain Ed25519-verified, distinct-key, strict-majority evidence; database row locks do not replace those signatures or witness durability.

The C184 contract describes the required shared row-lock order and event-ledger approach. The remaining implementation prerequisite is a reviewed schema/API contract that resolves how the existing replay entry ledger is extended to record consume, revoke, reservation, and terminal commit events while retaining one authoritative per-device head. This migration must also define idempotent operation reservation, operation fingerprint immutability, participant-vector canonicalization, token-signature persistence/recovery, and the exact relationship between a DB commit and external signer/witness acknowledgements.

No parallel checkpoint-head table was created. No production signing key, trust anchor, witness endpoint, or credential was invented or provisioned. No production migration was applied.

## Independent code remediation delivered

The exact-HEAD CI run on starting revision `9c1e46eeab9a261fa15b093f8d06c64315a0dc58` exposed one deterministic cross-platform Go test panic in both Linux and Windows:

```
TestFinalizationCallbackIsIdempotentAcrossCompactionFailureAndRestart
panic: interface conversion: portforward.ReplayCheckpointProvider is
*portforward.testAtomicCheckpointPrimary, not
*portforward.deterministicCheckpointProvider
replay_witness_test.go:2850
```

The fixture correctly wraps the deterministic replay provider in `testAtomicCheckpointPrimary`; the test incorrectly asserted the wrapper directly to the inner type. This was a test-fixture type assertion defect, not a Windows ACL or macOS durability defect.

Changed:
- `internal/portforward/replay_witness_test.go`

The test now checks the expected `*testAtomicCheckpointPrimary` adapter and its non-nil `replay` field before using the underlying deterministic provider. It fails with a descriptive test error rather than panicking if fixture composition changes.

Commit:
- `400a0331697daf79e1e733ad09bfdf9ec62561d4` — `test: unwrap atomic checkpoint primary safely`

No production checkpoint, Windows ownership/ACL, or macOS durability implementation was modified.

## CI evidence and exact-SHA status

### Starting revision

For `9c1e46eeab9a261fa15b093f8d06c64315a0dc58`:

- CI run [45488733938](https://github.com/ADRN-9/wedecent/actions/runs/45488733938):
  - Supabase DB job passed, including disposable local Supabase database tests and independent-session port-forward authorization races.
  - Relay worker, control plane, route-capability client, Windows release, and routed E2E passed.
  - Linux failed in `go test ./internal/session ./internal/portforward ./internal/transport` on the unsafe test type assertion above.
  - Windows failed in `go test ./...` on the same panic.
  - macOS agent was still queued at inspection.
- Desktop run [45488733891](https://github.com/ADRN-9/wedecent/actions/runs/45488733891):
  - Linux Tauri check completed successfully.
  - Windows Tauri check was in progress.
  - macOS Tauri check was queued.
  - This was not a completed cross-platform Desktop pass.

### Remediation revision

At `400a0331697daf79e1e733ad09bfdf9ec62561d4`:

- CI run [45489459597](https://github.com/ADRN-9/wedecent/actions/runs/45489459597) was triggered and remained in progress at the latest inspection:
  - relay worker, control plane, route-capability client, and routed E2E had passed;
  - Supabase DB, Linux, Windows agent, Windows release were still running;
  - macOS agent was queued.
- Desktop run [45489459584](https://github.com/ADRN-9/wedecent/actions/runs/45489459584): Linux, Windows and macOS Tauri checks were still in progress.

These are the exact run states observed, not claims of passing final workflows. Recheck the exact SHA after the workflows finish. No local `go test`, `psql`, or Supabase CLI execution is claimed.

## Guarantees implemented vs unproven

Implemented in the existing repository (not newly delivered by C185):
- Per-device replay JTI uniqueness and hash-chain advancement inside the capability-consumption RPC transaction.
- Participant authorization snapshot locking/revalidation in the capability-consumption RPC.
- Transactional revocation epochs for device/membership/access changes.
- Separate durable finalization operation/evidence recording and participant revalidation.
- Go Ed25519 checkpoint and fence token contracts, independent witness signature verification, duplicate-witness/key rejection, and strict-majority quorum logic.
- Durable file-journal fence primary/witness test implementations with exact-operation recovery and Linux locking.
- TLS 1.3/hostname/SPKI-pinned file-fence transport contract.

Not implemented or not proven:
- A PostgreSQL-backed atomic primary/head reader.
- One atomic PostgreSQL transition over every participant head for reservation and commit.
- A common generation/hash ordering revoke against finalization.
- PostgreSQL commit-time head revalidation tied to the Go fence token and witness quorum.
- Real PostgreSQL reservation/finalization/revocation concurrency and interrupted-commit recovery tests for this new authority.
- Independent-host witness operation, crash recovery, partition behavior, quorum intersection and anti-rollback evidence.
- Production primary signer provisioning, independent witness trust anchors, DNS/SPKI pin provisioning and independent durable storage.

PR #186 remains open, draft and unmerged. PR #176 was not changed or merged. No production migration was applied, and no deployment, production signing, credential provisioning, or activation was performed.
