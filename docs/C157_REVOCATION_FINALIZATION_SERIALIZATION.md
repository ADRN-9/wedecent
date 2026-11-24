# C157 — local revocation/finalization serialization and audit-sink assessment

## Source changes

The pending-store contract now exposes `LockTransition(context.Context)`. Both store implementations provide it:

- `FileCheckpointPendingStore` uses the existing journal-wide `.finalize` OS lock.
- `MemoryCheckpointPendingStore` uses its existing transition mutex (test-only; not durable).

`LockFinalization` validates the checkpoint request and delegates to the shared transition lock. This preserves the existing Consume and Finalize lock boundary while allowing Revoke to acquire the same lock without inventing a checkpoint request.

`WitnessedReplayCheckpointProvider.Revoke` acquires the transition lock before reading the primary head and holds it through primary revocation, witness revocation, signature/scope validation and quorum verification. Unlock errors are joined into the operation result. Missing lock support fails closed.

Existing authenticated acknowledgement and equivocation publication paths remain serialized: the top-level Consume/Finalize operations already hold the transition lock while using their locked journal writers; public journal mutation methods acquire the same lock themselves.

## Concurrency regressions

`TestRevokeAndFinalizeShareTransitionLock` exercises both lock acquisition orders against both store implementations:

- Finalization acquires first: revocation cannot reach the primary Revoke operation until the finalization callback completes; revocation then succeeds.
- Revocation acquires first: finalization cannot invoke its audit callback while revocation is blocked inside the primary operation; after revocation and witness quorum complete, finalization fails closed.

The tests use explicit channel gates around primary operations. A short negative wait is used to assert that the competing operation has not crossed the lock boundary.

`TestFinalizationAuditSinkDeduplicatesAfterCompletionMarkerFailureAndRestart` injects failure specifically when the local completion marker is persisted after the audit callback. It restarts the file-backed pending store, retries finalization, verifies the same operation ID and outcome are supplied, and checks a file-backed test sink stores one deduplicated record.

These fixtures demonstrate local client recovery behavior only. They are not evidence of a deployed external audit service.

## Production audit-sink assessment

The repository defines `CheckpointFinalizationAuditor` with the stable operation ID and outcome in its method signature. The inspected test implementation is `checkpointFinalizationAuditFixture` in `replay_witness_test.go`; it uses in-memory maps and is not a production adapter.

The generic `internal/audit.Log.Append` implementation is a durable append-only JSONL logger with file locking and fsync, but it does not accept a stable operation ID or enforce deduplication by operation ID plus outcome. It therefore cannot be treated as an idempotent implementation of `CheckpointFinalizationAuditor`.

The inspected `cmd/wd-core/main.go` configures the current forwarding manager and legacy replay endpoint. It does not construct or inject a production `CheckpointFinalizationAuditor`, and no production implementation of that interface was found in the inspected project wiring. Production audit-sink integration is absent; the runtime must remain fail-closed until an independently durable, atomically deduplicating sink is supplied and verified.

## Security boundary and remaining dependencies

The new lock establishes only local serialization among operations sharing the same pending-store lock path or memory-store instance. It does not establish distributed atomicity between independent primary and witness services, fence revocation in another process/region/service, or protect against an authority that ignores the client-side lock.

Production activation still requires an independently administered primary/witness fencing protocol with a shared revocation/finalization linearization point, plus a production audit sink that atomically deduplicates by stable operation ID and outcome. Those integrations and their credentials, signing keys, endpoint pins, operational retention and conformance evidence are not present in the inspected repository wiring.

## Verification status

Source changes were committed to the existing PR branch. No local Go command runner was available in this execution, so Go tests, race tests and vet are not claimed as run here. Exact-HEAD GitHub Actions must be inspected after the latest commit before any verification claim is made.


### CI correction

The first CI run on exact SHA `644bf3bc6d1f4c4e516936c3d2e5b1593865d90e` found a compile-time unused local binding in the new audit-recovery test. The binding was removed in follow-up commit `74a848f560998808b942d1b8963cf14bcbca801b`. The failed run is defect-discovery evidence only; it is not counted as a pass. Exact-HEAD CI and all three Desktop platform checks for the corrected revision remain pending.
