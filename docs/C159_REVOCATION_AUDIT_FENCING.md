# C159 — revocation locking, audit integrity and distributed fencing

## Revision and PR state

- Repository: `ADRN-9/wedecent`
- Branch: `feat/secure-port-forwarding-foundation`
- PR: #186 (must remain open and draft)
- C159 starting HEAD: `8b74fe55d7db329f6e0c6e58238ea452d9e6027e`
- C159 executable-source revision verified by CI: `9a3185af8047c6f235d55794f6760cc005252531`

No merge, signing, deployment or production publication was performed.

## Local locking and correctness changes

### Unix lock inode protection

Unix replay locking now uses a persistent `.lock.anchor` inode as the actual flock target. The existing `.lock` path is a hard-link alias retained for compatibility and diagnostics; `.lock.marker` is a second persistent hard-link identity marker.

- First initialization creates the anchor with exclusive creation, forces mode 0600, validates owner/mode/type, fsyncs the file, and syncs the containing directory.
- The visible `.lock` alias and `.lock.marker` are created as hard links to the anchor and checked with `os.SameFile`.
- `NewFileCheckpointPendingStore` initializes both the pending-journal lock and the separate transition lock before accepting the store; legacy pre-anchor lock files are adopted in place.
- Lock acquisition always opens and flocks the anchor, not the alias.
- A missing or replaced alias after initialization fails closed.
- If both anchor and alias disappear after state/initialization metadata exists, recreation is rejected.
- The opened anchor, anchor path and visible alias are rechecked after the flock is acquired.
- Existing pre-anchor `.lock` files can be adopted by hard-linking the same inode as the persistent anchor; the existing lock inode is not replaced.

This protects against deletion/replacement of the visible lock path splitting two processes onto separate inodes. It does not protect against a privileged or same-account attacker who can also rewrite the protected parent directory and all state artifacts; OS-level ownership/permission boundaries remain part of the threat model.

A Unix-only separate-process regression, `TestUnixReplayLockDeletionAcrossProcessesFailsClosed`, holds the parent process lock while a child process deletes the visible alias and attempts acquisition. The child must fail closed; the parent retains the anchor inode and subsequent acquisitions reject the missing alias. `TestUnixReplayOSLockWaitHonorsCancellation` exercises cancellation while waiting on the actual OS flock.

### Cancellation-aware lock acquisition

- The process-local path mutex uses `Mutex.TryLock` with context-aware bounded polling.
- Unix OS flock uses `LOCK_NB` with context-aware retry.
- Windows `LockFileEx` uses `LOCKFILE_FAIL_IMMEDIATELY` with context-aware retry. The main Windows lock handle no longer shares delete access; the bootstrap handle also denies delete sharing while it protects lock initialization.
- File-backed pending-store transition and snapshot-update paths pass their caller context into lock acquisition.
- File replay initialization and consumption pass the operation context through the lock and retry path.
- Memory-backed transition locking uses `TryLock` with context-aware bounded polling.

`TestCheckpointTransitionLockCancellation` covers file-backed and memory-backed pending stores. Platform-specific OS-lock cancellation tests cover Unix and Windows lock waiters.

### Revoke/Finalize concurrency regression

`TestRevokeAndFinalizeShareTransitionLock` now uses an explicit contention hook fired only after the competing lock attempt has actually encountered a held lock. It no longer uses a 30 ms sleep as proof of serialization.

- Both finalization-first and revocation-first orderings are exercised.
- Both memory-backed and file-backed stores are exercised.
- All blocking channels are initialized and released through `sync.Once` cleanup.
- Each subtest has a 10-second context deadline and bounded result waits.
- The test checks callback/primary-revocation ordering after observing actual lock contention.

### Unlock error propagation

The standalone acknowledgement and equivocation wrappers now join unlock failures into their returned errors for both file-backed and memory-backed stores. The standalone witness acknowledgement-quorum wrapper also propagates its unlock error. Revoke, Consume and Finalize already return joined unlock errors.

Regression coverage injects unlock failures into the acknowledgement, equivocation and witness-quorum wrappers for memory-backed stores, and acknowledgement/equivocation wrappers for file-backed stores.

## Windows v2 pending-journal fixture ownership correction

The assigned starting HEAD already contains the Windows v2 journal test-fixture correction in commit `8b74fe55d7db329f6e0c6e58238ea452d9e6027e`:

- `TestVersionTwoPendingJournalIsRejectedWithoutChangingOriginalBytes` writes the v2 fixture bytes and then calls `setReplayFileOwner(path)` before constructing the file-backed pending store.
- On Windows, `secureReplayFile` checks current-user ownership and DACL restrictions. The test fixture now satisfies the same ownership precondition as production journal files, so the test can specifically verify v2 rejection and byte preservation instead of failing early on a foreign temp-file owner.
- This C159 change was verified by source inspection. Passing Windows execution evidence must come from exact-HEAD CI, not from the source change itself.

## Production audit sink — integration is absent

The production contract is `CheckpointFinalizationAuditor` in `internal/portforward/checkpoint_authorization_replay.go`. `CheckpointAuthorizationReplay` has a `FinalizationAuditor` field and `FinalizeExpiredPortForwardAuthorization` fails closed when it is nil. It records started, completed, revoked, membership-unavailable and failed outcomes with a stable operation ID.

The inspected Local Core wiring does not supply it:

- `newLocalCoreForwardingVerifier` constructs `CheckpointAuthorizationReplay` without setting `FinalizationAuditor`.
- `coreprocess.Config` has no production finalization-auditor field or constructor.
- `cmd/wd-core/main.go` supplies neither a concrete checkpoint primary/witness provider nor a finalization auditor.
- No concrete production implementation of `CheckpointFinalizationAuditor` was found in the inspected PR tree.

The existing `internal/audit.Log.Append` is a local append-only JSONL logger. It does not atomically deduplicate by `(operation_id, outcome)`; it is not a valid substitute. The file-backed audit test fixture is test-only and is not production evidence.

No production adapter was added because the available runtime does not provide a configured checkpoint provider/service endpoint, production audit endpoint contract, or provisioned service credentials. Inventing a local-only adapter or treating ordinary append-only logging as production idempotency would violate the required trust boundary.

**Exact dependency:** provide a production-owned checkpoint-finalization audit service and an authenticated Local Core adapter. The service must commit an audit row transactionally with a unique constraint on `(operation_id, outcome)`, verify the device identity and request binding, return success for exact retries, reject conflicting content for an existing pair, retain records under the approved retention policy, and expose independently inspectable durability evidence. Wire it into Local Core and prove concurrent retries and crash/restart recovery against that deployed service.

## Distributed revocation/finalization fencing — service dependency

The inspected Supabase project has meaningful but narrower atomicity:

- `port_forward_replay_authority` and `port_forward_replay_entries` provide a per-device monotonic replay generation and append-only JTI chain.
- `consume_port_forward_authorization` is a transactionally locked RPC that checks forwarding participants, membership, permissions, route authorization, revocation epochs and JTI replay.
- The later atomic authorization migration snapshots participant/organization authority and revocation epochs for forwarding authorization consumption.
- `supabase/functions/port-forward-replay/index.ts` verifies the capability and device signature before calling the replay-consumption RPC.

Those mechanisms fence authorization consumption; they do not implement the checkpoint protocol's primary/witness commit, head, revoke, acknowledgement or equivocation operations.

The inspected Go tree defines `ReplayCheckpointProvider` and `CheckpointWitness` interfaces but has no concrete production primary/witness adapter. The deterministic primary and witnesses are test implementations. The legacy `RemoteReplay` is not a substitute: `NewProductionRemoteReplay` explicitly rejects the single-provider path because independent witness quorum is required. No Supabase checkpoint-witness tables, fencing RPCs or witness service endpoints were found in the inspected PR tree.

**Exact dependency:** the independently owned primary and witness services must implement one shared monotonic ordering protocol. It must atomically compare and advance participant revocation epochs, persist the finalization/revocation decision and stable operation ID, issue monotonic fencing tokens, reject stale tokens and replays, and make every witness durably acknowledge the same ordered state. Required evidence includes service-side transaction/locking design, stale-token negative tests, cross-region concurrent revoke/finalize tests, restart recovery, signed head/receipt verification, quorum behavior and deployed operational ownership. Local process mutexes, flock and the client pending journal do not establish distributed atomicity.

## Verification status

At the time this note was written, the first CI run on C159 changes exposed a compile-time error in the context-aware replay initialization call. That defect was corrected in commit `383f8f36969ff398d031fc80d056bdc149954b11`. The failed run is not counted as a pass.

Exact-HEAD CI and all three Desktop platform checks must be inspected again after the correction. Go tests, race tests, vet and platform checks are not claimed as passing until their exact-HEAD jobs and logs show success.
