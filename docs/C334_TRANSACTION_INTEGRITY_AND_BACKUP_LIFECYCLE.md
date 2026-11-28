# C334 — Transaction integrity and safe backup lifecycle

**Repository:** ADRN-9/wedecent  
**PR:** #209 — open, draft, unmerged  
**C333 starting reference:** `4c1a93c648d9f349024e862a674b84089d45c987`  
**C334 tested code candidate:** `bf7b583dc4fb9e19edbee509eb9329e69f375a51`  
**Date:** 2026-11-27

## Executive summary

C334 connects Windows backup deletion to a durable post-commit lifecycle. The Go updater now persists and validates transaction phase transitions, calls a Windows committed-backup finalizer while holding the same cross-process update lock, and retries finalization before admitting a subsequent update. The Windows finalizer validates protected updater state, the authenticated installer metadata and transaction journal, all five installed replacement hashes, and each remaining backup digest before cleanup.

Cleanup is deliberately after commit. If cleanup is interrupted, the committed journal remains the retry marker; missing backups are accepted only for a journal durably marked committed and only when all five current binaries still match the journal. If cleanup fails, the update remains committed, the API reports `ErrInstallCleanupPending`, and the next updater pass retries cleanup before discovery or a new update.

The C333 fail-closed rollback fix is retained: a failed binary rollback does not restart the service. PR #209 remains draft and unmerged.

## Implementation

### 1. Atomic transaction-state transitions

- Added `validateInstallStateTransition` and routed pending, executing, recovery-required, committed and final state writes through `persistInstallTransition`.
- Transaction identity (ID, sequence, package/manifest digests, previous/target versions) and keyset trust baseline are immutable during a transaction.
- Pending state must bind its previous version to the protected installed version.
- The stable sequence and installed version can advance only in the final atomic state write after successful installer execution and a durable committed transaction marker.
- Recovery can clear a transaction only after the adapter proves either applied (target sequence/version) or restored (previous version, unchanged sequence).
- Unknown phases, replayed or altered transaction identities, stale sequences, premature clearing and inconsistent installed-version bindings are rejected.

### 2. Cross-process serialization

- Existing Windows update serialization uses an exclusive `LockFileEx` byte-range lock on `.update-apply.lock`; Unix uses `flock`.
- Added `TestUpdateLockSerializesSeparateProcesses`, which holds the lock in a child test process, proves a second process times out while it is held, then proves acquisition succeeds after release.
- The Go updater holds the lock across installer execution and post-commit finalization.
- `ApplyStable` retries committed cleanup under that same lock before discovering/admitting another update.

This proves the managed updater's cross-process lock path. It is not a test of simultaneous manual administrative invocations of the PowerShell installer outside the Go-managed updater.

### 3. Safe Windows backup lifecycle

- Added `InstallerCommitFinalizer` and `PowerShellInstallerExecutor.FinalizeCommitted`.
- After the final updater state commit, Go invokes `Recover-WeDecentInstall.ps1 -FinalizeCommitted` with the exact stable sequence and installed version.
- On later updater starts, the same finalizer runs before update discovery, recovering from process termination after commit but before cleanup.
- The script requires exact protected updater state (no pending transaction), trusted installer metadata and ACLs, a protected journal root and journal files, the exact five approved binary entries, transaction-specific destination/backup associations, and SHA-256 verification of every installed target.
- It durably changes the journal to `committed` before deleting any backup. Remaining backups are hash-checked before deletion.
- Partial cleanup is idempotent: already deleted backups are accepted only when the journal says `committed` and the installed replacement still hashes correctly; remaining backups are checked and removed.
- A fully cleaned historical committed journal is accepted only when it has no remaining backups. An older unresolved journal, a future committed sequence, a mismatched version, a corrupted backup or a target hash mismatch blocks cleanup.
- Failure after commit does not roll back the installed version or sequence. It returns the explicit `ErrInstallCleanupPending`; retry occurs before another update is admitted.
- The standalone recovery path also recognizes a durable committed state with partially cleaned backups and resumes cleanup safely.

### 4. Regression coverage

Added/strengthened coverage for:
- Valid pending → executing → committed → final transitions.
- Invalid phase skips, mutated transaction digests, stale/premature sequence advancement, premature clearing, unknown phases and mismatched previous-version state.
- Applied and restored recovery outcomes; ambiguous recovery remains pending/fail-closed.
- Separate-process update lock exclusion and release.
- Cleanup invocation only after durable commit; cleanup failure preserves committed state and retry is exercised.
- Windows partial backup staging (some original backups created, others missing while destinations remain original).
- Missing, corrupted, replaced and mismatched backup associations.
- Failed rollback, repeated recovery, interrupted post-commit cleanup, repeated finalization and tampered installed target bytes.
- Service restart remains conditional on successful binary restoration.

## Exact-head validation evidence

All workflow results below target `bf7b583dc4fb9e19edbee509eb9329e69f375a51`.

| Workflow | Run ID | Result |
|---|---:|---|
| C324 updater exact-head security tests | `46013571265` | **Success** |
| Duplicate C324 updater exact-head security tests | `46013580616` | **Success** |
| Full repository CI | `46013571273` | **Success** |
| Desktop shell | `46013580573` | Windows Tauri job still in progress at report preparation; Linux and macOS jobs succeeded |

Specific evidence:
- Updater workflow ran `gofmt -l internal/updateinfo`, `go test ./internal/updateinfo -count=1`, and `go vet ./internal/updateinfo`; all passed.
- Windows-agent CI completed successfully, including `go test ./...` and the cross-process lock test.
- Windows CI steps passed: diagnostic release bundle build; PowerShell installer/hardware script parsing; upgrade process preflight; Windows installer recovery and backup-integrity tests; service recovery credential contract; state migration transaction coordinator; replay-store security regressions; native Windows agent/service-state ACL tests; native Windows binary build; and version/autostart command checks.
- The Windows installer recovery step emitted: `Windows transaction recovery and committed cleanup synthetic adversarial tests passed.`
- Windows release bundle, Linux agent, macOS agent, control-plane, Supabase DB, relay worker, route capability client and route E2E jobs passed in the full CI run.

## C332/C333 reconciliation

- C332 baseline repository CI `46006460918` passed on `7876d8b9bbe41755f7777886f3c59ab72f27bce5`.
- C332 Desktop run `46006460900` had Linux and macOS Tauri checks pass but the Windows Tauri check was cancelled; it was not a full Desktop pass.
- C333 preserved the five-binary checks and corrected service restart after rollback failure. Its report remains at [C333 five-binary preservation and integrity](C333_FIVE_BINARY_PRESERVATION_AND_INTEGRITY.md).
- C334 exact-head full CI passed. Desktop Windows Tauri validation is still outstanding in run `46013580573`; Linux and macOS Tauri checks passed.

## Remaining acceptance blockers

1. **Persistent privileged Windows VM:** Hosted GitHub Windows runners executed elevated synthetic recovery and native service tests, but no persistent isolated Windows 11/Server VM, named operator, durable service/reboot evidence or real crash/reboot acceptance has been established. ADRN-9 must designate the operator and provision/confirm the VM.
2. **Desktop Windows Tauri:** Run `46013580573` Windows Tauri job was still running when this report was prepared. Do not mark Desktop fully passed until it completes successfully.
3. **Manual PowerShell installer concurrency:** The verified cross-process lock covers Go-managed update/install/finalization. Direct standalone administrative invocations of `Install-WeDecent.ps1` do not independently acquire the Go update lock; simultaneous manual invocation versus a managed update is not claimed as proven. Treat that operational path as requiring serialization or a dedicated shared-lock implementation before accepting it as safe.
4. **Real hardware:** No physical Bluetooth RFCOMM or USB CDC-ACM/NCM hardware acceptance is part of this C334 task.

## Disposition

PR #209 remains open, draft and unmerged. No production signing, publication or deployment was performed. Repository CI and updater security checks passed at the exact tested code candidate; privileged persistent Windows VM acceptance and Desktop Windows Tauri completion remain open.
