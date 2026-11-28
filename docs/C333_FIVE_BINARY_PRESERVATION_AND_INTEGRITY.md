# C333 — Five-binary preservation and integrity report

**Repository:** ADRN-9/wedecent  
**PR:** #209 — open, draft, unmerged  
**Starting HEAD:** `7876d8b9bbe41755f7777886f3c59ab72f27bce5`  
**C333 candidate HEAD:** `7d1f24a0da85e8e778e55531e2dcc38ad12262c8`  
**Date:** 2026-11-27

## Summary

Inspected the Windows installer transaction, recovery script and adversarial recovery test. The existing implementation uses a transaction-specific backup for each of the five binaries, verifies all backups before the first replacement, pins source and destination SHA-256 values, and rejects mismatched/missing/corrupt backups during recovery.

Two service-lifecycle fail-closed defects were corrected: the regular upgrade path no longer restarts the service after binary rollback failure, and interrupted-installer recovery no longer uses a `finally` block that restarts the service when rollback throws. Recovery now verifies each restored destination digest before persisting `rolled-back`.

Added adversarial regression cases for a replaced backup and a journal that associates one binary with another binary's backup path.

## Five-binary integrity inspection

The exact five managed executable names are:
- `wd.exe`
- `wd-agent.exe`
- `wd-routerctl.exe`
- `wd-core.exe`
- `wd-ui.exe`

Source inspection at the starting candidate established:

1. `Assert-ReleaseBundle` requires a manifest entry for each of the five binaries and verifies the actual SHA-256 before installation.
2. `Install-Binaries` rehashes each source and compares it with the pinned manifest hash; it records whether the destination existed and its original SHA-256.
3. A transaction journal binds transaction ID, package and manifest digests, versions, sequence, and the exact five destination/backup/replacement records.
4. Each pre-existing destination is rehashed before its transaction-specific backup is copied; the backup is rehashed before any replacement begins. All five backup records are processed before the first call to `Install-Binary`.
5. `Install-Binary` verifies the staged copy and verifies the destination after replacement.
6. Recovery validates the exact approved binary set, unique names, destination paths, transaction-specific backup paths, original and replacement hashes, and the installed version/sequence authority before rollback.
7. Rollback preflights all originals/backups before mutation, restores from a verified backup, and verifies the final destination hash. A missing backup is accepted only if the original destination itself is still byte-identical to the recorded original.
8. For a binary that did not exist before the transaction, rollback removes it only if its contents match the recorded replacement hash.

These are repository source findings, not proof of real privileged Windows execution.

## Changes made

### Commit 1 — `172b9bbe175051a65ed636ff85e35ef25d29ec91`

File: `installer/windows/Install-WeDecent.ps1`

- `Invoke-RollbackStep` now returns an explicit success boolean.
- The existing-service upgrade catch path restarts the prior agent only when `Rollback-Binaries` completed successfully.
- If binary restoration fails, it emits an explicit warning and leaves the agent service stopped.

### Commit 2 — `9cd24754a8f1c1bb4d76b9e9122c8e256f4faebd`

File: `installer/windows/Install-WeDecent.ps1`

- Removed the interrupted-transaction recovery `finally` restart path.
- Recovery now persists the `rolled-back` journal phase only after restoring and verifying all five prior binaries.
- A rollback exception now exits fail-closed with the service stopped and backups retained.
- Added explicit final destination hash verification even when the original destination remains in place and the backup is absent.

### Commit 3 — `7d1f24a0da85e8e778e55531e2dcc38ad12262c8`

File: `scripts/test-windows-install-recovery.ps1`

- Added static regression assertions that service restart is gated on successful binary restoration and interrupted recovery has no rollback-restart `finally` block.
- Added a replaced-backup case.
- Added a mismatched backup-association case.
- Both cases assert rejection before any of the five installed destination files are mutated.

## Backup retention and cleanup finding

Backups are transaction-specific and are preserved through the installer replacement sequence. Recovery verifies their digest and retains them when rollback fails or state is ambiguous.

**Post-commit cleanup is not connected.** The source defines `Remove-BinaryBackup` and `Remove-BinaryBackups`, but the only references are the function definitions and their internal call; no successful transaction lifecycle invokes the cleanup function. The current behavior therefore retains binary backups after successful commit as well as after failure. This is a disk-usage leak, not evidence of unsafe early deletion.

Do not wire cleanup to installer success alone. For managed updates, cleanup must be authorized only after the protected updater state durably records the exact transaction as committed, and after all five installed destination hashes independently match the journal's replacement hashes. For non-managed installs, require the same durable state/journal consistency check. Cleanup must be idempotent and must preserve all backups on unknown state, journal mismatch, hash mismatch, or failed commit. This remains open engineering work.

## Validation evidence

Exact-head GitHub Actions for candidate `7d1f24a0da85e8e778e55531e2dcc38ad12262c8`:

| Workflow | Run ID | Latest observed status |
|---|---:|---|
| C324 updater exact-head security tests | `46007317327` | **Success** |
| Full repository CI | `46007317280` | In progress |
| Desktop shell | `46007317308` | In progress |

The updater security job completed successfully on the exact candidate SHA. The full repository and Desktop workflows had not completed at the latest status read. No local PowerShell execution was performed in this task.

C332 baseline reconciliation:
- Repository CI `46006460918` on `7876d8b9bbe41755f7777886f3c59ab72f27bce5`: success; all listed jobs, including `windows-agent` and `windows-release`, completed successfully.
- Desktop `46006460900` on the same SHA: Linux and macOS jobs succeeded; Windows job was cancelled. Overall conclusion: cancelled, not passed.
- Updater security `46006460872` on the same SHA: success.

Hosted Windows Actions are ephemeral runners. They do not establish persistent privileged VM acceptance, actual service interruption/reboot recovery, or real installer operation under the dedicated non-admin service account.

## Remaining blockers

1. **Privileged Windows VM:** C332 assessment remains applicable. No persistent isolated Windows 11/Server VM identity, named individual operator, access evidence, SCM/reboot evidence or real privileged acceptance record has been established. ADRN-9 must designate the operator and provision/confirm the VM.
2. **Post-commit backup cleanup:** cleanup helper exists but is not invoked. Implement a verified, idempotent post-commit cleanup path bound to protected updater state and all five destination hashes.
3. **Exact-head full CI and Desktop:** runs `46007317280` and `46007317308` were still running at report preparation. Do not call them passed until completed successfully.
4. **Real crash recovery:** actual forced process termination and reboot on the persistent Windows VM remain untested.

## PR and release disposition

PR #209 remains open and draft. No merge, production signing, release publication or deployment was performed. This report does not claim production readiness or privileged Windows acceptance.
