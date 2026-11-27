# C335 — Windows recovery remediation status and evidence

**Repository:** ADRN-9/wedecent  
**PR:** #209 — open, draft, unmerged  
**Inspection date:** 2026-11-27  
**Reconciled source HEAD:** `172839462fe2e8e9092411bd23cb5c138cd6bfb0`  
**Base:** `security/c298-transport-override-fail-closed` at `629456e4a2f594adad7433589aaa3591454503d5`  
**Disposition:** C335 implementation is NOT COMPLETE. This report records verified source findings and current CI evidence; it does not claim remediation.

## Repository identity and ancestry

GitHub PR metadata confirms:
- Source branch: `security/c324-verified-update-admission-recovery`
- Base branch: `security/c298-transport-override-fail-closed`
- PR #209: open, draft=true, merged=false
- Head SHA: `172839462fe2e8e9092411bd23cb5c138cd6bfb0`
- Base SHA: `629456e4a2f594adad7433589aaa3591454503d5`
- GitHub compare: 165 commits ahead, 0 behind; merge base equals the PR base SHA.

The connected GitHub repository is `ADRN-9/wedecent`; its default branch is `main`. The GitHub connection reports push/admin permissions. No branch rewrite, merge, signing, publication, or deployment was performed.

## Confirmed C335 defects at the reconciled HEAD

### 1. Installer metadata is outside the rollback transaction

`installer/windows/Install-WeDecent.ps1`:
- `Write-WeDecentMetadata` (around line 243) atomically replaces `ProgramData\WeDecent\installer.json`, but deletes its temporary previous-file backup in `finally`.
- The managed upgrade path starts the new service and writes target-version metadata around lines 1317–1325.
- The transaction journal created by `Install-Binaries` (around line 1006) records binary hashes and service state, but no authenticated prior metadata bytes/digest/existence marker.
- The catch path restores binaries but does not restore the previous metadata.

`installer/windows/Recover-WeDecentInstall.ps1` also validates the current metadata and restores binary backups without restoring prior metadata. An interruption after metadata publication but before Go's durable state commit can therefore leave old binaries paired with target-version metadata.

### 2. SCM service existence and identity are not mandatory in recovery

At `Recover-WeDecentInstall.ps1` around lines 435–469:
- `Get-Service -ErrorAction SilentlyContinue` permits the expected service to be absent.
- If the journal says the service was running, restart is skipped when the service object is null.
- Recovery can still persist `rolled-back` and return `not-applied`, allowing the Go adapter to treat the rollback as verified.
- The script does not authenticate the service's SCM ImagePath, StartName/account SID, and enabled start configuration against protected metadata before recovery.

### 3. Recovery journal/restart ordering is unsafe

The same recovery path starts the service and waits for Running before persisting the `rolled-back` journal marker. A journal publication failure can therefore leave a service running while the transaction remains pending. Restart failure is not followed by a guaranteed stop-and-retain-pending sequence.

The installer-side interrupted-recovery path also needs the same explicit invariant: restore and verify all five binaries and prior metadata, durably persist the rollback marker, then restart. Any incomplete restore or failed journal write must leave the service stopped.

### 4. Existing tests do not exercise actual SCM recovery

`scripts/test-windows-install-recovery.ps1` creates filesystem/journal fixtures with `service_was_running = $false`. It does not provision or manipulate the named SCM service. Its source assertions and synthetic filesystem fixtures therefore cannot prove:
- missing/misconfigured service rejection;
- stop failure or stop timeout handling;
- restart failure followed by stop;
- service account SID/ImagePath validation;
- service state after interrupted metadata restoration.

The test suite does include repeated recovery and several backup/journal integrity cases, but those are synthetic filesystem tests, not privileged Windows VM acceptance.

## Exact-HEAD hosted validation

All three GitHub Actions workflows completed successfully for HEAD `172839462fe2e8e9092411bd23cb5c138cd6bfb0`:

| Workflow | Run ID | Result |
|---|---:|---|
| C324 updater exact-head security tests | `46014509594` | SUCCESS |
| Repository CI | `46014509572` | SUCCESS — 9/9 jobs |
| Desktop shell | `46014509530` | SUCCESS — Windows, Linux, macOS |

Repository CI Windows-agent job `140558083286` passed, including step 7, **Test Windows installer recovery and backup integrity**. The updater-security workflow passed its configured formatting, `go test ./internal/updateinfo -count=1`, and `go vet ./internal/updateinfo` steps. Desktop jobs `140558133666`, `140558134243`, and `140558134245` passed for Linux, Windows, and macOS respectively.

These are exact-HEAD hosted CI results. They do not demonstrate real service recovery, power-loss recovery, or a persistent privileged Windows installation.

## C335 implementation status

**No source-code or test-file modifications were made in this C335 execution.** The repository was inspected through GitHub read APIs. No local shell, PowerShell, Go, or other commands were executed. No test was run by this operator; the CI results above were queried from GitHub Actions.

Required implementation remains:
1. Persist a bounded, authenticated snapshot of prior installer metadata (existence, exact bytes, digest) in the durable transaction before mutating metadata.
2. On rollback, validate the snapshot and restore exact previous metadata atomically; if no prior metadata existed, remove only the authenticated transaction's newly written metadata.
3. Verify the expected SCM service exists and authenticate ImagePath, StartName/account SID and start mode against protected metadata before rollback.
4. Stop and confirm the service is stopped before file mutation.
5. Restore and hash-verify all five previous binaries and prior metadata.
6. Persist the durable `rolled-back` journal state before attempting restart.
7. On restart failure/timeout, stop the service, retain the pending updater authorization and backups, and fail closed. Repeated recovery must remain idempotent.
8. Add adversarial tests for interrupted metadata restore, missing/misconfigured SCM service, stop/start failures, journal-write failure after restore, repeated recovery and inconsistent metadata/journal snapshots.

## External acceptance blockers

- **Persistent privileged Windows VM:** not evidenced as provisioned or accessible in repository records.
- **Accountable individual operator:** ADRN-9 is identified as the accountable organization, but no named individual VM operator is designated.
- Hosted `windows-latest` is not a substitute for process termination/reboot tests against a real SCM service and persistent NTFS installation.
- The separate production updater integration/privileged broker concerns identified by prior independent reviews remain unresolved.

A human ADRN-9 administrator must designate the VM operator and confirm/provision the isolated persistent Windows VM. This does not block independent code remediation, which remains outstanding.

## Release/PR controls

PR #209 must remain open, draft and unmerged. Preserve history. Do not sign, publish, or deploy production artifacts. No production credentials, trust anchors, or customer data were accessed.
