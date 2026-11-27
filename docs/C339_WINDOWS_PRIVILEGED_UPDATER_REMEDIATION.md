# C339 — Windows privileged updater remediation status

**Repository:** ADRN-9/wedecent  
**PR:** #209 — open, draft, unmerged  
**Branch:** `security/c324-verified-update-admission-recovery`  
**Report HEAD:** `f94f51c9419bc4df237ca9bc31225e221511fe7d`  
**Date:** 2026-11-27

## Disposition

Implementation work advanced the native Windows updater path and process-authentication boundary. **Production acceptance is not established.** The exact report HEAD has not yet received a fresh successful updater-security, full repository, and desktop CI run. The Windows recovery PowerShell script requires canonical restoration and syntax/integration validation before this PR can be considered buildable.

PR #209 remains open, draft and unmerged. No production signing, publication, deployment, merge, or production trust-anchor provisioning was performed.

## Changes present at report HEAD

- Repaired the invalid multiline Go string in `internal/updateinfo/windows_runtime.go` by using a Go raw string for the PowerShell Authenticode verification script.
- Added the native Windows desktop **Check for updates** action. It disconnects an active session, stops Local Core, invokes the installed updater, and waits for a readiness response before closing the UI.
- Added a UAC `runas` handoff in `cmd/wd-agent/update_windows.go`. The elevated helper validates the installed updater and starts a protected staged worker.
- The staged worker is copied from the installed updater, checked for digest equality, and verified against the provisioned Authenticode publisher pin before execution.
- The worker waits for both launcher processes to exit before applying the transaction, avoiding replacement of a running updater binary.
- Process handles are checked against the expected executable image path and Windows process-token user SID plus AuthenticationId (logon-session LUID). Missing/ambiguous identities fail closed.
- Added regression coverage for cross-user and cross-session identity mismatch, image-path substitution, the worker handoff, caller-supplied path/trust rejection, strict update-root JSON, and PowerShell path verification.
- The installer now snapshots the existing recovery-script digest and transaction-specific backup path into the install journal, verifies the backup before replacing the script, and retains the backup until committed cleanup. Its rollback helper restores the prior script and keeps the backup if restoration fails.
- The Go executor now checks the recovery-script path, transaction journal binding, current script digest, and transaction backup digest before launching recovery or committed cleanup on Windows.

## Desktop entrypoint assessment

### Native Go Windows desktop

The inspected native path is `cmd/wd-ui/ui_windows.go` → installed `wd-agent.exe update apply --wait-for-ui <pid>` → UAC helper → protected staged worker → `updateinfo.ApplyInstalledWindowsStable` → transaction-aware `PowerShellInstallerExecutor`.

This is an implemented source-level call path. It is **not yet proven by a real privileged Windows installation acceptance test**.

### Tauri desktop

Inspected `desktop/src-tauri/src/main.rs` at the report HEAD. Its process launches are for the desktop bridge; it contains no updater invocation or UAC updater handoff. **Tauri updater integration is not present and is not claimed.** The Tauri shell and native Go UI are separate product entrypoints.

## Exact-head workflow evidence and failures

The following runs are real GitHub Actions results, but they target earlier intermediate heads, not report HEAD `f94f51c9419bc4df237ca9bc31225e221511fe7d`.

| Run ID | Workflow | Result | Relevant finding |
|---:|---|---|---|
| `46048600689` | C324 updater security | Failed | Invalid multiline Go string; formatter/test stage could not parse Windows runtime |
| `46048600749` | Full CI | Failed | Windows release and Windows agent builds failed from the same Go syntax defect; Linux failed a release-anchor check |
| `46056851724` | C324 updater security | Failed | `go test ./internal/updateinfo` exposed a missing `ProgramData` assumption in a Linux process-fixture finalizer |
| `46056972721` | C324 updater security | Failed | Process fixture expected the pre-cleanup call; sequence-zero skip suppressed it |
| `46057123217` | C324 updater security | Failed | Windows cross-compilation found missing `currentProcessElevated` and a public/private Ed25519 test-key mix-up |

At run `46057123217`, `gofmt -l internal/updateinfo` passed and `go test ./internal/updateinfo -count=1` passed; Windows cross-compilation then failed. The missing Windows elevation wrapper and test-key ordering were corrected in commits `9f9257fc55e6990dbb30e4da7490ddd371b9617e` and `f94f51c9419bc4df237ca9bc31225e221511fe7d`. **Those fixes have not yet been validated by a fresh workflow at the report HEAD.**

Earlier full-CI and Desktop runs are not substitutes for exact-head validation. No successful exact-head workflow IDs or job outcomes are claimed here.

## Outstanding blockers

1. **Recovery script integrity implementation is not accepted.** The current branch's `installer/windows/Recover-WeDecentInstall.ps1` is 146,510 bytes / 2,494 lines and contains malformed concatenated fragments, including an invalid recovery-script digest condition. Restore a single canonical script, integrate the transaction-bound backup validation/restore/cleanup once, and run the PowerShell recovery adversarial suite. Do not execute or ship the malformed script.
2. Add and pass adversarial interruption/corruption tests proving: backup is transaction-bound; recovery script digest is checked before elevated execution; failed installation restores the previous script; corrupted/missing backup fails before mutation; rollback failure leaves service stopped and retains the backup.
3. Add full process-authentication tests for wrong SID, wrong logon session, malformed/ambiguous token information, invalid caller image, UAC cancellation, and an elevated helper launched without the intended original caller.
4. Verify staged-worker publisher mismatch and path substitution negatives on Windows. Hosted source tests are not actual privileged install acceptance.
5. Fresh exact-HEAD runs are required for:
   - updater security: formatting, updater tests, Windows cross-compilation and vet;
   - full repository CI;
   - Windows, Linux and macOS Desktop CI;
   - Windows recovery and updater integration tests.
6. Persistent privileged Windows VM and named accountable infrastructure operator remain unprovided. Actual UAC, SCM replacement, reboot, interruption, rollback and five-binary before/after digest acceptance remain blocked.
7. Production Ed25519 update-root pin, Authenticode publisher pin, external signing, and production release credentials remain unprovisioned. Do not invent these values.

## Next priorities

1. Restore the recovery script to one valid canonical implementation and finish transaction-bound recovery-script backup lifecycle plus adversarial tests.
2. Finish process SID/logon-session and UAC negative tests, including staged-worker publisher mismatch.
3. Run all required workflows against the exact resulting HEAD and publish each workflow ID and job outcome.
4. Obtain the persistent privileged Windows VM and named operator; perform real service replacement/reboot/interruption acceptance.
5. Keep Tauri integration explicitly out of scope until its own product entrypoint is implemented and verified.

## Safety and release status

No PR merge, production signing, production publication, deployment, or production trust-anchor provisioning was performed. Hosted CI is not evidence of real privileged Windows acceptance.
