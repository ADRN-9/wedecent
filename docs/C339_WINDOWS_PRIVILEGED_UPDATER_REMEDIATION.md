# C339 — Windows privileged updater remediation status

**Repository:** ADRN-9/wedecent  
**PR:** #209 — open, draft, unmerged  
**Branch:** `security/c324-verified-update-admission-recovery`  
**Report source HEAD:** `57e2eb07ea10b27133e1969b60980374c1df5e26`  
**Date:** 2026-11-27

## Disposition

C339 implementation has advanced, and the dedicated updater-security workflow passed at the report source HEAD. **Production acceptance is not established.** Full repository CI did not complete successfully at that HEAD; Windows and macOS Desktop jobs were cancelled, and Linux Desktop was still running when inspected. A fresh full CI and complete Windows/Linux/macOS Desktop result is still required.

PR #209 remains open, draft and unmerged. No production signing, publication, deployment, merge, or production trust-anchor provisioning was performed.

## Implementation present

- Fixed the invalid multiline Go PowerShell/AuthentiCode script literal in `internal/updateinfo/windows_runtime.go`; repaired the Windows trust-test JSON fixture and formatting.
- Corrected Go formatting in `cmd/wd-ui/bootstrap_windows.go`, `internal/updateinfo/powershell_executor.go`, and the relevant Windows runtime tests.
- Added the native Windows desktop **Check for updates** action. It stops an active terminal/Local Core session, invokes the installed updater with a UI handoff PID, and waits for the authenticated readiness response before closing the UI.
- Added a UAC `runas` handoff in `cmd/wd-agent/update_windows.go`. The elevated helper validates the installed updater and launches a staged worker.
- The staged worker is copied from the installed updater, checked for digest equality, and verified against the configured Authenticode publisher pin before execution. It waits for both launcher processes to exit before applying the transaction.
- Process handles are checked against the expected executable image path and Windows process-token user SID plus AuthenticationId (logon-session LUID). Missing/ambiguous identities fail closed.
- Added regression coverage for cross-user and cross-session identity mismatches, missing SID, image-path substitution, launcher/worker handoff, caller-supplied path/trust rejection, strict update-root JSON, and PowerShell path verification.
- Installer recovery-script publication records the target path, transaction-specific backup path, original/new SHA-256 digests and publication state. It verifies the backup before replacing the script and retains it until the transaction is durably committed.
- Interrupted rollback validates the transaction-bound script/backup, restores the previous script through a verified temporary copy, persists the restored digest/state, and leaves the backup available for retry if restoration or later recovery fails.
- The Go executor authenticates the transaction journal, installed recovery-script path/digest and prior-script backup before privileged recovery or committed-cleanup invocation. The committed cleanup path also verifies the script binding.

## Desktop entrypoint assessment

### Native Go Windows desktop

The inspected source call path is:

`cmd/wd-ui/ui_windows.go` → installed `wd-agent.exe update apply --wait-for-ui <pid>` → UAC helper → protected staged worker → `updateinfo.ApplyInstalledWindowsStable` → transaction-aware `PowerShellInstallerExecutor`.

This is an implemented source-level call path, **not** proof of a real privileged Windows installation acceptance test.

### Tauri desktop

Inspected `desktop/src-tauri/src/main.rs`. Its registered command handler exposes the desktop bridge, terminal and file-transfer commands, but no updater invocation or UAC updater handoff. **Tauri updater integration is not present and is not claimed.** Native Go UI and Tauri are separate product entrypoints.

## Workflow evidence

### Exact report-source HEAD: `57e2eb07ea10b27133e1969b60980374c1df5e26`

| Workflow | Run ID | Result | Evidence |
|---|---:|---|---|
| C324 updater exact-head security tests | `46057502835` | **Passed** | Job `140703460227`: formatting, updater Go tests, Windows AMD64 cross-compilation and `go vet ./internal/updateinfo` all succeeded |
| Full repository CI | `46057502779` | **Cancelled** | No completed Windows/Linux/macOS acceptance result |
| Desktop shell | `46057495685` | **Incomplete** | Linux Tauri job `140703472703` was running; Windows and macOS Tauri jobs were cancelled |

A duplicate updater run `46057502835` also passed; duplicate CI/Desktop attempts were cancelled. Cancellation is not a pass.

### Earlier failures and corrections

| Run ID | Workflow | Result | Finding |
|---:|---|---|---|
| `46048600689` | C324 updater security | Failed | Invalid multiline Go string |
| `46048600749` | Full CI | Failed | Windows builds failed from the same syntax defect; Linux failed a release-anchor check |
| `46056851724` | C324 updater security | Failed | Linux process-fixture finalizer assumed ProgramData |
| `46056972721` | C324 updater security | Failed | Process fixture expected a cleanup call suppressed by sequence-zero handling |
| `46057123217` | C324 updater security | Failed | Windows cross-compilation found missing `currentProcessElevated` and incorrect Ed25519 test-key ordering |

Corrections followed in commits including `9f9257fc55e6990dbb30e4da7490ddd371b9617e`, `f94f51c9419bc4df237ca9bc31225e221511fe7d`, `b1e61d1db12f5a9541d21e6cf356b571a516fe93`, and the subsequent recovery-script transaction commits. Historical failures are retained here for traceability.

## Outstanding blockers

1. Fresh full repository CI must complete successfully at one exact HEAD, including Windows agent/release, Linux and macOS jobs. The latest observed full CI was cancelled.
2. Fresh Windows, Linux and macOS Desktop CI must complete successfully at one exact HEAD. The latest observed Desktop run had Windows/macOS cancelled and Linux still running.
3. Run the PowerShell recovery adversarial suite on a Windows runner. It now contains transaction-script restoration and corrupted-backup cases, but no successful run of that suite has been evidenced in this report.
4. Add/verify process-authentication negatives for malformed/ambiguous token information, UAC cancellation, an elevated helper without the intended original caller, and staged-worker publisher mismatch. Current SID/LUID mismatch coverage is synthetic comparator testing, not an actual cross-user logon-session launch.
5. A persistent privileged Windows VM and named accountable Windows operator remain unprovided. Actual UAC, SCM replacement, reboot, power-loss/interruption, rollback and five-binary before/after digest acceptance remain blocked.
6. Production Ed25519 update-root pin, Authenticode publisher pin, external signing, and production release credentials remain unprovisioned. Do not invent these values.
7. Tauri updater integration remains absent; no updater action is exposed through the Tauri command handler.

## Next priorities

1. Obtain a fresh successful full repository CI and all three Desktop CI results at the same exact HEAD.
2. Run the Windows PowerShell recovery adversarial suite and Windows updater integration tests; publish run IDs and job results.
3. Finish UAC, token-information and staged-worker publisher mismatch negative tests.
4. Obtain the persistent privileged Windows VM and named operator; perform real service replacement, reboot, interruption and rollback acceptance.
5. Keep PR #209 open, draft and unmerged. Do not sign, publish or deploy production artifacts.

## Safety and release status

No PR merge, production signing, production publication, deployment, or production trust-anchor provisioning was performed. Hosted CI is not evidence of real privileged Windows acceptance.
