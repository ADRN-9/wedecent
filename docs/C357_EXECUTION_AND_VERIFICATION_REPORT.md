# C357 — implementation and verification report

**Repository:** ADRN-9/wedecent  
**Pull request:** [#209](https://github.com/ADRN-9/wedecent/pull/209)  
**Branch:** `security/c324-verified-update-admission-recovery`  
**Code-under-test HEAD:** `1b762076bbdfe47b65ebc09e01625917cf4049ac`  
**Code-under-test tree:** `5deca79c47605adff7f9ce8e50ad693150a3bbd3`  
**Base:** `629456e4a2f594adad7433589aaa3591454503d5`  
**Report prepared:** 2026-11-28 UTC

## Executive result

C357's repository implementation and hosted exact-head verification are complete at the code-under-test SHA above. The branch contains 31 commits after the supplied C356 baseline `4ad930dd88e0a35a1276bf0e96f3e7c030451a5f`; it is 31 commits ahead and zero behind that baseline. Existing commits were recovered and retained; no implementation was duplicated or overwritten in this task.

PR #209 was verified as **open, draft, and unmerged**. It must remain so. This report does not claim production readiness or privileged Windows acceptance.

## Implementation recovered

The 31-commit C357 delta includes the following substantive changes:

- Authenticate standalone recovery against protected installer metadata and the live SCM service identity: service name, dedicated local account name and resolved SID, executable path, state path, and supported start mode.
- Reject built-in service identities (LocalSystem, LocalService, NetworkService) for the dedicated service-account recovery path.
- Revalidate the complete live identity under an SCM database lock before stop/start operations. Hold that lock through rollback and service restart; preserve it through restart-failure stop recovery.
- Reject unexpected service starts during rollback rather than silently restarting into an unverified state.
- Add negative cases for missing, malformed, unresolved, or mismatched identities and for executable/state/start-mode mismatches. Verify rejected recovery produces zero protected-file, journal, and SCM side effects.
- Replace independently exported acquire/release lock functions with a module-owned scoped installer transaction action. Use the same exclusive machine-wide lock for installer, direct migration, and recovery entrypoints, including cross-process contention tests.
- Authenticate forward-migration metadata and the live SCM account/path before migration tree, ACL, metadata, or journal transaction mutations. Authenticate an existing nonterminal journal before another forward transaction can proceed.
- Preserve exact service start mode from the locked initial SCM snapshot instead of assuming Automatic; reject unsupported modes.
- Fix the duplicate PowerShell extended type-data load in the Windows lock-contention child harness.

### Duplicate ObjectSecurity failure

The baseline CI failure was in the installer-lock child-process test. Its child imported `StateMigration.psm1`, which caused duplicate `System.Security.AccessControl.ObjectSecurity` type-data members (including `AuditToString`, `AccessToString`, `Sddl`, `Access`, `Group`, `Owner`, and `Path`) to be loaded and made the child fail before acquiring the lock.

Commit [`917df1f4941f5745efac8b73c46ca76deb1adf3c`](https://github.com/ADRN-9/wedecent/commit/917df1f4941f5745efac8b73c46ca76deb1adf3c) removes that redundant module import from the child contention harness and has the child hold the same exclusive OS file handle directly. The production lock API remains covered by the module's scoped transaction tests and competing installer/direct-migration/recovery process tests. The test does not downgrade assertions to a best-effort or skip path.

## Exact-head GitHub Actions evidence

All three workflow runs below are associated with code-under-test HEAD `1b762076bbdfe47b65ebc09e01625917cf4049ac`.

| Workflow | Run ID | Job ID(s) | Conclusion |
|---|---:|---|---|
| C324 updater exact-head security tests | `46116277392` | `140890721221` updater-security | **success** |
| Repository CI | `46116277401` | `140890724932` relay-worker; `140890725087` windows-release; `140890725090` windows-agent; `140890725100` supabase-db; `140890725110` macos-agent; `140890725176` route-capability-client; `140890725205` control-plane; `140890816128` route-e2e; `140890882264` linux | **all 9 success** |
| Desktop shell | `46116277517` | `140890741958` windows-tauri-check; `140890741805` linux-tauri-check; `140890742126` macos-tauri-check | **all 3 success** |

### Windows agent job detail

Windows-agent job `140890725090` completed successfully. Its recorded steps all completed successfully, with no skipped steps:

1. Windows updater executor integration tests.
2. Diagnostic Windows release bundle build.
3. Installer and hardware-script parsing.
4. Upgrade user-process preflight verification.
5. Installer recovery and backup-integrity tests.
6. Service installer recovery credential-contract verification.
7. Windows state migration transaction coordinator.
8. Windows replay-store security regressions.
9. Dedicated Windows service-account provisioning for native state tests.
10. Native Windows agent tests.
11. Actual Windows service-state ancestor ACL checks.
12. Hostile ancestor-owner startup rejection.
13. Distinct service SID state provisioning.
14. Native Windows binary build and version/UI-autostart checks.

The job log records these positive results, among others:

- Forward migration rejects mismatched account SID, metadata/source mismatch, live SCM state-path mismatch, live SCM executable mismatch, and an existing nonterminal journal before transaction filesystem/ACL/journal/SCM mutation.
- Migration coordinator rollback passes at Prepared, ServiceStopped, Copying, Copied, IdentityVerification, IdentityProtected, Verified, DestinationPublished, StatePublished, SCMTransition, ServiceReconfigured, MetadataUpdated, and ServiceRestarted.
- Unsupported SCM states and SCM state races are rejected without mutation.
- Fresh-process synthetic recovery, source/ACL mutation rejection, native file-identity substitution rejection, deterministic namespace-race rejection, and protected metadata/journal ACL tests pass.
- Installer, direct migration, and recovery processes serialize on the machine-wide exclusive lock.
- Standalone recovery rejects missing/malformed/mismatched account SID, unresolved/mismatched live account, metadata account-name mismatch, executable/state-path mismatch, and start-mode mismatch without filesystem, metadata, journal, or SCM mutation.
- The migration coordinator integration test reports PASS.

The Windows updater security job records formatting, updater admission/recovery tests, Windows package compilation, and vet steps as successful.

## Evidence limits and outstanding risks

Hosted Windows Actions is ephemeral. The coordinator suite uses SCM test doubles for migration/recovery transaction scenarios; the log explicitly labels fresh-process destination-publication recovery as a synthetic crash-state with SCM mocked. Native Windows tests and temporary service-account provisioning are valuable hosted evidence, but do not prove the installed WeDecent service can reopen its machine-scope DPAPI identity under its actual service token across a real interruption and reboot.

The persistent privileged Windows acceptance gate remains **NOT ESTABLISHED**:

- ADRN-9 is the accountable repository/infrastructure organization.
- No named individual VM provisioning/operator is designated in repository evidence.
- No persistent isolated Windows VM identity, persistent disk/snapshot identity, access window, or operator evidence is recorded.
- Actual service-token group evidence and DPAPI identity reopening under the real service account across migration, interruption, restart, and same-disk reboot remain outstanding.
- Hard process termination at durable journal/side-effect boundaries, reboot on the same persistent disk, repeated recovery, exact five-binary/metadata hash checks, and real SCM rollback evidence remain outstanding.
- Hosted CI does not satisfy this gate. A skipped privilege check or Windows error 1314 must be recorded as NOT ESTABLISHED, never as acceptance.

The separate production release gates also remain: production trust-anchor provisioning and external signing, and any required production infrastructure/provider inputs. No production signing, release publication, deployment, PR merge, or activation was performed.

## Next recommended assignment: C358

Provision and identify the isolated persistent Windows 11 or supported Windows Server acceptance VM, designate a named accountable operator, and execute the documented privileged acceptance procedure at an immutable candidate SHA. Capture actual service-token groups, SCM StartName/SID/path/start mode/state, machine-scope DPAPI identity continuity (public device ID/fingerprint/certificate digest and protected-key digest only), hard process interruption at durable boundaries, same-disk reboot, rollback/retry, and before/after five-binary plus metadata hashes. Preserve redacted transcripts and evidence hashes. Keep PR #209 open and draft until that acceptance is independently reviewed.

## Repository state

At report preparation time PR #209 was open, draft, and unmerged. The tested branch HEAD and tree are recorded above. This report is documentation of the observed implementation and hosted evidence, not a declaration that the remaining privileged or production gates have passed.


## C359 erratum — SCM database lock limitation (2026-11-28)

The earlier statement that holding `LockServiceDatabase` prevented service reconfiguration between identity admission and SCM mutation was incorrect for supported modern Windows. Microsoft documents that, as of Windows Vista, this function is retained for application compatibility and has no effect on the SCM database. It does not serialize `ChangeServiceConfig`, `ControlService`, or `StartService` against concurrent writers. See [Microsoft LockServiceDatabase documentation](https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-lockservicedatabase).

C359 removed the obsolete SCM database-lock P/Invoke and wrapper from `Recover-WeDecentInstall.ps1`. The standalone recovery stop/start wrappers now re-read and authenticate service account name/SID, executable path, state path and start mode immediately before each SCM state mutation. The existing protected machine-wide transaction lock serializes WeDecent installer/migration/recovery entrypoints only; it does not fence external SCM writers.

**Security limitation:** Windows SCM does not expose an atomic conditional stop/start API bound to an expected service configuration snapshot. A concurrent process with local-administrator rights can still change service configuration in the interval after the final query and before the SCM mutation. Local administrators must therefore remain a trusted OS authority in the current design. A complete mitigation for concurrent privileged writers requires a privileged broker/installer service with a narrowly authenticated IPC boundary and a service-object DACL that removes configuration authority from ordinary callers, plus native adversarial race tests. Do not claim this race is closed until that architecture and tests are implemented. The C357 exact-head CI results remain valid as tests of the then-tested source, but they do not validate the false lock guarantee.

The C359 implementation and exact-head verification status are recorded in `docs/C359_SCM_IDENTITY_RACE_REPORT.md`.
