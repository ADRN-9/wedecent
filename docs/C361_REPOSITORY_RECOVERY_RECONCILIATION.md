# C361 — PR #209 repository recovery and reconciliation

**Recovery date:** 2026-11-28  
**Repository:** ADRN-9/wedecent  
**PR:** #209 — C324: require verified update capabilities and recover interrupted installs  
**Branch:** `security/c324-verified-update-admission-recovery`  
**Recovered code HEAD:** `cfd6a7c187633923c6ace86fde31892c98de3e47`  
**Recovered tree:** `db854ef5e3a7a663baa410789ac95ffac9b188b8`  
**Immediate parent:** `dcabc64d3c03bac7bc9977c2ead0ef2fcfb3b42a`  
**PR base:** `629456e4a2f594adad7433589aaa3591454503d5`  
**Live PR state:** OPEN, DRAFT, UNMERGED.

## 1. Repository and PR identity

The branch ref and PR #209 head independently resolve to the same commit `cfd6a7c187633923c6ace86fde31892c98de3e47`. The current commit object reports tree `db854ef5e3a7a663baa410789ac95ffac9b188b8` and immediate parent `dcabc64d3c03bac7bc9977c2ead0ef2fcfb3b42a`.

The PR is open, draft, unmerged, and reported mergeable by GitHub. No branch update, merge, force-push, signing, deployment or production activation was performed during C361 recovery.

## 2. Reconciliation of previously reported commit identities

Both identities supplied to C361 exist in the current branch ancestry and were fetched directly from GitHub:

| Commit | Tree | Parent | Meaning |
|---|---|---|---|
| `2cc8be745dc88fe6f31afb568b480b6f6ce930c7` | `7cfa92fdc7076d0344929d4cf6f413143e2bffe0` | `4440a16f943052648daaa890fae7f56003c9ef69` | C359 corrected recovery behavior and removed obsolete SCM database-lock reliance |
| `6ffc14a51166a85ae722d77263421212e436ee98` | `33c2bc9859ad3dfd9d03955111c3817f799e838b` | `2cc8be745dc88fe6f31afb568b480b6f6ce930c7` | Documentation-only correction to C357 lock claim |
| `439d725e979af0c61fa44aab97f60eed3c0d46e3` | `ea08456b15a1a4a22fa1c3e24b0b2e2d8e254067` | `6ffc14a51166a85ae722d77263421212e436ee98` | C359 SCM identity-race report |

GitHub compare results:

- `2cc8be7...439d725`: ahead by 2, behind by 0. Changes: C357 report correction (+11 lines) and new C359 report (+122 lines).
- `439d725...cfd6a7c`: ahead by 12, behind by 0. The exact 12 commits and seven-file C360 delta are listed below.

There is no conflict, replacement, rebase, force-push, or abandoned parallel branch in this relevant ancestry.

## 3. Complete relevant ancestry after C359 baseline

The linear history from the C359 code baseline to current recovered HEAD is:

1. `2cc8be745dc88fe6f31afb568b480b6f6ce930c7` — test recovery revalidates without obsolete SCM lock.
2. `6ffc14a51166a85ae722d77263421212e436ee98` — correct C357 SCM database lock security claim.
3. `439d725e979af0c61fa44aab97f60eed3c0d46e3` — publish C359 SCM identity race report.
4. `0788226523170830dca2393c8d02c00582c2fd5e` — restrict service object ACL and SCM handle rights.
5. `45fcca2e4cd0bdc63eca37f09dcbbc292008eaee` — expose elevated service ACL hardening command.
6. `3e15dd7aed80f87618c5fa593fd8318f2a712548` — assert least-privilege service DACL.
7. `7fa1c3656393b69c09c61f9078fbf70e42d57655` — harden existing service DACL before upgrade.
8. `79fe2b3f628f3d6dd354107110a78b11d2cfcaa5` — document service security command.
9. `fddddc15235498c89650aa885955e9699552e99f` — require SCM DACL hardening before upgrades.
10. `aafe5348b4b534a21f4634110d6e2370f9aa0119` — publish C360 broker threat model and status.
11. `9f55ce77ebeb3422235e03e5a602a3ae49e83dfb` — extend Windows VM acceptance for DACL and broker.
12. `51ab97ed368f0af5a2e7c0ae8b043e6e351ac7e6` — validate service DACL descriptor parsing.
13. `493cc7628fb8045279fe60ee8ca7dba55828193d` — align SCM access constants.
14. `dcabc64d3c03bac7bc9977c2ead0ef2fcfb3b42a` — use SE_SERVICE object type for SCM DACL.
15. `cfd6a7c187633923c6ace86fde31892c98de3e47` — assert SCM security object type.

Every commit above is an ancestor of recovered HEAD. The final C360 commit's immediate parent is `dcabc64...`.

## 4. C360 file delta

GitHub compare reports exactly seven files changed after C359 report commit `439d725...`:

| File | Status | Additions | Deletions |
|---|---|---:|---:|
| `cmd/wd-agent/service_windows.go` | modified | 11 | 0 |
| `docs/C360_WINDOWS_SCM_BROKER_DESIGN_AND_STATUS.md` | added | 158 | 0 |
| `docs/WINDOWS_STATE_MIGRATION_VM_ACCEPTANCE.md` | modified | 33 | 0 |
| `installer/windows/Install-WeDecent.ps1` | modified | 9 | 0 |
| `internal/winservice/service_windows.go` | modified | 68 | 13 |
| `internal/winservice/service_windows_test.go` | modified | 35 | 1 |
| `scripts/test-windows-service-installer-contract.ps1` | modified | 2 | 0 |

The PR currently has 56 cumulative changed files. The broader C324/C335/C339/C342/C357 work remains in the PR and was not altered by C361.

## 5. Recovered C360 implementation and security status

C360 implemented containment, not a privileged broker:

- SCM handles use narrower access masks for create, query, start, stop and delete.
- New service creation applies a protected service-object DACL and deletes the newly created service if DACL application fails.
- An elevated `wd-agent service secure` command applies the same DACL to an existing service.
- Existing-service upgrade calls that command after metadata/live service-account SID validation and ShouldProcess approval, before migration/upgrade mutations. Failure aborts.
- The DACL is `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000004;;;AU)`: SYSTEM and local Administrators full control, Authenticated Users query-status only.
- The SCM security-object type was corrected to `SE_SERVICE == 2`; regression tests assert that value, exact SDDL, parseability and access masks.
- The Windows service installer contract statically requires the hardening command and fail-closed error handling.

### Existing privileged broker implementation: NOT FOUND

The current recursive repository tree contains no dedicated Windows service-management broker implementation, no broker service entry point, and no broker IPC protocol. The broker candidates inspected are not equivalent substitutes:

- `internal/coreapi/localipc/localipc_windows.go` implements the current user's Local Core named pipe. Its DACL grants generic access to the current user SID only. It does not implement an elevated installer-to-privileged-broker authority boundary, caller-token impersonation, or service mutation authorization.
- `internal/relay/broker.go` is an in-memory relay connection-slot broker. It is unrelated to Windows SCM management.
- `cmd/wd-agent/service_windows.go` exposes service install/start/stop/status/uninstall and the new `secure` command; it does not run a separate privileged SCM broker.

The existing-service DACL command is not an authenticated broker. It is an elevated executable invocation.

### Direct SCM mutations remain

Source inspection at recovered HEAD found direct elevated SCM operations in:

- `installer/windows/Install-WeDecent.ps1`: Stop-Service / Start-Service and `sc.exe delete`, including rollback/error paths.
- `installer/windows/Recover-WeDecentInstall.ps1`: Stop-Service / Start-Service.
- `installer/windows/StateMigration.psm1`: `sc.exe config`, Stop-Service / Start-Service for migration and rollback.
- `installer/windows/Uninstall-WeDecent.ps1`: Stop-Service and `sc.exe delete`.

Thus the C360 DACL hardening is not a single non-bypassable mutation boundary. Direct elevated installer/recovery operations remain. No atomic SCM compare-and-mutate protection against concurrent local Administrators/SYSTEM is claimed.

## 6. Historical versus current hosted workflow evidence

### C359 historical evidence

The C359 PR report states code baseline `2cc8be7...` and reports successful workflow runs on the subsequent documentation-only HEAD `6ffc14a...`. GitHub run metadata independently confirms that all three historical runs used `6ffc14a51166a85ae722d77263421212e436ee98`, not `2cc8be7...`:

| Workflow | Run ID | Run HEAD | Conclusion |
|---|---:|---|---|
| CI | `46121069210` | `6ffc14a...` | success |
| Desktop shell | `46121069142` | `6ffc14a...` | success |
| Updater security | `46121069155` | `6ffc14a...` | success |

C359 PR discussion records that the hosted Windows isolation probe skipped for missing process-token privileges. This remains NOT ESTABLISHED.

### C360 exact recovered code HEAD evidence

The following runs were executed at the exact recovered code HEAD `cfd6a7c187633923c6ace86fde31892c98de3e47`:

| Workflow | Run ID | Job outcomes | Conclusion |
|---|---:|---|---|
| CI | `46122726069` | 9/9 jobs success | success |
| Desktop shell | `46122726075` | Windows, Linux, macOS all success | success |
| Updater security | `46122726092` | updater-security success | success |

The C360 Windows agent job `140910563792` completed successfully. Its log nevertheless contains the explicit warning:

`Cross-user/session process isolation probe skipped: hosted Windows runner lacks the process-token privileges required to create a child under the authenticated service identity. Run this test on the persistent privileged Windows VM.`

The overall workflow success does not convert that skip into a pass. Windows error 1314 / cross-user process isolation remains NOT ESTABLISHED.

No C361 code changes or new workflows were performed against this recovered code HEAD. These are historical verified C360 runs, not fresh C361 runs.

## 7. Exact outstanding security and infrastructure blockers

1. No dedicated privileged SCM broker service.
2. No dedicated authenticated named pipe with a narrow broker-specific DACL and remote-client rejection.
3. No server-side named-pipe client impersonation and validation of actual caller SID, groups, elevation, integrity, session and process identity.
4. No handle-based executable identity/signature validation to prevent process-path substitution and replacement races.
5. No fixed operation allowlist, service identity binding, capability validation or protected broker-owned metadata verification.
6. No challenge, one-use request identifier, expiry, replay store or restart invalidation.
7. No strict bounded IPC decoder rejecting malformed, duplicate, unknown or trailing fields and path/device/reparse substitutions.
8. No durable broker audit/transaction journal and crash-recovery state machine.
9. No routing of install, service creation/configuration, migration, recovery, upgrade, rollback, stop/start, uninstall and cleanup SCM writes through one broker.
10. No adversarial native IPC/SCM tests proving zero side effects for unauthorized caller, identity substitution, replay, malformed IPC or concurrent SCM reconfiguration.
11. Windows 1314 cross-user/session probe is skipped on hosted CI and remains NOT ESTABLISHED.
12. No named persistent Windows VM operator, persistent VM/disk/snapshot identifiers or completed privileged acceptance evidence.
13. Actual dedicated service-token DPAPI identity continuity, hard interruption, same-disk reboot, repeated recovery and real SCM rollback are NOT ESTABLISHED.

Local Administrators and SYSTEM remain trusted OS authority. A broker can prevent ordinary callers and the dedicated agent account from acquiring unauthorized mutation rights, but it cannot make a fully privileged local administrator or SYSTEM process untrusted and unable to alter the host.

## 8. Recommended C362 implementation sequence

1. **Freeze the threat model and authority split.** Define the distinct broker service identity, installer client identity, agent service identity, fixed service name, permitted operation enum and protected metadata authority. Keep Local Core IPC separate.
2. **Implement the broker as a separate Windows service.** Use a dedicated local named pipe with explicit DACL, reject remote clients, obtain the actual pipe-client token by impersonation, validate token/session/elevation/process identity, and revert impersonation safely on every path.
3. **Implement bounded authenticated request protocol.** Fixed schema/version and operation allowlist; server-generated random challenge, one-use transaction ID, short expiry, durable replay state; reject malformed/oversized/duplicate/unknown/trailing data.
4. **Bind authority to actual service identity.** Broker independently reads ACL-protected metadata and validates service name, resolved account SID, executable path/file identity/signature, state directory owner/DACL, start mode and package/update capability. Do not accept caller-provided identity claims as authority.
5. **Centralize and serialize every SCM mutation.** Expose typed broker operations for create/configure/provision DACL, stop/start/delete, migration, recovery, upgrade, rollback and uninstall. Remove direct PowerShell SCM mutation after each path is migrated. A named mutex alone is not an OS access boundary; retain service-object DACLs and document trusted-admin limitations.
6. **Add adversarial native tests before integration.** Unauthorized standard user and agent tokens, spoofed identity, wrong process/signature, remote pipe, malformed/oversized messages, replay/expiry/restart, path/reparse substitution, account SID mismatch, concurrent ordinary-user mutation, broker crash and journal recovery. Compare pre/post SCM configuration/state/DACL and protected filesystem/journal snapshots to prove zero side effects.
7. **Integrate in stages.** Start with installer/service create and stop/start; then migration/recovery; then rollback/uninstall. Make every transitional fallback fail closed, never silently call direct SCM from PowerShell if broker is unavailable.
8. **Run exact-candidate CI and privileged Windows VM acceptance.** Preserve the 1314 skip classification until genuinely executed under a named operator's persistent privileged VM. Verify service-token DPAPI continuity, process interruption, reboot, rollback and successful authorized terminal operation.

## 9. C361 execution disposition

- [x] Live GitHub access established.
- [x] PR #209 and branch ref independently inspected.
- [x] Current HEAD, tree, immediate parent and base verified.
- [x] Both previously reported SHAs reconciled in live ancestry.
- [x] Complete 14-commit ancestry from C359 baseline to C360 HEAD enumerated.
- [x] C360 seven-file delta and PR cumulative 56-file inventory recovered.
- [x] PR comments and C359/C360 reports recovered.
- [x] Historical C359 workflow runs distinguished from exact C360 code-HEAD workflow runs.
- [x] C360 exact-HEAD workflow results and explicit 1314 skip reconciled.
- [x] Existing broker candidates inspected and found unrelated/inadequate.
- [x] Direct SCM mutation paths identified in installer, recovery, migration and uninstall.
- [ ] Privileged SCM broker implementation.
- [ ] Persistent privileged Windows VM acceptance.
- [ ] Windows 1314 probe genuinely executed.
- [ ] Production readiness.

**C361 is a bounded recovery/reconciliation task. No new broker implementation was started.** PR #209 remains open, draft and unmerged. No force-push, merge, signing, deployment or activation was performed.
