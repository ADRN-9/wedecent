# C359 — Windows SCM identity race and verification report

**Repository:** ADRN-9/wedecent  
**PR:** [#209](https://github.com/ADRN-9/wedecent/pull/209)  
**Branch:** `security/c324-verified-update-admission-recovery`  
**Code-under-test HEAD:** `2cc8be745dc88fe6f31afb568b480b6f6ce930c7`  
**Code-under-test tree:** `7cfa92fdc7076d0344929d4cf6f413143e2bffe0`  
**Verification/documentation HEAD:** `6ffc14a51166a85ae722d77263421212e436ee98`  
**Verification/documentation tree:** `33c2bc9859ad3dfd9d03955111c3817f799e838b`  
**Base:** `629456e4a2f594adad7433589aaa3591454503d5`  
**Prepared:** 2026-11-28 UTC

## Executive result

C359 found and corrected a false security assumption in C357: `LockServiceDatabase` is a compatibility no-op on Windows Vista and later, so it does not prevent external SCM configuration changes. The obsolete P/Invoke lock was removed from standalone updater recovery. Stop/start wrappers continue to re-read the authenticated service identity immediately before their SCM state mutation. Regression assertions were updated to reject any future reliance on the obsolete lock.

**The SCM check/use race is not fully closed.** Windows SCM does not expose an atomic conditional `ControlService`/`StartService` operation bound to an expected configuration snapshot. A concurrent process with local-administrator rights can still reconfigure service identity between the final query and the state mutation. Current design must treat local administrators as a trusted OS authority. A privileged broker/service-object ACL boundary and native adversarial race tests are still required before claiming resistance to concurrent privileged SCM writers.

The C359 code change, regression tests and exact-head hosted workflows passed. This is not production acceptance.

## Live repository and PR recovery

- PR #209: **open, draft, unmerged**.
- Current branch ref at report time: `6ffc14a51166a85ae722d77263421212e436ee98`.
- No force-push, merge, signing, deployment or activation was performed.
- All earlier C357 commits and history were preserved.

## Implementation

### Commits retained

| Commit | Change |
|---|---|
| `373daa22861f7bb6b08bc9b29250bafeb11a27d7` | Remove obsolete SCM database-lock implementation from standalone recovery and put fresh identity snapshots immediately before service stop/start wrappers |
| `4440a16f943052648daaa890fae7f56003c9ef69` | Remove stale lock parameters/references and correct fail-closed error wording |
| `2cc8be745dc88fe6f31afb568b480b6f6ce930c7` | Update regression assertions to reject SCM database-lock reliance and require fresh identity checks in stop/start wrappers |
| `6ffc14a51166a85ae722d77263421212e436ee98` | Correct the C357 report's incorrect SCM lock security claim |

The standalone recovery wrapper authenticates service account name/SID, executable path, state path and start mode immediately before its `Stop-Service`/`Start-Service` calls. Its protected machine-wide transaction lock continues to serialize WeDecent installer, migration and recovery entrypoints; it does not fence external SCM writers.

### SCM API finding

Microsoft's [LockServiceDatabase documentation](https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-lockservicedatabase) explicitly says that, as of Windows Vista, the function is provided for application compatibility and has no effect on the database. It is not a service configuration exclusion lock on supported modern Windows.

Microsoft's [service security and access-rights documentation](https://learn.microsoft.com/windows/win32/services/service-security-and-access-rights) describes service-specific rights such as `SERVICE_CHANGE_CONFIG`, `WRITE_DAC` and `WRITE_OWNER`. A secure next design must place SCM mutation behind a narrow privileged broker and restrict ordinary callers' service-object configuration rights. The local administrator remains a trusted OS authority; an administrator can take ownership/change service security and is not isolated by a user-mode mutex or a last-moment query.

### Race coverage still missing

C359 did **not** add a native adversarial test that concurrently reconfigures SCM from a second privileged administrator process between identity validation and the service-state mutation. It also did not establish an atomic compare-and-mutate guarantee for migration, upgrade, rollback and error-handling SCM operations. The current static/transaction regressions prove fresh identity revalidation and removal of the invalid lock assumption, not closure of the privileged external-writer race.

Do not treat this C359 partial remediation as production-ready. The next engineering batch must implement the broker boundary and exercise concurrent external reconfiguration, identity substitution, fail-closed behavior and zero-side-effect rejection on supported Windows versions.

## Exact-head GitHub Actions verification

The workflows below ran on verification/documentation HEAD `6ffc14a51166a85ae722d77263421212e436ee98`. The only difference from code-under-test HEAD `2cc8be745dc88fe6f31afb568b480b6f6ce930c7` is the C357 documentation erratum; no product/test code changed after the tested code HEAD.

| Workflow | Run ID | Job ID(s) | Conclusion |
|---|---:|---|---|
| C324 updater exact-head security | `46121069155` | `140905471273` updater-security | **success** |
| Full repository CI | `46121069210` | `140905506501` windows-agent; `140905506667` supabase-db; `140905506684` relay-worker; `140905506686` control-plane; `140905506698` macos-agent; `140905506782` windows-release; `140905506869` route-capability-client; `140905573584` route-e2e; `140905640741` linux | **9/9 success** |
| Desktop shell | `46121069142` | `140905549590` macos-tauri-check; `140905549783` linux-tauri-check; `140905549867` windows-tauri-check | **3/3 success** |

### Windows agent job

Windows-agent job `140905506501` completed successfully. The following relevant steps passed:

- Windows updater executor integration tests.
- Diagnostic Windows release bundle build.
- Windows installer/hardware script parsing.
- Windows upgrade user-process preflight.
- Installer recovery and backup-integrity tests.
- Service installer recovery credential-contract tests.
- Windows state migration transaction coordinator.
- Windows replay-store security regressions.
- Distinct Windows service-account provisioning and cleanup.
- Native Windows agent tests.
- Service-state ancestor ACL checks.
- Hostile ancestor-owner startup rejection.
- Distinct service SID state provisioning.
- Native Windows binary build and version/UI-autostart checks.

All nine repository CI jobs and all three desktop jobs concluded success.

### Windows process-isolation skip — NOT ESTABLISHED

The Windows-agent log still contains:

`WARNING: Cross-user/session process isolation probe skipped: hosted Windows runner lacks the process-token privileges required to create a child under the authenticated service identity. Run this test on the persistent privileged Windows VM.`

This is an internal test skip, not a passing isolation test. The job can be green while this specific acceptance remains **NOT ESTABLISHED**.

Microsoft's [CreateProcessWithTokenW documentation](https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) states that it requires `SeImpersonatePrivilege`; error 1314 should be handled with `CreateProcessAsUser` or `CreateProcessWithLogonW`. `CreateProcessAsUser` generally needs `SeIncreaseQuotaPrivilege` and may require `SeAssignPrimaryTokenPrivilege`; `CreateProcessWithLogonW` requires no special privileges but the target account must be allowed to log on interactively.

A C359 attempt to add a `CreateProcessWithLogonW` fallback was tested and reverted after the hosted Windows job failed: run `46120258169`, job `140903060681`, reported `CreateProcessWithTokenW=-2147024809`, `CreateProcessAsUserW=1314`, and `CreateProcessWithLogonW=-2147024809`. The failed fallback is not present in the current branch. The isolation probe remains skipped and requires a supported launcher and/or the persistent privileged VM.

## Persistent privileged Windows acceptance

The infrastructure gate remains open:

- ADRN-9 is the accountable organization.
- A named individual VM provisioning/operator is not designated in repository evidence.
- A persistent isolated Windows VM identity, disk/snapshot identity and access window are not evidenced.
- Actual service-token groups and SCM StartName/SID continuity are not captured on a persistent VM.
- Machine-scope DPAPI identity reopening under the actual service token remains unproven.
- Hard process termination at durable transaction boundaries, same-disk reboot, repeated recovery and real SCM rollback remain unproven.
- Hosted Windows Actions is ephemeral and does not satisfy this acceptance.

The runbook remains in `docs/WINDOWS_STATE_MIGRATION_VM_ACCEPTANCE.md`, with the dependency register in `docs/C332_PRIVILEGED_WINDOWS_INFRASTRUCTURE_ASSESSMENT.md` and `docs/windows-updater-privileged-acceptance.md`.

## Next recommended assignment: C360

Implement the authenticated privileged Windows installer/SCM broker:

1. Broker service runs under a dedicated trusted system identity and is the sole supported WeDecent SCM configuration authority.
2. IPC ACL and caller authentication bind each request to the authenticated installer/update transaction and protected metadata.
3. Service-object DACL removes `SERVICE_CHANGE_CONFIG`, `WRITE_DAC` and `WRITE_OWNER` from ordinary service callers; verify the effective descriptor before mutation. Treat local administrator as trusted OS authority.
4. Broker serializes installer, migration, recovery, rollback and error paths, revalidates service identity inside the privileged boundary and fails closed on mismatch.
5. Add native concurrent external SCM reconfiguration and identity-substitution tests. Prove rejected changes produce zero protected-file/journal/SCM side effects.
6. Replace the hosted process-isolation probe launcher with a tested supported mechanism. Do not convert error 1314 into a pass.
7. Execute persistent-VM service-token, DPAPI, hard-interruption, reboot and rollback acceptance with a named operator.

Keep PR #209 open, draft and unmerged until the privileged broker, adversarial tests and persistent-VM acceptance are independently reviewed.
