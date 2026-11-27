# C342 — Repository reconciliation and recovery remediation

**Project:** WeDecent  
**Task:** C342 — `0484071334264760888512790ee55502`  
**Repository:** `ADRN-9/wedecent`  
**PR:** [#209](https://github.com/ADRN-9/wedecent/pull/209)  
**Branch:** `security/c324-verified-update-admission-recovery`  
**Report date:** 2026-11-27

## Executive result

C342 reconciled the live branch, repaired the Windows installer recovery transaction, fixed the Windows PowerShell Authenticode verifier, corrected a Linux cross-process replay-lock initialization race, and fixed historical transaction admission so a completed rollback cannot be replayed over a later installation.

The code checkout `68a8c37956146528cc2548de2191da5ab9d53600` passed the complete repository CI workflow and the dedicated updater-security workflow. Linux and macOS Desktop checks passed. The Windows Desktop Tauri shell job was still running at report publication; its status is explicitly pending below.

**This is repository/automated-verification progress, not production acceptance.** No persistent privileged Windows VM or named accountable VM operator was available, so full privileged install/upgrade/reboot/power-loss acceptance is still outstanding. No production signing, publication, deployment or merge was performed.

## 1. Live repository reconciliation

| Item | Verified value |
|---|---|
| Current source HEAD | `68a8c37956146528cc2548de2191da5ab9d53600` |
| Current tree SHA | `67baac2349a63a1173e139a068a82b04f7cf83dc` |
| Parent | `897f81e0fb0a4330be32330e4550b80acc1851c7` |
| C341 report commit / comparison base | `0eae549edb6d05c64c616e7ef2c72aeef7cdcb55` |
| Merge base | `0eae549edb6d05c64c616e7ef2c72aeef7cdcb55` |
| Commits since C341 | 44 ahead, 0 behind |
| PR base | `security/c298-transport-override-fail-closed` |
| PR state | Open; draft; unmerged |
| PR commit count | 387 |

GitHub compare confirms C341 remains an ancestor of the current branch. No commit was rewritten or removed.

### Changed paths since C341

| Path | Additions | Deletions |
|---|---:|---:|
| `cmd/wd-agent/update_windows.go` | 9 | 9 |
| `cmd/wd-ui/bootstrap_windows.go` | 6 | 6 |
| `installer/windows/Install-WeDecent.ps1` | 187 | 4,851 |
| `internal/portforward/replay_lock_unix.go` | 3 | 5 |
| `internal/updateinfo/application_test.go` | 11 | 0 |
| `internal/updateinfo/windows_runtime.go` | 21 | 6 |
| `scripts/test-windows-install-recovery.ps1` | 235 | 3 |

### Complete commit list since C341

The following 44 commits are the complete GitHub compare range from C341 report commit `0eae549edb6d05c64c616e7ef2c72aeef7cdcb55` to source HEAD `68a8c37956146528cc2548de2191da5ab9d53600`:

| Commit | Subject |
|---|---|
| `68a8c3795614` | test(installer): align legacy journal assertion with rollback compatibility |
| `897f81e0fb0a` | test(installer): locate historical rollback guard independent of indentation |
| `78d2f6ab2290` | fix(installer): make historical recovery state validation explicit |
| `887b1787b547` | test(installer): cover historical rollback and superseded journal admission |
| `97557497bc07` | fix(installer): retain metadata commit-phase consistency check |
| `8b9c69275f01` | fix(installer): validate metadata snapshots without replaying historical state |
| `dc3b3102a5ab` | fix(installer): treat completed rollback and superseded journals as historical |
| `ca484303d71b` | fix(replay): tolerate reordered lock alias visibility during initialization |
| `29b713cf50c0` | fix(installer): persist restored prior recovery script state |
| `3ae4b6c07ec9` | test(installer): hash the restore fixture transaction backup |
| `380f40aa678e` | test(installer): use transaction-bound backup in restore fixture |
| `b5b036e50b1e` | test(installer): verify recovery script restoration and fresh rollback journal |
| `1fcee6f33e39` | fix(installer): reset new-install recovery journal after rollback |
| `214b0cc554bf` | fix(installer): re-protect restored recovery script before rollback completes |
| `13efc8f1540d` | test(installer): make recovery fixture paths unambiguous |
| `e7bc73b877a5` | fix(update): load Windows PowerShell security module from trusted system path |
| `24f4abf43d28` | test(installer): reject ACL-untrusted recovery scripts and backups |
| `6bdc38127340` | fix(installer): verify recovery script ACLs across publish and rollback |
| `8a17a3f0595e` | test(installer): bind fresh recovery fixture backup to transaction ID |
| `ff23c1e68d44` | test(installer): exercise recovery script admission states |
| `ba5e552c5d8f` | test(installer): remove duplicate fresh-install static assertions |
| `12125066a7c1` | test(installer): assert explicit fresh-install recovery state |
| `e890e4e70475` | fix(installer): initialize recovery script state explicitly |
| `0cb42349bbba` | test(installer): cover fresh-install recovery script lifecycle |
| `9ca9c175c15f` | fix(update): explicitly load PowerShell Authenticode security module |
| `11cab2887bf8` | test(installer): cover fresh-install recovery script lifecycle |
| `56d4781152ee` | fix(installer): support first install recovery script transactions |
| `c8ec5a77e9ac` | test(update): capture Windows publisher verification diagnostics |
| `fc6de3982473` | test(installer): distinguish active and superseded committed journals |
| `8cf5a5777e3e` | fix(installer): distinguish current committed journal from superseded history |
| `c8fa230dac41` | test(update): expose Windows publisher verification failure reason |
| `97f890cf0fdd` | test(installer): cover legacy transaction compatibility guard |
| `a936f61c548a` | fix(installer): preserve compatibility with legacy committed journals |
| `6a19e632da0d` | test(installer): reject duplicate installer function definitions |
| `0d3e894484b2` | fix(update): verify catalog-signed Windows system binaries |
| `3d3664a93738` | test(installer): assert recovery script admission and cleanup integrity |
| `45a40b3181ed` | fix(installer): authenticate recovery script and preserve transaction backup |
| `5b6a7cb1416a` | fix(installer): remove duplicated recovery implementation |
| `efc0875b5742` | test(installer): require recovery script rollback before service restart |
| `5a16c41590eb` | fix(installer): restore single transaction recovery implementation |
| `dec2c1cb0052` | fix(update): allow trusted revocation retrieval for PowerShell verification |
| `4ea515721c5c` | test(update): isolate executor process fixture from Windows trust admission |
| `68cb61b6ddaf` | style(desktop): format Windows process declarations |
| `8c1b1f621b26` | style(update): format Windows token statistics |

## 2. Security-oriented installer review

### Duplicate implementation finding

At the C341 reference HEAD `e057164c86c284015900ab74e07433e70eb0db4e`, `installer/windows/Install-WeDecent.ps1` was 6,682 lines with 112 function definitions but only 48 unique function names. Fourteen function names had duplicate definitions, including transaction recovery, binary rollback, committed-backup cleanup, and recovery-script publication/restoration functions.

The current file is 2,018 lines with 48 function definitions and 48 unique names. The 4,851-line deletion is removal of duplicated implementation, not removal of the transaction recovery design. The clean single-transaction implementation was restored and the required recovery protections were reapplied and extended. A static test now rejects duplicate top-level function definitions.

### Transaction and recovery invariants reviewed and implemented

- Recovery-script target path and transaction-specific backup path are bound to the journal transaction ID.
- The previous recovery script is snapshotted before replacement, hashed, and protected with the trusted metadata ACL.
- The journal records whether a prior recovery script existed and distinguishes `original`, `absent`, `publishing`, and `published` states.
- Recovery-script admission validates complete journal fields, exact paths, regular-file/non-reparse status, ACL trust and SHA-256 identity.
- Committed cleanup requires a durable committed transaction and verifies the installed recovery script and any retained backup before deleting snapshots.
- Rollback restores the prior script, reapplies the trusted ACL, verifies the restored bytes, and persists `recovery_script_state = original`.
- A fresh installation with no prior script publishes the recovery script transactionally. On failure, rollback removes only the script published by that transaction and persists `recovery_script_state = absent`.
- The commit marker and committed-backup cleanup are outside the rollback catch boundary; cleanup failure is not misrepresented as an uncommitted installation.
- Service restart remains gated on successful binary, recovery-script, metadata and journal restoration.
- Legacy committed and rolled-back journals with no recovery-script fields remain compatible; incomplete legacy transactions fail closed.
- Historical committed/superseded and rolled-back journals are validated without comparing their old script/metadata hashes to a later installation. Completed rolled-back journals are skipped before service-stop and binary-restoration operations, preventing an old rollback from overwriting newer installed binaries.

### Remaining installer considerations

- Superseded committed transactions with retained binary backups still fail closed rather than silently discarding those backups.
- Hosted Windows recovery tests exercise transaction helpers and service-state tests, but do not replace a persistent VM's full installer, reboot and power-loss acceptance.
- Production update-root provisioning and WeDecent publisher signing remain separate release prerequisites.

## 3. Windows updater and Authenticode remediation

The Windows PowerShell publisher verifier initially failed because Windows PowerShell inherited a PowerShell 7 module path and attempted to load the wrong `Microsoft.PowerShell.Security` module.

The verifier now explicitly imports the Windows PowerShell security module from the protected system path under `$PSHOME`. It retains the exact Microsoft Windows publisher identity check and optional thumbprint check. Catalog-signed system binaries are accepted only through the explicit catalog-signature fallback when WinVerifyTrust reports `TRUST_E_NOSIGNATURE`; other invalid-signature outcomes remain failures. Failure output now includes the PowerShell verifier's diagnostic output.

The Windows updater executor integration tests pass at the current checkout. No publisher verification requirement was removed.

The two Go formatting failures in `cmd/wd-agent/update_windows.go` and `cmd/wd-ui/bootstrap_windows.go` were corrected.

## 4. Linux replay-lock race remediation

A full-CI failure exposed a race in Unix replay-lock initialization: a concurrent process could observe the initialization marker before the lock hard-link became visible and immediately fail with “persistent replay lock path is missing while its marker remains.” The failed worker then did not record its replay entry.

The Unix initializer now waits for both lock and marker aliases within the existing bounded retry window. It does not recreate an alias for an initialized store and still fails closed if the aliases remain incomplete. The existing multi-process stress test passed after the change.

## 5. Verification evidence

All workflow results below are tied to the exact source checkout `68a8c37956146528cc2548de2191da5ab9d53600`.

| Workflow | Run ID | Job IDs / results |
|---|---:|---|
| Full repository CI | `46066222157` | **All 9 jobs passed** |
| Updater security | `46066222172` | Job `140732063117`: **passed** |
| Desktop shell | `46066222280` | Linux job `140732179135`: **passed**; macOS job `140732179491`: **passed**; Windows job `140732179392`: **in progress at report publication** |

Full CI jobs that passed:
- `windows-agent` — `140732176033`
- `relay-worker` — `140732176123`
- `windows-release` — `140732176172`
- `macos-agent` — `140732176192`
- `supabase-db` — `140732176212`
- `route-capability-client` — `140732176219`
- `control-plane` — `140732176402`
- `route-e2e` — `140732283062`
- `linux` — `140732376411`

Windows CI additionally passed:
- updater executor integration tests;
- Windows installer and hardware-script parsing;
- installer recovery and backup integrity tests, including original-script restore and fresh-install rollback journal reset;
- historical committed/rolled-back transaction admission tests;
- state migration transaction coordinator;
- Windows replay-store security regressions;
- native Windows agent tests;
- service-state ancestor ACL and hostile-owner rejection checks;
- distinct service SID state provisioning and cleanup;
- native Windows binary build and version/UI command checks.

Linux CI additionally passed:
- Go formatting;
- replay initialization/crash-recovery stress;
- port-forward session/transport tests and race tests;
- all Go package tests and vet;
- protocol compatibility and decoder fuzzing;
- race detector;
- direct transport smoke, interrupted child cleanup and outbound-only relay smoke tests;
- production release workflow syntax, privilege-separation and output-containment checks.

**These are hosted CI results.** The direct transport smoke test is software validation, not real-hardware validation.

## 6. Outstanding blockers and acceptance boundary

1. **Persistent privileged Windows VM and named operator:** not available in the verified project evidence.
2. **Actual privileged installer acceptance:** clean install, upgrade, service replacement, reboot, power-loss interruption and rollback have not been demonstrated on a persistent VM.
3. **Production trust and signing:** production update trust-anchor provisioning and external signing credentials remain unprovisioned in the available evidence. The Windows system PowerShell publisher check does not establish WeDecent's production publisher signing.
4. **Physical/offline transport acceptance:** no new real-hardware evidence was produced here for Linux/Windows Bluetooth RFCOMM, USB CDC-ACM, Linux USB gadget CDC-ACM or USB NCM/direct-TCP.
5. **Production activation:** no production signing, publication, deployment or activation was performed.

## 7. Task disposition and recommended C343

**C342 implementation and full repository CI: passed.** Updater-security passed. Linux and macOS Desktop checks passed. Windows Desktop Tauri shell remained in progress at report publication, so three-platform Desktop acceptance is not yet claimed complete.

Recommended C343:
1. Obtain a persistent privileged Windows VM and name the accountable operator.
2. Run the actual packaged installer clean-install, upgrade, service replacement, restart/reboot, interrupted transaction and rollback scenarios on that VM; retain logs and exact artifact digests.
3. Finish Windows Desktop shell validation at the exact source checkout and record the result.
4. Continue production update trust-anchor provisioning and external signing preparation through the required human-controlled credential path.
5. Keep PR #209 open, draft and unmerged until those remaining acceptance gates are evidenced.

No source history was rewritten. PR #209 remains open, draft and unmerged. No production artifact was signed, published or deployed.
