# C332 — Privileged Windows infrastructure assessment

**Repository:** ADRN-9/wedecent  
**PR:** #209  
**Reference candidate:** `ecb2f885cbdde3f534ce3f150dd2a5208842c721`  
**Assessment date:** 2026-11-27  
**Disposition:** Infrastructure acceptance is NOT ESTABLISHED. This document records repository evidence and a reproducible acceptance gate; it does not claim a VM exists, is accessible, or has passed testing.

## Executive finding

The repository defines a detailed persistent-VM acceptance procedure, but repository-visible evidence does not establish provisioning or accessibility of a suitable machine. The C324 privileged Windows update path is also not yet demonstrated as a shipped privileged service integration. Hosted Actions and mocked PowerShell/Go tests are useful regression evidence only.

## Ownership and environment status

- **Accountable repository/infrastructure organization:** ADRN-9 is identified as the accountable owner in `docs/windows-updater-privileged-acceptance.md`.
- **Named individual provisioning operator:** not designated in the inspected repository records.
- **Persistent VM identity / provisioned state / operator access:** unknown and not evidenced. Do not infer that no external VM exists; repository records and available GitHub reads cannot establish external inventory or access.
- **Required decision:** an ADRN-9 organization/repository administrator must name a human owner, confirm whether a suitable VM is provisioned and accessible, and supply its non-secret identifier and acceptance window. If unavailable, record an explicit provisioning decision, reason, owner and target date.
- **Signing runner is not the acceptance VM.** The release workflow references self-hosted labels `wedecent-signing`, `wedecent-release-publisher`, `wedecent-update-signer`, and `wedecent-update-verifier`. Labels prove workflow dependencies, not current runner availability or suitability. Never use signing/publishing infrastructure for destructive interruption/reboot testing.

## Required isolated Windows environment

Provision a persistent Windows 11 or supported Windows Server VM, isolated from production/customer state and release-signing/publishing systems, with:

1. A stable VM and persistent local NTFS disk; record VM, disk, Windows edition/build and boot identity.
2. A clean snapshot plus a post-baseline snapshot; operator ability to restore snapshots and reboot the same persistent disk.
3. Separate elevated administrator operator account and dedicated local **non-administrator** WeDecent service account with stable SID. Service account receives only required service logon and filesystem rights; record effective token groups and SCM `StartName`. Do not run the service as the operator or claim a virtual `NT SERVICE\<name>` SID where the installer configures a local account.
4. Actual Service Control Manager access, filesystem owner/DACL inspection, Event Log access, and independent VM-side process termination (hypervisor supervisor/debugger/second console) at controlled transaction boundaries.
5. Ability to install an isolated **test-signed** build and provision test-only update trust material, recovery authority and short-lived test credentials through an approved secret store. No production trust anchors, production signing keys, customer data or release credentials.
6. Persistent redacted evidence storage for transcripts, event logs, journal snapshots, hashes, snapshot IDs and test results. Never archive passwords, bearer tokens, private keys or DPAPI blobs.

The NTFS install/state/staging paths must remain on the expected local volume and within the installer-approved protected root. Migration documentation currently requires a new destination beneath the configured install root and same-parent atomic rename; arbitrary volumes and UNC paths are not acceptable substitutes.

## Accounts and identity evidence

- Operator: elevated, interactive, individually attributable; used only to install, inspect SCM/filesystem and control test interruptions.
- Service: dedicated local standard account, stable SID, not a member of Administrators; record SID, start mode, SCM image path, service state, token groups and exact ACL/owner.
- Test authority: separate short-lived test recovery/update credentials and test trust keyset; provision via approved secret store/secure input.
- Device identity: let the real installed service create/use its machine-scope DPAPI-protected Ed25519 identity. Capture only device ID, public fingerprint, certificate SHA-256 and protected-key file digest. Never export private key material or copy DPAPI blobs into artifacts.

## Reproducible acceptance procedure

Pin the exact candidate SHA, test-signed installer/package SHA-256, Windows image/build, VM/disk/snapshot IDs, operator identity, service SID, artifact digests and UTC timestamps before running. Use a fresh restored baseline for each destructive scenario.

### A. Baseline install and five-binary manifest

1. Restore clean Windows snapshot; verify persistent disk identity and NTFS.
2. Install the candidate test-signed package with test-only trust configuration.
3. Configure/verify the dedicated non-admin service account and actual SCM service.
4. Capture SHA-256 for all five installed binaries: `wd.exe`, `wd-agent.exe`, `wd-routerctl.exe`, `wd-core.exe`, `wd-ui.exe`. Record their paths, versions and manifest.
5. Verify service starts under the expected SID, protected state ACLs, identity fingerprint and authorized terminal operation.
6. Create and record a post-baseline snapshot.

### B. Upgrade, backup and commit

1. Restore the post-baseline snapshot.
2. Run the actual installer/update path for a newer test package.
3. Observe the transaction journal and verify each original binary is backed up and hash-verified before any replacement begins.
4. Verify all five replacement hashes against the authenticated package.
5. Verify installer metadata, protected updater state, installed version, stable sequence and transaction journal agree before declaring commit.
6. Verify the service only restarts after complete verified success. Verify backups remain until the commit is durable and independently confirmed; test cleanup only after this condition.
7. Verify authorized terminal operation and capture the final manifest.

### C. Hard process interruption and same-disk reboot

For each independent case, restore the baseline snapshot. Use a VM-side supervisor to pause the actual installer/updater PID at the selected durable journal boundary or side-effect window, terminate the process (not an exception or mocked fault), verify process exit, then reboot the same VM while retaining the same disk. On boot, collect SCM and journal state before launching recovery in a fresh process.

Cover:
- Before first mutation and after pending/executing intent persistence.
- Before and after each of the five binary replacement boundaries.
- After backup creation/verification and during partial replacement.
- After service stop and before restart.
- After binary replacement but before metadata update.
- After metadata publication but before updater stable-sequence commit.
- After durable commit but before backup cleanup.
- During rollback after service stop, during restoration, after restoration but before journal finalization.
- Process termination and full OS reboot with a pending transaction.

For each case verify either complete authenticated target installation or exact restoration of all five original hashes. If outcome is ambiguous, retain journal and backups, keep the service stopped, and block subsequent updates. A failed/incomplete rollback must never restart the service against a mixed or unverified installation.

### D. Negative and replay cases

Run on restored snapshots: corrupt/missing backup; malformed, forged or path-substituted journal; reparse-point and DACL/owner substitution; duplicate transaction ID; stale sequence/downgrade; mismatched manifest/package digest; missing trust or Authenticode authority; failed metadata persistence; failed stable-sequence commit; and recovery interruption/retry.

Each must fail closed, retain the only recoverable originals, avoid unverified service restart, and preserve enough evidence for safe retry.

### E. Evidence package

Attach a redacted per-case ledger with PASS / FAIL / NOT ESTABLISHED (never count skipped/mock cases as PASS):
- Exact repository SHA and artifact SHA-256 / package manifest.
- VM image/build, VM/disk/snapshot IDs, NTFS volume, boot IDs and UTC timestamps.
- Operator identity (non-secret), service account name/SID, token groups, SCM ImagePath/StartName/start mode/state.
- Five-binary pre/post SHA-256 manifests and backup hashes.
- Transaction journal phases/digests; updater state version, pending transaction, stable sequence and installed version.
- Metadata digest and ACL/owner report.
- Installer/updater PID, forced termination evidence, recovery PID/exit code and reboot evidence.
- Redacted PowerShell transcripts, Windows event logs and authorized terminal operation result.
- Negative-test result and explicit failure behavior.

Acceptance passes only when every required case is executed on the persistent VM and independently reviewed; any unexpected service restart, missing backup, hash mismatch, identity regeneration, metadata/sequence disagreement, or lost recovery evidence is a failure.

## Existing evidence and its limits

- `.github/workflows/ci.yml` uses `windows-latest` for `windows-agent`; this is hosted CI, not persistent VM acceptance.
- `.github/workflows/production-release-build.yml` references separate self-hosted signing, publishing, update-signing and update-verification labels. Workflow labels do not prove a runner is online, persistent, privileged or suitable for acceptance.
- `docs/WINDOWS_STATE_MIGRATION_VM_ACCEPTANCE.md` contains a detailed migration procedure, separate operator/service accounts, machine-scope DPAPI identity checks, hard process termination, same-disk reboot and mock-coverage boundaries. Its C277 reconnaissance explicitly says external VM existence and runner availability are unverified.
- `docs/windows-updater-privileged-acceptance.md` identifies ADRN-9 as accountable owner, says an individual operator is not designated, and records no VM identity or real privileged restart/reboot evidence.
- `docs/UPDATE_INSTALL_TRANSACTION_C324.md` explicitly says the production Windows service executor, actual atomic replacement/rollback adapter, Authenticode policy and platform recovery adapter are not implemented by the interface/tests alone.
- C331 source inspection found no `internal/updateinfo`, `ApplyStable` or `PowerShellInstallerExecutor` callsite in `cmd/wd-agent/main.go`, `cmd/wd-core/main.go` or `cmd/wd/main.go`. The executor adapter's `exec.CommandContext` does not itself provide elevation or an authenticated privileged broker.

## Independent engineering work that can proceed

1. Implement a narrow authenticated privileged updater host/broker and explicit Local Core/service callsite; verify caller identity, package/transaction binding, privilege separation, replay rejection and audit.
2. Change rollback/recovery so any incomplete restoration leaves service stopped and transaction pending; never restart from a finally/catch path after rollback failure.
3. Make installer metadata, updater state and stable-sequence transition a crash-consistent commit protocol; add fault injection around each durable write and restart.
4. Make backup finalization idempotent and invoke deletion only after durable commit and independent target verification; preserve backups on unknown/recovery-required outcomes.
5. Add tests for the above and run exact-head hosted CI. These tests remain supplemental to real VM acceptance.

## Human provisioning decisions required

ADRN-9 must provide: (a) named infrastructure operator; (b) provisioned persistent isolated Windows VM identifier and access window, or explicit provisioning refusal/reason/owner/date; (c) approved test signing/trust/authority workflow and secret-store access; and (d) permission for controlled process termination, snapshot restoration and reboot on the isolated machine.

**No persistent VM acceptance was performed for C332. No production signing, release publication, deployment or PR merge was performed.**
