# Windows state migration: persistent VM acceptance

Hosted CI and the PowerShell migration coordinator are necessary but do not prove real Service Control Manager (SCM), service-token, DPAPI, or reboot behavior. This acceptance gate requires a persistent, elevated Windows VM dedicated to migration validation.

## VM and account prerequisites

- Use a persistent Windows 11 or supported Windows Server VM with a clean snapshot and a second snapshot after baseline installation.
- Run the installer/migration harness from an elevated administrator operator account. Do not run the service under this account.
- Create a dedicated, non-administrator local service account with a stable SID. Grant only the rights required to run the WeDecent service; do not add it to Administrators.
- Configure the real WeDecent Windows service to run as that local account. Record the SCM `StartName`, resolved local account SID, start mode, binary path, and effective token groups. The current service installer does **not** enable a separate virtual per-service SID (`NT SERVICE\<name>`); this acceptance gate validates the dedicated local account SID, not a virtual service SID. Do not report the latter as enabled or tested.
- Use a real DPAPI-protected Ed25519 identity provisioned by the agent. Record the device ID, public-key fingerprint, and certificate SHA-256 before migration. Never export or copy plaintext private-key material for the test.
- Keep VM credentials and recovery material in the approved secret store. Do not place credentials, DPAPI blobs, private keys, or customer state in CI artifacts or this repository.

## Required acceptance sequence

1. **Baseline:** install the signed test build, enroll/provision one device identity, configure the dedicated service account, and verify the service starts with a non-administrator token.
2. **Real SCM migration:** run the actual installer migration from the original state directory to a new, non-existent destination directory beneath the configured WeDecent install directory (currently `%ProgramFiles%\WeDecent\data\agent`). The destination and its staging sibling must be on a local NTFS volume; the installer rejects destinations outside its install-root boundary, and the migration coordinator publishes staging by same-parent atomic rename. Do not choose an arbitrary second volume or UNC path. Capture before/after SCM `PathName`/ImagePath, `StartName`, resolved account SID, start mode, service state, and event logs.
3. **Identity and DPAPI continuity:** verify the same device ID, Ed25519 fingerprint, and certificate bytes before and after migration. If the source already contains a machine-scoped DPAPI key, verify the protected-key bytes/digest are identical in the destination. If the source instead contains the supported legacy plaintext `identity.key`, verify the destination contains a machine-scoped `identity.key.dpapi`, contains no plaintext legacy key, and preserves the same cryptographic identity; do not claim that a DPAPI blob was byte-preserved when the source had none. In both cases keep the source untouched until acceptance and never export the private key or DPAPI blob. Restart the actual SCM service and verify it can decrypt/use the same identity without regeneration or prompting.
4. **Service restart:** stop/start the service through SCM after migration. Confirm authorized terminal operation and inspect service-token groups and state-directory ACLs.
5. **Process termination:** inject termination at each durable journal phase, including before and after destination publication, SCM reconfiguration, metadata publication, and rollback. Relaunch the installer/recovery path in a fresh process. Confirm fail-closed behavior and exact restoration or safe pending recovery.
6. **Reboot recovery:** terminate the VM during a pending transaction, reboot from the same persistent disk, and run recovery. Verify SCM configuration, service start behavior, metadata, original identity, ACLs, and journal terminal state.
7. **Negative cases:** repeat with a substituted source/destination/staging/journal/metadata object, reparse point, changed owner/DACL, missing authority, a user-scoped DPAPI identity, duplicate/trailing/malformed journal input, and injected native CreateFile / GetFileInformationByHandle failures. The current Windows key loader requires machine-scope DPAPI and rejects an existing user-scoped key rather than silently changing its protection scope; verify this rejection leaves the source identity, SCM configuration, metadata, and service state unchanged. Confirm no unsafe SCM transition, metadata replacement, or service restart follows any rejected validation.
8. **Evidence:** archive redacted console output, PowerShell transcripts, SCM query output, service-token/local-account-SID and ACL reports, event logs, pre/post identity fingerprints, VM snapshot identifiers, exact source commit SHA, installer artifact SHA-256, and test timestamps. Do not archive secrets or private-key bytes.

## Acceptance criteria

- The service runs as the dedicated non-administrator SID before and after migration.
- The original Ed25519 identity remains unchanged; no silent identity regeneration occurs. An existing machine-scoped DPAPI blob must remain byte-identical. For a legacy plaintext source key, the destination must contain the equivalent machine-scoped DPAPI-protected identity and no plaintext key; the original source remains preserved until acceptance.
- Actual SCM path/account/start-mode transitions match the migration journal and authenticated installer metadata.
- Every injected failure either completes a verified rollback or leaves an explicit recoverable pending transaction with the service stopped; no unverified service restart is permitted.
- Process termination and full VM reboot do not lose the ability to recover safely.
- All negative cases fail closed and produce auditable evidence.

## Current infrastructure dependency

The repository does not provision or control this persistent elevated VM. A Windows infrastructure owner must supply the VM, administrator operator access, dedicated non-administrator service account/SID, snapshot/reboot capability, and access to the approved signing/test-credential workflow. Hosted GitHub Actions must not be presented as a substitute for this acceptance.

## C277 infrastructure reconnaissance (2026-11-25)

This section records the repository-visible infrastructure evidence checked for the persistent acceptance dependency. It does not assert that no external VM or runner exists.

### Findings

- The CI workflow uses GitHub-hosted `windows-latest` for the Windows agent job. The Desktop workflow also uses `windows-latest` for its Windows Tauri job. These jobs are not configured as persistent, elevated acceptance VMs.
- The production release workflow declares separate self-hosted runner labels: `[self-hosted, windows, wedecent-signing]` for Windows signing and `[self-hosted, linux, wedecent-release-publisher]` for publication. Those labels establish workflow dependencies, not current runner availability, VM persistence, administrative access, snapshot/reboot capability, or suitability for destructive migration acceptance.
- The signing runner must not be repurposed for migration fault injection or reboot testing. Acceptance requires an isolated machine and credentials so that tests cannot affect signing keys, release artifacts, or publication infrastructure.
- The repository root and `.github` directory contain no CODEOWNERS file. The Windows migration acceptance procedure identifies a required Windows infrastructure owner but does not name one.
- The repository-visible issue search and PR #203 discussion did not establish a named Windows infrastructure owner, an assigned VM-provisioning ticket, or a commitment that a persistent acceptance VM can be provisioned.
- The available GitHub integration does not expose the repository self-hosted runner inventory/administration endpoint. Consequently, online/offline runner status and the existence of an unadvertised persistent Windows VM remain unverified.

### Ownership and provisioning disposition

**Accountable Windows infrastructure owner: not identified from verifiable available evidence.**

**Provisioning decision: unknown.** There is no evidence sufficient to say that a persistent elevated Windows 11/Server VM is currently available or that an owner has committed to provision one. This is an external infrastructure dependency, not a failed software test.

The repository owner or organization administrator must identify a named infrastructure owner and confirm one of these outcomes:

1. Supply an isolated, persistent Windows 11 or supported Windows Server VM meeting the prerequisites above; or
2. Explicitly state that provisioning is unavailable, identify the reason, and provide an owner and target date for resolving the dependency.

### Exact provisioning request

Provide an isolated persistent Windows 11 or supported Windows Server VM with:

- A clean snapshot and the ability to create/restore a post-baseline snapshot.
- Elevated operator access for installer, SCM, filesystem ACL/owner, process-termination, and reboot testing.
- A dedicated local non-administrator service account with stable SID and only the rights needed to run the service; the operator account must remain separate.
- Ability to install the test-signed WeDecent build and configure/query the actual Windows Service Control Manager service.
- A persistent disk and permission to terminate the VM/process at specified migration journal boundaries and reboot the same disk for recovery.
- An approved secret store for operator credentials and recovery material; no secrets or DPAPI/private-key material may be copied into repository files or CI artifacts.
- A controlled method to provision an actual DPAPI-protected Ed25519 identity and capture redacted device ID, public fingerprint, certificate hash, service-account SID, ACL, SCM, event-log, snapshot, and artifact-hash evidence.
- Network isolation and access sufficient for authorized terminal validation without exposing production signing keys, production customer data, or release publication credentials.

On receipt, run every step and negative case in this document against the exact candidate SHA and record redacted evidence. Hosted CI remains supplemental only.

No code, trust policy, ACL rule, migration behavior, release workflow, or signing configuration is changed by this infrastructure note.


## C289 — reproducible acceptance execution plan

This section separates repository/hosted regression coverage from acceptance that must execute on the isolated persistent VM. The commands below are preparation instructions; none of the real-machine steps is evidence of execution until its redacted output and machine identifiers are attached to the acceptance record.

### Candidate and artifact pinning

Before each run, record:

- PR #203 head commit SHA and confirm it is still the intended candidate.
- Test-signed installer/package SHA-256 and the SHA-256 of the installed `wd-agent.exe`.
- Windows edition/build, VM identifier, disk identifier, snapshot identifiers, UTC start/end times, and operator identity (non-secret).
- Service name, service account name, resolved stable SID, start mode, binary path, and effective token groups.
- Device ID, SHA-256 SPKI fingerprint, certificate SHA-256, and a digest of the DPAPI-protected key file. Never export the private key or copy DPAPI blobs into artifacts.

Use an isolated test signing certificate and a test recovery authority with short-lived credentials. Do not use production signing keys, production recovery credentials, customer state, or the production signing/publishing runners.

### Existing repository checks that can be reused

Run these on a disposable Windows CI runner or the isolated acceptance VM from a clean checkout of the pinned candidate. The build step is required because the migration coordinator script expects `dist/wedecent-windows-amd64/wd-agent.exe`.

From a Bash shell with the repository's pinned Go toolchain:

```bash
WEDECENT_BUILD_MODE=diagnostic ./scripts/build-windows-release.sh
```

From elevated 64-bit PowerShell on a disposable test host (the first three scripts do not require an installed service; the coordinator creates temporary fixtures and mocks SCM commands):

```powershell
pwsh -NoProfile -File .\scripts\test-windows-upgrade-preflight.ps1
pwsh -NoProfile -File .\scripts\test-windows-service-installer-contract.ps1
pwsh -NoProfile -File .\scripts\test-windows-state-migration-coordinator.ps1
go test ./...
go test ./cmd/wd-agent -run '^TestWindowsServiceStateDefaultLocationUsesProtectedProgramFilesAncestors$' -count=1 -v
go test ./cmd/wd-agent -run '^(TestServiceStartupRejectsForeignAncestorOwnerBeforeLogIdentityOrRecoveryLoad|TestWindowsSDDLRightsMaskHandlesDirectoryServiceRightsFailClosed)$' -count=1 -v
```

For the distinct-SID provisioning regression, first create a disposable local non-admin account and set `WEDECENT_TEST_SERVICE_ACCOUNT` to its local account name, then run:

```powershell
go test ./cmd/wd-agent -run '^TestServiceProvisionDistinctConfiguredSIDNativeIntegration$' -count=1 -v
```

The CI workflow's Windows job (`.github/workflows/ci.yml`, `windows-agent`) is the canonical reference for the complete hosted sequence. It parses installer/hardware scripts, runs the upgrade preflight, installer credential contract, migration coordinator, replay-store regressions, native Go tests, protected-ancestor/hostile-owner tests, and the distinct-SID provisioning test. Its temporary service account is removed in an `always()` cleanup step.

**Coverage boundary:** `scripts/test-windows-state-migration-coordinator.ps1` replaces `Get-CimInstance`, `Get-Service`, `Stop-Service`, `Start-Service`, and `sc.exe` with test doubles. It provides valuable software-level transaction, journal, path, ACL, file-identity, injected-failure, rollback, and fresh-process recovery coverage. It does not install or control a real SCM service. `TestServiceProvisionDistinctConfiguredSIDNativeIntegration` provisions and validates an empty state directory owned by a different SID; its own source comment explicitly requires subsequent SCM startup and DPAPI persistence testing under that account. `internal/identity/protect_windows_test.go` exercises machine-scope DPAPI behavior in the test process, not under the installed service token. These tests must not be reported as real-service acceptance.

### Persistent-VM execution sequence (must be performed on the real machine)

1. **Provision and isolate.** Restore a clean Windows 11 or supported Windows Server VM snapshot. Keep the elevated operator separate from the service account. Create a dedicated local standard account (for example, `WeDecentAcceptSvc`), resolve and record its SID, verify it is not an administrator, and grant only the service logon rights required by the installer. Keep credentials in the approved secret store.
2. **Install a known baseline.** Install a test-signed baseline build using the documented installer flow in `installer/windows/README.md`. Use a test recovery-authority URL/pin/trust document and short-lived bearer delivered through the installer's secure prompt/secure-string input. Do not place bearer values in argv, environment variables, logs, or transcripts. Verify the actual service's `StartName`, SID, start mode, image path, running state, token groups, and state-directory ACL/owner before continuing.
3. **Create the identity fixture.** Let the actual service provision/use its Ed25519 identity. Capture only the device ID, public fingerprint, certificate hash, and DPAPI-protected key-file digest. Confirm authorized terminal operation against a separately controlled test endpoint. Do not export or duplicate private-key material or DPAPI blobs.
4. **Take the baseline snapshot.** Snapshot the VM after the baseline installation and identity enrollment. Record snapshot ID, VM/disk ID, service configuration, source state path, source manifest, identity evidence, and exact baseline artifact hashes.
5. **Run the real installer migration.** From elevated PowerShell, invoke the candidate `installer/windows/Install-WeDecent.ps1` against the existing authenticated installation with the intended new `-StateDir` under the protected Program Files install tree. Follow the candidate's documented parameters and credential prompts; do not edit installer metadata or SCM configuration by hand. Capture before/after SCM `ImagePath`, `StartName`, start mode, service state, metadata, journal phases, state ACL/owner, and event logs. Confirm the original source remains available until the transaction is accepted.
6. **Verify identity and service-token continuity.** After migration, query the actual SCM service and confirm it runs under the same dedicated non-admin SID. Verify the device ID, Ed25519 fingerprint, certificate bytes/hash, and DPAPI-protected key bytes are unchanged. Stop and start the service using SCM; verify the same identity is reopened without prompting or regeneration. Re-run authorized terminal operation.
7. **Exercise hard process interruption and recovery on disposable snapshots.** The durable journal phases in the current `StateMigration.psm1` are exactly `Prepared`, `Copying`, `Copied`, `Verified`, `StatePublished`, `ServiceReconfigured`, `Committed`, `RollingBack`, and `RolledBack`. `ServiceStopped`, `IdentityVerification`, `IdentityProtected`, `SCMTransition`, `MetadataUpdated`, and `ServiceRestarted` are fault-injection hook names, not persisted journal phases; do not describe them as journal states. Restore the baseline snapshot for each interruption case. Use a VM-side debugger or controlled supervisor to pause the actual installer process immediately after the selected journal write has been durably published, then terminate that process (not merely throw an exception). Verify the process has exited before launching a new PowerShell process and invoking installer recovery. Exercise forward boundaries after `Prepared`, `Copying`, `Copied`, `Verified`, `StatePublished`, and `ServiceReconfigured`, plus pending rollback at `RollingBack`; verify `Committed` and `RolledBack` as terminal outcomes rather than recovery points. Also terminate in the side-effect windows between durable journal writes: after service stop but before `Copying` is written; during partial staging and after machine-scope DPAPI protection/staging-complete publication but before `Verified`; after atomic destination publication but before `StatePublished`; after SCM path reconfiguration but before `ServiceReconfigured`; after metadata publication and after service restart but before `Committed`; and during rollback after service stop but before `RollingBack`, after SCM restoration, after metadata restoration, after service restart, and after candidate cleanup but before `RolledBack`. These windows matter because the last durable journal phase can legitimately lag the most recent side effect. Recovery must reconcile each state without regenerating identity, losing the original source, or restarting against an unverified path. The coordinator's `-FaultAt` option throws into the installer's in-process catch/rollback path and is **not** evidence of abrupt process termination. Its child-PowerShell fresh-process test also mocks SCM commands. Record the exact durable phase, process PID/exit evidence, journal digest, SCM state/configuration, source/destination/staging integrity, and recovery outcome for each case. Do not use a CI runner or signing/publishing runner.
8. **Exercise rollback and negative cases.** On separate restored snapshots, induce the documented failure cases (source/destination/staging substitution, malformed or substituted journal/metadata, reparse points, owner/DACL changes, missing authority, and native file-handle failures) using the harness where applicable. For real-machine checks, verify that rejected inputs do not restart the service, replace metadata, delete/overwrite the source, or weaken ACLs. A mock-driven test result is supplemental, not proof of real SCM behavior.
9. **Exercise reboot recovery.** On a disposable snapshot, terminate the VM while a real migration transaction is durably pending, reboot the same persistent disk, and run recovery from a fresh process. Verify SCM path/account/start mode, service state, journal terminal phase, metadata, source preservation, ACLs, and unchanged identity evidence.
10. **Close out evidence.** Preserve redacted PowerShell transcripts, SCM query output, service-token/local-account-SID and ACL reports, relevant Windows event logs, journal phase summaries, pre/post identity fingerprints and hashes, snapshot/VM/disk identifiers, exact source commit SHA, installer and binary SHA-256 values, and UTC timestamps. Review every file for passwords, bearer tokens, private-key material, DPAPI blobs, customer data, and other secrets before retention.

### Pass criteria and reporting format

A step is **PREPARED** when its procedure and inputs are documented; **EXECUTED** only when run on the named persistent VM and supported by retained evidence. Mark each result **PASS**, **FAIL**, or **NOT ESTABLISHED**. Hosted CI PASS must remain separately labelled and cannot satisfy the real-machine gate.

The real-machine gate passes only when the actual SCM service uses the dedicated non-admin SID before and after migration; DPAPI reopening preserves the exact Ed25519 identity across service stop/start and reboot; all injected interruptions recover or roll back safely with the source retained; rejected cases fail closed without unsafe SCM/metadata/filesystem mutation; and authorized terminal operation succeeds after recovery.

Do not run destructive interruption, rollback, or reboot tests on production infrastructure, a shared developer workstation, or either production signing/publishing runner. If the persistent VM or approved test signing/recovery fixtures are unavailable, stop before installation/mutation, report the precise missing prerequisite, and leave the real-machine steps **NOT ESTABLISHED**.


## C293 — independent implementation/runbook reconciliation (2026-11-26)

This review compares the runbook with the candidate implementation at PR #203 HEAD `1aa5f641a61311923ce7e67bd4b98fad528d7dd9`. It is a source-level assessment, not execution evidence from a Windows VM.

### Implementation facts that constrain acceptance

- `internal/winservice/service_windows.go` creates the service with `CreateServiceW` and changes only its description with `ChangeServiceConfig2W`. It does not configure `SERVICE_CONFIG_SERVICE_SID_INFO` or enable a virtual `NT SERVICE\<name>` SID. `cmd/wd-agent/service_state_windows.go` and `internal/winservice/service_windows.go` resolve and enforce the dedicated **local account SID** for state-directory ownership and runtime identity. Acceptance records must therefore call this the account SID, not claim a virtual service SID is enabled.
- `installer/windows/Install-WeDecent.ps1` constrains `StateDir` beneath `InstallDir`; the current default install root is under Program Files. `StateMigration.psm1` requires local NTFS state paths, creates staging as a sibling of the destination, and publishes it into that parent. A destination on an arbitrary second volume or outside the install root is not a supported test input.
- `internal/identity/private_key_scope_windows.go` selects machine-scoped DPAPI by default; `private_key_windows.go` uses `CRYPTPROTECT_LOCAL_MACHINE` and rejects an existing user-scoped protected key when machine scope is required. The protected blob's DACL is the local access boundary. Include the user-scope rejection as a negative case. The decisive acceptance is successful identity reopening by the actual SCM service running as the dedicated local account after migration, stop/start, and reboot—not a successful elevated-operator `identity-check` alone.
- `StateMigration.psm1` persists the nine phases listed in step 7. Other named interruption hooks are transient fault-injection points and do not become journal phases. Its stable manifest intentionally excludes `identity.key` and `identity.key.dpapi`; therefore a stable-manifest match is not proof of private-key continuity. Check the full manifest and the separate certificate/fingerprint/protected-key identity assertions, with the legacy-key conversion exception described in step 3.
- `test-windows-state-migration-coordinator.ps1` replaces `Get-Service`, `Stop-Service`, `Start-Service`, `Get-CimInstance`, and `sc.exe` with test doubles. Its `-FaultAt` mechanism throws into the same process's catch/rollback path. The script separately starts a child PowerShell process for a recovery test, but the SCM remains mocked. Neither behavior proves abrupt termination of the real installer or recovery through actual SCM.

### Journal validation and mutation ordering

The installer first authenticates existing installer metadata and prepares/protects the migration-journal parent directory. That parent-directory ACL preparation is a filesystem mutation that occurs before journal parsing and must be treated as a prerequisite hardening operation, not as proof that the journal was trusted. `Read-WeDecentMigrationJournal` then checks the journal file's type, owner/DACL and file identity, strict JSON (including duplicate-property and trailing-content rejection), schema/phase, required fields, absolute/disjoint paths, account SID, exact Boolean fields, manifest digests, and original-metadata/source binding. Only after this parser returns does recovery acquire its mutation lease, validate the source, and enter SCM/metadata/tree rollback operations. Report this accurately as **journal validation before transaction side effects, after journal-parent protection**, not as validation before every filesystem mutation.

### ACL and filesystem evidence interpretation

Migration intentionally normalizes the destination tree: the destination root and descendants are assigned to the dedicated local account SID and receive the restricted allow-list DACL for that account, LocalSystem, and local Administrators. The source tree is validated and retained; destination ACLs are not expected to be byte-for-byte identical to legacy source ACLs. Legacy-source ancestor validation is intentionally narrower than normal runtime validation: it permits benign inherited create-child rights but rejects untrusted delete-child, delete, ownership, or DACL mutation rights. Record source and destination owner/DACL evidence separately, verify every destination descendant and all protected ancestors, and confirm the original source manifest/identity remains intact through commit or rollback.

### Additional evidence required for an independently auditable run

For each run, retain the source, staging, and destination manifest digests (including the stable-source digest), journal SHA-256 and phase history, before/after SCM `PathName`, `StartName`, resolved local account SID, start mode and service state, actual process exit/recovery evidence, source-retention and destination-cleanup results, and owner/SDDL reports for the state tree and relevant ancestors. Record both the test-signed installer and installed agent SHA-256. Keep identity evidence to device ID, public fingerprint, certificate digest, and protected-key digest; never retain private keys, DPAPI blobs, or recovery bearer values.

### C293 assessment disposition

The changes above correct runbook terminology, unsupported destination wording, phase enumeration, and the distinction between injected exceptions and hard process termination. They do not assert that the implementation has passed real SCM, service-account DPAPI, process-kill, rollback, or reboot acceptance. Those remain NOT ESTABLISHED until executed on the isolated persistent VM.
