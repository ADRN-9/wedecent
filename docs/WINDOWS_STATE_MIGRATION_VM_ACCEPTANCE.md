# Windows state migration: persistent VM acceptance

Hosted CI and the PowerShell migration coordinator are necessary but do not prove real Service Control Manager (SCM), service-token, DPAPI, or reboot behavior. This acceptance gate requires a persistent, elevated Windows VM dedicated to migration validation.

## VM and account prerequisites

- Use a persistent Windows 11 or supported Windows Server VM with a clean snapshot and a second snapshot after baseline installation.
- Run the installer/migration harness from an elevated administrator operator account. Do not run the service under this account.
- Create a dedicated, non-administrator local service account with a stable SID. Grant only the rights required to run the WeDecent service; do not add it to Administrators.
- Configure the real WeDecent Windows service to use that account and its service SID. Record the service name, SID, start mode, binary path, and effective token groups.
- Use a real DPAPI-protected Ed25519 identity provisioned by the agent. Record the device ID, public-key fingerprint, and certificate SHA-256 before migration. Never export or copy plaintext private-key material for the test.
- Keep VM credentials and recovery material in the approved secret store. Do not place credentials, DPAPI blobs, private keys, or customer state in CI artifacts or this repository.

## Required acceptance sequence

1. **Baseline:** install the signed test build, enroll/provision one device identity, configure the dedicated service account, and verify the service starts with a non-administrator token.
2. **Real SCM migration:** run the actual installer migration from the original state directory to a new local volume/directory. Capture before/after SCM ImagePath, account SID, start mode, service state, and event logs.
3. **Identity and DPAPI continuity:** verify the same device ID, Ed25519 fingerprint, certificate bytes, and DPAPI-protected key bytes before and after migration. Restart the service and verify it can decrypt/use the same identity without regeneration or prompting.
4. **Service restart:** stop/start the service through SCM after migration. Confirm authorized terminal operation and inspect service-token groups and state-directory ACLs.
5. **Process termination:** inject termination at each durable journal phase, including before and after destination publication, SCM reconfiguration, metadata publication, and rollback. Relaunch the installer/recovery path in a fresh process. Confirm fail-closed behavior and exact restoration or safe pending recovery.
6. **Reboot recovery:** terminate the VM during a pending transaction, reboot from the same persistent disk, and run recovery. Verify SCM configuration, service start behavior, metadata, original identity, ACLs, and journal terminal state.
7. **Negative cases:** repeat with a substituted source/destination/staging/journal/metadata object, reparse point, changed owner/DACL, missing authority, and injected native CreateFile / GetFileInformationByHandle failures. Confirm no unsafe SCM transition, metadata replacement, or service restart follows a rejected validation.
8. **Evidence:** archive redacted console output, PowerShell transcripts, SCM query output, service-token/SID and ACL reports, event logs, pre/post identity fingerprints, VM snapshot identifiers, exact source commit SHA, installer artifact SHA-256, and test timestamps. Do not archive secrets or private-key bytes.

## Acceptance criteria

- The service runs as the dedicated non-administrator SID before and after migration.
- The original Ed25519 identity and DPAPI material remain unchanged; no silent identity regeneration occurs.
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
- A controlled method to provision an actual DPAPI-protected Ed25519 identity and capture redacted device ID, public fingerprint, certificate hash, service SID, ACL, SCM, event-log, snapshot, and artifact-hash evidence.
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
7. **Exercise interrupted recovery on disposable snapshots.** For each durable forward phase in the journal (`Prepared`, `ServiceStopped`, `Copying`, `Copied`, `IdentityVerification`, `IdentityProtected`, `Verified`, `StatePublished`, `SCMTransition`, `ServiceReconfigured`, `MetadataUpdated`, `ServiceRestarted`), restore the baseline snapshot and repeat the migration on a fresh disposable clone. Terminate only the test installer process at the selected phase using the VM operator's controlled process-termination mechanism; do not use a CI runner or signing runner. Start a fresh installer/recovery process and verify deterministic recovery, source preservation, correct SCM configuration, and no identity regeneration. Record the journal phase and exact outcome for every interruption point.
8. **Exercise rollback and negative cases.** On separate restored snapshots, induce the documented failure cases (source/destination/staging substitution, malformed or substituted journal/metadata, reparse points, owner/DACL changes, missing authority, and native file-handle failures) using the harness where applicable. For real-machine checks, verify that rejected inputs do not restart the service, replace metadata, delete/overwrite the source, or weaken ACLs. A mock-driven test result is supplemental, not proof of real SCM behavior.
9. **Exercise reboot recovery.** On a disposable snapshot, terminate the VM while a real migration transaction is durably pending, reboot the same persistent disk, and run recovery from a fresh process. Verify SCM path/account/start mode, service state, journal terminal phase, metadata, source preservation, ACLs, and unchanged identity evidence.
10. **Close out evidence.** Preserve redacted PowerShell transcripts, SCM query output, service-token/SID and ACL reports, relevant Windows event logs, journal phase summaries, pre/post identity fingerprints and hashes, snapshot/VM/disk identifiers, exact source commit SHA, installer and binary SHA-256 values, and UTC timestamps. Review every file for passwords, bearer tokens, private-key material, DPAPI blobs, customer data, and other secrets before retention.

### Pass criteria and reporting format

A step is **PREPARED** when its procedure and inputs are documented; **EXECUTED** only when run on the named persistent VM and supported by retained evidence. Mark each result **PASS**, **FAIL**, or **NOT ESTABLISHED**. Hosted CI PASS must remain separately labelled and cannot satisfy the real-machine gate.

The real-machine gate passes only when the actual SCM service uses the dedicated non-admin SID before and after migration; DPAPI reopening preserves the exact Ed25519 identity across service stop/start and reboot; all injected interruptions recover or roll back safely with the source retained; rejected cases fail closed without unsafe SCM/metadata/filesystem mutation; and authorized terminal operation succeeds after recovery.

Do not run destructive interruption, rollback, or reboot tests on production infrastructure, a shared developer workstation, or either production signing/publishing runner. If the persistent VM or approved test signing/recovery fixtures are unavailable, stop before installation/mutation, report the precise missing prerequisite, and leave the real-machine steps **NOT ESTABLISHED**.
