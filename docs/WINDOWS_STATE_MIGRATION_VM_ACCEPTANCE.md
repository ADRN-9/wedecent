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
