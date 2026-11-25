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
