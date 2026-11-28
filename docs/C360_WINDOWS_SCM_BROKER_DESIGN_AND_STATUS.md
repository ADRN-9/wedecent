# C360 — Windows SCM broker boundary: implementation and threat model

**Status:** PARTIAL CONTAINMENT IMPLEMENTED; PRIVILEGED BROKER NOT IMPLEMENTED.  
**PR:** #209, intentionally open and draft.

## Executive disposition

C359 established that LockServiceDatabase is a no-op on supported Windows versions and cannot fence external SCM writers. C360 adds least-privilege SCM handle access and an explicit protected service-object DACL, applied to newly created services and to existing services before the installer performs upgrade/migration/recovery mutations.

This is a useful reduction of the ordinary caller attack surface, not the requested final broker boundary. The service-management path still contains direct elevated PowerShell/SCM mutations, and an authenticated broker IPC server has not been implemented. Do not describe the SCM broker as shipped or the concurrent privileged-writer race as closed.

## C360 code changes

### Service-object access control

internal/winservice/service_windows.go now:

- Opens the SCM with SC_MANAGER_CONNECT for ordinary start/stop/query operations and SC_MANAGER_CREATE_SERVICE for service creation, rather than requesting SC_MANAGER_ALL_ACCESS everywhere.
- Opens service handles with operation-specific rights: SERVICE_START | SERVICE_QUERY_STATUS, SERVICE_STOP | SERVICE_QUERY_STATUS, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS, or SERVICE_QUERY_STATUS.
- Applies a protected service DACL after successful creation and rolls back service creation if DACL application fails.
- Exposes an elevated wd-agent service secure --service-name=... command that applies the same DACL to an existing service.
- Uses SetSecurityInfo with SE_SERVICE, DACL_SECURITY_INFORMATION and PROTECTED_DACL_SECURITY_INFORMATION.

The exact DACL authored is:

    D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000004;;;AU)

This grants LocalSystem and BUILTIN\Administrators full service-object access, and Authenticated Users only SERVICE_QUERY_STATUS. It does not grant ordinary authenticated callers service start, stop, delete, configuration, WRITE_DAC or WRITE_OWNER rights. Local Administrators retain full control and are explicitly within the trusted OS authority boundary.

### Installer integration

For an existing service, Install-WeDecent.ps1 invokes the service secure command from the already validated release bundle after authenticated metadata and live service-account SID checks, and after ShouldProcess approval, but before migration, recovery or upgrade mutations. A nonzero result aborts the transaction. New services receive the DACL from winservice.Install before the install command returns.

The Windows service installer contract now asserts that existing-service upgrades invoke this hardening step and fail closed if it fails.

### Scope limitation

This does not move all service configuration, state migration, rollback, recovery, start/stop, or error-handling operations behind one privileged broker. The installer and recovery PowerShell still perform direct SCM mutations while running elevated. An elevated administrator can also change the service DACL or reconfigure SCM outside WeDecent. This is not atomic compare-and-mutate protection.

## Threat model

### Principals

| Principal | Intended authority |
|---|---|
| Standard interactive user / desktop process | Use Local Core; may query service status; no SCM start/stop/configuration or DACL mutation |
| Dedicated WeDecent agent service account | Read/write only protected service state and execute the agent; no SCM configuration or control authority |
| WeDecent privileged service-management broker (future) | Sole supported WeDecent mutation authority under a tightly scoped LocalSystem service identity |
| Elevated signed installer/update transaction (current transitional path) | Performs approved service mutations; temporary authority until broker is implemented |
| Local Administrators / SYSTEM | Trusted OS authority; can ultimately take ownership, change ACLs, replace binaries or modify SCM |

### Threats the current DACL reduces

- A compromised ordinary user process attempting ChangeServiceConfig, StartService, ControlService(STOP), DeleteService, or service-object DACL changes through normal SCM access checks.
- The dedicated service account attempting to reconfigure or stop its own service.
- Accidental overbroad SCM handles in WeDecent's own start/stop/query code.

### Threats not closed

- A local administrator or SYSTEM process reconfiguring SCM concurrently with an installer/recovery operation.
- Any PowerShell direct SCM mutation that is not yet routed through a broker.
- A broker confused-deputy flaw, because the broker does not yet exist.
- IPC spoofing, malformed messages, replay, cross-session impersonation, or request authorization, because no broker IPC protocol/server exists.
- Real service-object DACL effectiveness under an actual non-admin token, until persistent-VM acceptance verifies access denied for every forbidden operation.
- Race-free service identity validation at the kernel SCM mutation boundary.

Local administrators with equivalent system privileges are trusted. No user-mode broker can prevent a fully privileged administrator/SYSTEM principal from taking ownership, changing service security, replacing trusted files, or altering the machine's service configuration.

## Required final broker design

A separate, signed and protected Windows service-management broker is required. It must be installed and started as a distinct service, not be the ordinary WeDecent agent service running under its dedicated non-admin account.

### IPC boundary

- Use a dedicated local named pipe, not the general same-user Local Core pipe.
- Pipe DACL grants connect/read/write only to SYSTEM and the explicitly authorized elevated installer/update principal; reject remote named-pipe clients.
- Server obtains the caller token by impersonating the connected pipe client. Validate token user SID, enabled group membership, elevation type, integrity level, session, and process identity. Never trust caller-supplied SID, executable path, is_admin, or role fields.
- Authenticate the caller process image against the installed signed publisher and approved transaction executable. Verify file identity and signature using a handle-based path check; reject reparse points and replacement races.
- Require a server-generated unpredictable challenge, one-use request identifier, short expiry, and strict per-connection state. Consume the challenge before mutation and reject duplicate/replayed request IDs. Restart must invalidate all outstanding challenges.
- Bound message size; use strict UTF-8 JSON or a versioned binary schema; reject duplicate/unknown fields, trailing bytes, malformed encodings, invalid operation enum values, path traversal, alternate streams, UNC/device paths, reparse points and ambiguous paths.
- Never accept arbitrary executable commands, arbitrary service names, caller-selected security descriptors, arbitrary account names, or arbitrary destinations.

### Request authorization and service identity

Every mutation request must bind:

- Fixed service identity and operation enum.
- Authenticated caller token SID and process identity.
- A server-generated one-use challenge and transaction ID.
- The exact expected service account name and resolved SID.
- Exact expected executable path and file identity/hash.
- Exact protected state directory and its owner/DACL.
- Expected service start mode and current service configuration digest.
- The signed update/migration capability, target version and package digest where applicable.
- A bounded expiry and replay sequence.

The broker must independently load ACL-protected installer metadata and verify all fields; it must not accept the request's values as authority. It must serialize all WeDecent SCM mutations, reopen the service with the minimum required access, revalidate all identity/configuration immediately before the SCM call, record a durable transaction/audit event, and fail closed on mismatch.

A challenge prevents request replay; it does not prevent concurrent administrators from changing SCM. The service DACL and OS privilege model provide the boundary against ordinary callers. Local administrators remain trusted.

### Operations that must use the broker

- Initial service creation and service DACL provisioning.
- Service account/path/start-mode configuration.
- Service stop/start and delete.
- Migration service stop/reconfiguration/restart.
- Upgrade and rollback transitions.
- Recovery and error-handler state transitions.
- Uninstall and cleanup transitions that mutate SCM.

PowerShell may collect input and display progress, but it must not call sc.exe config/delete, Stop-Service, Start-Service, or any SCM mutation API directly after the broker migration is complete.

## Required adversarial tests

| Test | Required assertion |
|---|---|
| Non-admin user requests start/stop/config/delete | IPC rejected; SCM and filesystem snapshots unchanged |
| Dedicated service account requests mutation | IPC rejected; zero side effects |
| Caller spoofs another SID or process path in JSON | Ignored/rejected; actual impersonated token is authority |
| Pipe opened from remote client | Connection rejected |
| Malformed, oversized, duplicate-field or trailing-data message | Rejected before mutation |
| Replayed challenge/request ID | Rejected before mutation |
| Expired challenge/capability | Rejected before mutation |
| Operation not in allowlist | Rejected before mutation |
| Path traversal, UNC, device path, ADS, reparse-point substitution | Rejected before mutation |
| Service account name/SID substitution | Rejected before mutation |
| Executable path/file ID/hash substitution | Rejected before mutation |
| State directory owner/DACL substitution | Rejected before mutation |
| Concurrent ordinary-user SCM reconfiguration | Denied by service-object DACL |
| Concurrent local-administrator SCM reconfiguration | Documented trusted-admin boundary; broker must detect mismatch where possible and fail closed, but cannot claim atomic exclusion |
| Broker abrupt termination | Durable journal permits deterministic recovery; no unverified service restart |
| Broker restart/replay | Old challenges and request IDs remain invalid |

Every rejection test must compare pre/post SCM config, service state, service DACL, protected metadata, journal, binary and state-tree snapshots. It must prove zero protected side effects, not merely assert an error string.

## Windows 1314 and persistent VM acceptance

The hosted Windows isolation test remains NOT ESTABLISHED. The last observed hosted-runner warning was that the runner lacks process-token privileges to create a child under the authenticated service identity. A previous experimental CreateProcessWithLogonW fallback failed in CI and was reverted. Do not relabel that skip as pass.

The persistent privileged Windows VM acceptance runbook remains docs/WINDOWS_STATE_MIGRATION_VM_ACCEPTANCE.md. Accountable repository/infrastructure owner is ADRN-9; an individual VM operator has not been named in the inspected repository evidence. The named operator, persistent VM/disk/snapshot IDs, service-token group evidence, machine-scope DPAPI identity continuity, hard process interruption, reboot and real SCM rollback evidence are still outstanding.

## C360 execution status

- [x] Live HEAD/tree/PR/history independently recovered.
- [x] Least-privilege SCM manager/service handle access implemented.
- [x] Protected service-object DACL applied on new service creation.
- [x] Existing-service upgrade hardens DACL before migration/upgrade mutation.
- [x] Static contract test requires the upgrade DACL hardening step and fail-closed error handling.
- [ ] Authenticated privileged broker service and named-pipe IPC.
- [ ] Caller-token impersonation and process/signature authorization.
- [ ] Broker request schema, challenge, replay protection and durable audit.
- [ ] All migration/recovery/upgrade/rollback SCM writes routed through broker.
- [ ] Native adversarial SCM and IPC zero-side-effect tests.
- [ ] Persistent privileged VM and named operator acceptance.
- [ ] Windows 1314 isolation probe genuinely executed.
- [ ] Fresh exact-HEAD updater, full CI and Windows/Linux/macOS desktop workflows passed after final code changes.

The current implementation is a containment improvement. It is not a completed C360 broker and is not production-ready.
