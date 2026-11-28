# C362 — Privileged Windows SCM Broker Security Architecture

**Status:** DESIGN PROPOSED; NOT IMPLEMENTED; NOT SECURITY-ACCEPTED  
**Design baseline:** dd6efadcf9d190e5761009db02a6aff11929e655  
**Baseline tree:** 49b7e1518f512c1879945f110330c4b4823dc77c  
**Repository:** ADRN-9/wedecent  
**PR:** #209 — open, draft, unmerged  
**Branch:** security/c324-verified-update-admission-recovery  
**Date:** 2026-11-28

## 1. Executive decision

Implement a distinct Windows service-management broker, separate from the ordinary WeDecent agent and Local Core. The broker is the only supported WeDecent component allowed to mutate the WeDecentAgent SCM service object. The elevated installer becomes a typed, authenticated client. PowerShell remains an orchestrator and user interface; it must no longer call Stop-Service, Start-Service, sc.exe config/delete, or other SCM mutation APIs after migration.

The broker is not a general command runner. It exposes a closed set of versioned operations, fixed service identity, constrained product paths, transaction identifiers and narrowly typed parameters. It independently validates the installed product state and signed package evidence. Caller-supplied names, paths, SIDs, role claims, hashes and configuration snapshots are assertions to compare, never authority.

The broker serializes all WeDecent mutations and journals before/after state. This serializes cooperating WeDecent operations; it does not create an atomic compare-and-mutate primitive in Windows SCM. Local Administrators and SYSTEM remain trusted OS authorities. They can change service configuration or security concurrently and can take ownership of protected files. The architecture detects unexpected changes where possible, aborts before subsequent operations, retains recovery evidence, and never claims to eliminate a race against an equally privileged administrator.

**No implementation or race closure is claimed by this document.** C362 delivers a design and a migration/test plan only.

## 2. Verified baseline and repository findings

C361 baseline commit dd6efadcf9d190e5761009db02a6aff11929e655 is the live branch ref and PR head. Its tree is 49b7e1518f512c1879945f110330c4b4823dc77c and its parent is cfd6a7c187633923c6ace86fde31892c98de3e47. PR #209 was independently fetched and remains OPEN, DRAFT and UNMERGED.

The baseline has the C360 service-object DACL and least-privilege handle improvements. Existing service DACL is:
D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000004;;;AU)

SYSTEM and BUILTIN\Administrators receive full control; Authenticated Users receive query-status only. The new broker requires a broker-specific service SID ACE with only the rights needed for the fixed agent service. That is a future implementation change and must not be assumed present.

### 2.1 Direct mutation inventory and exact migration ownership

The following source files were fetched at the C361 baseline. Line numbers below are from those exact baseline blobs and must be refreshed when implementation begins.

| File | Direct SCM mutation sites found | Broker operation mapping |
|---|---|---|
| installer/windows/Install-WeDecent.ps1 | 1590 Stop-Service; 1649 Start-Service; 1657 Stop-Service rollback; 1795 Stop-Service; 2251 Start-Service; 2260 Stop-Service rollback; 2294 Start-Service rollback; 2305 Stop-Service rollback; 2433 Stop-Service; 2436 sc.exe delete | StopForUpgrade, StartAfterUpgrade, StopForRollback, RestorePreviousState, CreateAgentService, DeletePartiallyInstalledService |
| installer/windows/Recover-WeDecentInstall.ps1 | 270 and 284 Stop-Service; 289 Start-Service; 868 documents immediate revalidation and the LockServiceDatabase compatibility no-op | RecoverStop, RecoverStart, RecoverRollback |
| installer/windows/StateMigration.psm1 | 903 sc.exe config; 1190 Stop-Service; 1212 Start-Service; 2065 Stop-Service; 2131 Start-Service; same path is used by rollback helpers | MigrationStop, ApplyStatePath, MigrationStart, RollbackStatePath, RollbackStart |
| installer/windows/Uninstall-WeDecent.ps1 | 284 Stop-Service; 291 sc.exe delete; fallback path when wd-agent.exe is unavailable | PrepareUninstall, StopForUninstall, DeleteAgentService |

Additional service-control APIs are inside internal/winservice/service_windows.go: CreateServiceW, ChangeServiceConfig2W, StartServiceW, ControlService(STOP), DeleteService, OpenSCManagerW, OpenServiceW and SetSecurityInfo. The existing cmd/wd-agent service commands expose install/start/stop/uninstall/secure. These must be divided into broker client operations and non-privileged status operations; they must not remain alternate privileged mutation paths.

Fresh-install service creation is invoked by Invoke-AgentServiceInstall in Install-WeDecent.ps1 (baseline line 761 onward), which launches wd-agent.exe service install with the service-account password and recovery-authority bearer on redirected standard input. The broker migration must preserve the separation of these secrets. The service-account password may be delivered only in a dedicated bounded secret frame for CreateAgentService and must never be logged, persisted in the broker journal, or put in command-line arguments. The recovery-authority bearer is not an SCM credential: it remains in the agent's separate protected provisioning flow and is never passed to the SCM broker.

### 2.2 Existing IPC is not the broker

internal/coreapi/localipc/localipc_windows.go implements the same-user Local Core pipe, with a current-user SID DACL and remote-client rejection. It does not authenticate an elevated installer transaction or authorize SCM mutation. Do not widen or repurpose it.

internal/relay/broker.go manages relay connection slots and is unrelated to Windows service management.

C360's service DACL and service secure command are useful containment only. They do not provide authenticated broker IPC, impersonated caller authorization, replay protection, a broker journal, or a single mutation boundary.

## 3. Threat model and trust boundaries

### 3.1 Protected assets

- The WeDecentAgent service object: service account, binary command line, start mode, dependencies, service DACL and runtime state.
- Installed agent binaries and the signed package/manifest from which they are staged.
- Installer metadata, update/migration journals, service identity SID and state directory.
- Device identity, pairing and recovery material in the protected state tree.
- Broker executable, service configuration, broker policy, audit log and transaction journal.
- Integrity and availability of terminal sessions during upgrade, recovery, migration and uninstall.

### 3.2 Principals

| Principal | Trust and permitted authority |
|---|---|
| Standard user / desktop / Local Core client | Untrusted for SCM writes. May use the supported Local Core API and query status. Cannot invoke broker mutation operations. |
| WeDecentAgent service account | Dedicated non-admin identity. May access its protected state and run the agent. Cannot manage itself, broker, SCM configuration or broker journal. |
| Elevated installer client | Potentially compromised input source. Authenticated by actual Windows token and pinned installed publisher/product executable identity. May request only operations covered by an approved signed transaction and current operator elevation. |
| SCM broker service | Trusted reference monitor for WeDecent service mutations. Separate service, separate service SID, protected image/configuration/policy, no interactive logon. |
| SYSTEM and local Administrators | Trusted host authorities. They can ultimately override service DACLs, replace files, take ownership and reconfigure SCM. This architecture does not claim protection against a malicious equally privileged administrator. |
| Other services, remote clients and network principals | Untrusted; no broker pipe access and no remote pipe connections. |

### 3.3 Security invariants

1. Only the broker performs WeDecentAgent SCM create/configure/start/stop/delete and service-object DACL changes after migration.
2. The broker has no arbitrary command, executable, service-name, account-name, security-descriptor, path or PowerShell operation.
3. The broker derives authority from its own protected policy, verified transaction descriptor, installed metadata and actual Windows security tokens. Request fields are never self-authenticating.
4. The agent service account is not a broker client principal and cannot acquire SCM mutation authority.
5. Every mutating operation is bound to one fixed service name, one transaction, one approved package digest and a short-lived server-issued challenge.
6. Any ambiguity, malformed message, stale transaction, identity mismatch, unexpected service state or uncertain recovery phase stops progress before the next side effect.
7. Secrets never enter audit records, diagnostic strings, process arguments or durable broker transaction records.
8. The broker never starts a service whose executable, account SID, state path, start mode or protected metadata cannot be independently verified.
9. A broker timeout is an unknown outcome, not proof that an operation failed. The client queries transaction status; it does not blindly retry a non-idempotent operation.
10. Broker serialization is not represented as protection from concurrent Local Administrator/SYSTEM writes.

### 3.4 Explicit non-goals

- Defending a host after SYSTEM or an equally privileged local administrator is compromised.
- Making Windows SCM mutations atomic compare-and-swap operations.
- Arbitrary service administration or a general-purpose privileged task runner.
- Remote broker access, network RPC, relay-based SCM control or Local Core protocol reuse.
- Storing service-account passwords or recovery bearer values in broker audit/journal.
- Silently repairing an untrusted pre-existing service, service account, binary path, state directory or DACL.

## 4. Windows security model and concurrency boundary

### 4.1 Service-object DACL versus SCM manager DACL

The Service Control Manager database and each individual service object have different security descriptors and access masks.

SC_MANAGER_CONNECT is required to open the SCM for ordinary connection. SC_MANAGER_CREATE_SERVICE is a manager-level right required for service creation. Service-specific rights include SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STOP, SERVICE_CHANGE_CONFIG, DELETE, READ_CONTROL and WRITE_DAC.

The broker must open the SCM and the fixed WeDecentAgent service with only the rights needed for the current operation. It must not use SC_MANAGER_ALL_ACCESS or SERVICE_ALL_ACCESS as a convenience default.

The existing C360 service DACL grants SYSTEM and Administrators full control and Authenticated Users query-status only. The broker migration adds a distinct broker service SID ACE to the agent service DACL, granting only the exact service-object rights needed by broker operations. The agent's own service SID is not granted service-control rights. The broker service object's DACL and binary directory are separately protected.

The SCM manager DACL must be evaluated separately for initial CreateService authority. If the chosen broker service account is granted SC_MANAGER_CREATE_SERVICE, that right is broad at the manager level: SCM does not provide a per-service-name create permission. The broker's compiled operation allowlist and strict package/service-name validation are therefore mandatory. This manager right must not be granted to the agent or interactive user. The implementation must document and test the exact SCM DACL ACE and effective token access.

### 4.2 LockServiceDatabase is not the concurrency solution

LockServiceDatabase / UnlockServiceDatabase are documented as compatibility no-ops on Windows Vista and later. They do not fence SCM configuration changes and must not be used as a security claim or serialization primitive.

The broker uses an in-process exclusive mutation gate and a machine-wide named mutex with a protected DACL to serialize cooperating WeDecent broker instances/operations. A durable transaction journal and transaction-ID uniqueness prevent duplicate broker work. These controls serialize WeDecent's own requests; they do not lock out external administrators or SYSTEM.

### 4.3 Concurrent privileged administrator changes

SCM exposes no atomic conditional ChangeServiceConfig/StartService/ControlService operation that means “perform this only if the service configuration still equals digest X.” A query followed by an SCM call has a time-of-check/time-of-use interval. Re-querying immediately before and after narrows and detects some races but does not remove that interval.

The security boundary is therefore explicit:

- Standard users and the dedicated agent account are denied mutation by the service-object DACL and broker IPC authorization.
- Only the broker is the supported WeDecent mutation path.
- Local Administrators/SYSTEM remain trusted and can change SCM configuration concurrently.
- The broker records a pre-mutation configuration digest, validates identity immediately before the API call, performs one typed mutation, then re-queries and verifies the expected postcondition.
- If any mismatch is observed, it stops subsequent operations, does not restart against an unverified binary/state path, retains backups/journal and emits a high-severity audit result.
- Compensation/rollback is attempted only if the current state matches a known transaction-owned state and all rollback inputs still verify. Otherwise the transaction enters NeedsOperator and the service remains stopped when safe to do so.
- Documentation and acceptance must say “detects and fails closed on observed mismatch where possible,” never “eliminates concurrent administrator race.”

A malicious local administrator can still win the final TOCTOU interval or rewrite the broker itself. That is within the documented trusted-host authority boundary, not a broker guarantee.

## 5. Broker process, service identity and lifecycle

### 5.1 Separate service identity

Create a distinct Windows service named WeDecentSCMBroker, with its own protected installation directory, executable, service configuration, service SID, state/journal directory, audit log and service-object DACL. It must not run inside wd-agent.exe, the agent service account, the desktop process or Local Core.

Preferred account model: a dedicated virtual service account NT SERVICE\WeDecentSCMBroker with a unique service SID and restricted service SID mode. Grant only the specific broker SID and SYSTEM the required access to broker files, policy, journal and pipe. The broker must have no interactive logon and no network listener. Required token privileges are reduced to the minimum needed for pipe-client impersonation and service operation; explicitly document and verify the effective token and required privileges on supported Windows versions.

For SCM manager access, the installation bootstrap must grant the broker SID only SC_MANAGER_CONNECT and, if broker-owned initial service creation is enabled, SC_MANAGER_CREATE_SERVICE. The latter is inherently broad at SCM manager scope; the broker must enforce a single fixed service name and typed CreateAgentService operation. If this cannot be safely granted/tested under the virtual account, stop and document the precise Windows access limitation rather than silently running the ordinary agent as SYSTEM. Any alternative broker account/privilege design requires a separate reviewed decision.

For the agent service object, the protected DACL grants the broker service SID only the required query/start/stop/configure/delete/read-control/write-DACL rights, SYSTEM and Administrators the documented full authority, and Authenticated Users query-status only. The broker does not grant its own SID to the agent service token. Do not grant WRITE_OWNER unless a demonstrated operation requires it.

### 5.2 Broker service object and binary protection

- Install broker binary and policy under a fixed machine-wide product directory whose owner is SYSTEM/Administrators and whose DACL denies write/replace/delete to standard users and the agent account.
- Reject reparse-point ancestors and verify volume/file IDs for the broker executable, policy and journal directory.
- Protect the broker service DACL so only SYSTEM/Administrators can reconfigure/delete it; ordinary users receive no mutation rights.
- Pin the expected publisher identity and package signing policy. Validate the broker image before install/update; use a verified package manifest and immutable staging.
- Service start mode and failure actions are fixed by broker policy. Do not accept them from an IPC caller.
- Broker must not load plugins, scripts, DLLs, config includes or executable paths from writable locations.
- No outbound network dependency is required for local SCM mutation. If update authorization needs signed manifest data, the installer supplies a verified signed transaction descriptor; the broker validates its signature against a provisioned trust anchor and checks package digest/expiry.

### 5.3 Startup and shutdown

At startup, broker validates its own service configuration, executable identity, policy, state directory ACL/owner, journal integrity and pending transaction. It does not create the pipe until journal recovery reaches a known safe state. If validation or recovery is uncertain, it remains unavailable and records a sanitized failure.

On shutdown, broker stops accepting new clients, finishes or durably marks the active transaction, flushes journal/audit data, closes pipe instances and releases the mutation gate. It must not kill the agent or restart it as a generic shutdown action.

Service recovery actions must not blindly restart a broker whose journal is corrupt or whose binary/policy identity is invalid. Windows service recovery configuration must be conservative; startup validation is authoritative.

## 6. Named-pipe IPC protocol

### 6.1 Pipe endpoint and DACL

Use a dedicated local-only pipe, for example:
\\.\pipe\WeDecent.SCM.v1

This is not the Local Core pipe. Create it with PIPE_REJECT_REMOTE_CLIENTS, FILE_FLAG_FIRST_PIPE_INSTANCE for initial ownership, bounded buffers, and an explicit protected DACL. The DACL permits SYSTEM and the elevated local Administrators group to connect; all authorization is still performed against the actual client token. Do not grant Everyone, Authenticated Users, the agent service SID, interactive-user SID or network logon SID generic access.

The broker obtains the actual pipe client PID with GetNamedPipeClientProcessId and session ID with GetNamedPipeClientSessionId. It impersonates the connected client using ImpersonateNamedPipeClient, obtains the thread token with OpenThreadToken, duplicates it for inspection, and always calls RevertToSelf in a finally/defer path. Impersonation failure, token-open failure or revert failure aborts the request and closes the pipe. Never accept SID, elevation, session, image path or role values supplied in the message.

### 6.2 Client authentication

Authorization requires all of the following:

1. The actual impersonated token is a local interactive/elevated administrator token: expected user SID, enabled Administrators membership, full elevation (not a filtered/limited token), high integrity, not AppContainer, not a network logon token, and an allowed interactive session.
2. Pipe client PID is live and bound to the pipe connection. The process token matches the impersonated token identity and session.
3. The process image is the installed, protected WeDecent installer/broker-client executable at a fixed canonical path. Open the image without following reparse points; capture volume serial/file ID, final path and file hash; validate Authenticode signature against the pinned product publisher and expected product identity. Hold the image handle during verification and re-check file identity after signature verification. Reject path aliases, UNC/device paths, reparse points, writable ancestors, unsigned images, wrong publisher, unexpected version and file-ID/hash changes.
4. The caller is requesting an operation allowed to that exact client type and transaction state.
5. The transaction descriptor/package is valid, signed by the appropriate provisioned trust anchor, unexpired, and binds the expected operation, service identity, package digest and transaction ID.

The actual token and opened file handle are authoritative. A caller-supplied process path or “is_admin” field is never authority. If Windows APIs cannot establish stable image identity under a held handle on a supported version, fail closed and revise the client-authentication mechanism before implementation approval.

The threat model treats local Administrators as trusted host authorities. Process-signature checks prevent accidental/ordinary confused-deputy use; they do not protect against a malicious administrator capable of injecting into or replacing an elevated process.

### 6.3 Framing and schema

Use a versioned binary framing or strict UTF-8 JSON schema with a 4-byte network-order length prefix and a hard maximum message size (initial proposal: 64 KiB request, 16 KiB response; secret-bearing CreateAgentService frame separately bounded). Reject zero/oversized lengths, truncated frames, multiple messages where one is expected, invalid UTF-8, duplicate JSON keys, unknown fields, trailing bytes, non-canonical numeric values, invalid enum values and schema-version mismatch. The implementation must use a decoder that explicitly detects duplicate keys; Go encoding/json default duplicate-key behavior is insufficient on its own.

Each request contains only:
- protocol version;
- operation enum;
- transaction ID (128-bit random identifier);
- server challenge ID and 256-bit challenge response binding;
- monotonic request sequence for that connection;
- signed transaction descriptor reference/digest;
- operation-specific typed payload.

Responses contain protocol version, transaction ID, operation, accepted/completed/pending/rejected state, stable error code, safe user-facing message, and postcondition digest. Never return stack traces, passwords, bearer values, private paths outside the approved product roots, raw command output or secret-bearing Windows error context.

No arbitrary command string, shell, PowerShell text, executable path, service name, service account name, security descriptor, raw SCM access mask, registry path or destination path is accepted.

### 6.4 Handshake, challenge and replay

1. Client connects and authenticates at the OS token/process layer.
2. Broker generates a cryptographically random 256-bit challenge, a connection nonce and a short expiry (initial proposal: 60 seconds).
3. Client returns the challenge bound to the operation, transaction ID, request sequence, signed descriptor digest and caller identity. Challenge is single-use and consumed before any mutation.
4. Broker verifies the signed transaction descriptor, expiry, package digest, fixed service identity, current policy and current service state.
5. Broker atomically reserves the transaction ID in its protected journal before beginning side effects.
6. Duplicate transaction IDs, stale challenges, wrong connection nonce, expired descriptors, mismatched request digests, repeated sequence numbers or operation changes are rejected before mutation.

Challenges are in-memory and invalidated on broker restart. A persistent broker boot epoch changes on each successful startup. Transaction IDs and terminal outcomes are persisted in the durable journal so replay after restart is rejected. Do not rely on a wall-clock timestamp alone; validate clock sanity and use monotonic time for connection deadlines. If the clock moves backwards or expiry cannot be established, fail closed for privileged operations.

A fresh challenge is not an authorization capability by itself. It only prevents replay of an already authorized request. Authorization still requires the actual caller token, verified client image, signed transaction descriptor and server-side state checks.

### 6.5 Secret-bearing install request

The current installer sends the dedicated service-account password to wd-agent.exe over redirected stdin. During migration, the password is not placed in process arguments, environment variables, logs or durable journal. A dedicated CreateAgentService request may carry a separate bounded secret frame over the already authenticated local pipe, protected by the pipe DACL and OS session boundary. The broker immediately copies it into a locked/zeroed buffer, uses it only for CreateServiceW, clears all copies on success/failure and never echoes it. The broker must not persist it.

The recovery-authority bearer is not required for SCM. It must remain in the agent's separate protected provisioning flow, not be accepted by the broker. Do not combine the two secret channels. A future design may replace the service-account password with a supported virtual service account, but that changes the service identity model and requires a separately reviewed migration; it must not be silently introduced.

## 7. Typed operation allowlist

The service name is a compiled constant: WeDecentAgent. The broker does not accept an arbitrary service name. Every operation re-derives all identity and path inputs from broker policy, signed transaction descriptor and protected metadata.

| Operation | Allowed purpose | Server-derived values |
|---|---|---|
| PrepareInstall | Reserve one signed initial install transaction | Fixed service name, approved bundle digest, protected install/state roots, account SID from validated installer transaction |
| CreateAgentService | Create exactly WeDecentAgent | Exact verified wd-agent.exe path, fixed argv generated from schema, validated account SID, start mode policy; secret password only in bounded secret frame |
| ApplyAgentServiceDacl | Apply fixed protected agent-service DACL | Fixed DACL template plus broker service SID |
| PrepareUpgrade | Validate current service and signed target package | Current SCM config digest, installed service SID, target binary file ID/hash, state root |
| StopAgentService | Stop fixed agent for a prepared transaction | Fixed service name, expected current config digest, transaction state |
| ConfigureAgentBinary | Set only the verified target wd-agent.exe and fixed argument schema | Path derived from protected staging manifest; no caller-selected binary path |
| ConfigureAgentStatePath | Change only the state path between authenticated source/destination roots of an active migration transaction | Source/destination from validated journal; no arbitrary path |
| StartAgentService | Start only after full post-configuration verification | Fixed service name and expected config digest |
| RecoverTransaction | Reconcile one broker-owned pending transaction | Journal-derived phase and verified source/destination; no caller-selected recovery action |
| RollbackTransaction | Restore only a verified transaction-owned previous configuration | Journal backup digest, previous path/account/start mode and known state |
| PrepareUninstall | Validate signed uninstall transaction and retention/purge choice | Fixed service, product roots and explicit purge capability |
| DeleteAgentService | Stop if policy permits, then delete fixed agent service | Fixed service name and journaled state; only after backup/retention policy checks |
| QueryTransaction | Read sanitized state of caller's own authorized transaction | Transaction ID bound to caller/descriptor |
| QueryAgentStatus | Read-only status/config digest | Fixed service name; no mutation rights |

No generic StartService(name), StopService(name), ChangeServiceConfig(name, config), DeleteService(name), RunCommand, ExecutePowerShell, arbitrary ACL setter or arbitrary path operation exists.

The following must remain outside broker authority: device identity creation, pairing, recovery bearer issuance, network/relay configuration, terminal authorization, routing grants, UI settings and file transfer. Local Core remains the application/security authority for those domains.

## 8. Server-side identity and filesystem validation

For every mutation, broker independently validates:

### 8.1 Service identity and configuration

- Exact service name and expected service type.
- Actual SCM StartName resolved to SID, compared with authenticated metadata and transaction descriptor.
- Exact executable path parsed using Windows command-line rules, not substring or StartsWith checks.
- Exact allowed argument vector and state-directory argument.
- Start mode, service type, error control, dependencies, service account, service DACL and current status.
- Current service object owner/DACL and absence of unexpected ACEs.
- Service process image path/file identity when running.
- No service identity or account change during ordinary upgrade/migration. A service-account migration is a distinct reviewed operation with explicit old/new SID proof.

### 8.2 Executable identity

- Resolve path under the fixed protected install/staging root.
- Open with no-follow semantics; reject reparse points and alternate data streams.
- Verify final path, volume serial/file ID, size, SHA-256 and Authenticode publisher/signature.
- Compare digest with signed package manifest and transaction descriptor.
- Verify protected owner/DACL on file and every ancestor.
- Revalidate file identity immediately before configuration/start and after start. Do not use an arbitrary path from the request.
- Hold handles where practical to reduce replacement races; document residual local-administrator authority.

### 8.3 State directory and metadata

- Open directory handles and canonicalize by handle; reject UNC, device namespace, relative, alternate-stream and reparse paths.
- Verify fixed-volume/local filesystem policy and expected source/destination roots.
- Verify owner and DACL for root, ancestors, metadata, journal and descendants; deny write/rename/delete to untrusted principals.
- Read strict schema metadata and journal from protected handles, verify file identity and expected owner/DACL, reject duplicate keys and unexpected fields.
- Bind service account name and SID, install root, state path, service executable, transaction ID, source/destination manifest digests and phase history.
- Never follow a reparse point during tree traversal or cleanup. Reject junctions and hard-link substitutions where identity cannot be proven.
- Compare full stable manifest and protected identity continuity before state publication, service reconfiguration and service start.

### 8.4 Revalidation boundaries

Validate before transaction reservation, immediately before each SCM mutation, immediately after each SCM mutation, before each filesystem publication/deletion, and before service start. Postcondition mismatch is a transaction failure. This is defense in depth and detection; it does not turn SCM into a conditional atomic API.

## 9. Serialization, concurrency and operation lifecycle

Use one process-wide mutation semaphore and a machine-wide named mutex with a protected DACL (SYSTEM and broker service SID only). Acquire in a fixed order. The journal has an exclusive file handle and transaction ID uniqueness. All mutating requests, including recovery and uninstall, share this gate. Read-only QueryAgentStatus and QueryTransaction may run concurrently from a consistent snapshot.

Do not create one independent mutex per operation; that permits conflicting start/stop/configure operations. Do not rely on the existing PowerShell installer.lock as the broker authority. During migration it may remain as a transitional orchestrator lock, but broker serialization is authoritative and cross-process.

If the mutex is abandoned, do not simply take it and continue. Validate the journal and reconcile the current SCM/filesystem state before accepting a new mutation. If an active request disconnects, the broker continues the durable operation or moves it to a known safe failure state; client disconnect is not cancellation authority after a mutation has begun.

### 9.1 Durable transaction phases

Use a strict finite state machine, persisted and flushed before each irreversible side effect:

- Created: request authenticated; no side effects.
- Prepared: transaction descriptor, pre-state config digest and source manifests verified.
- StopIntent: durable intent to stop.
- Stopped: SCM confirms stopped; actual service identity rechecked.
- StageVerified: target package and state staging verified.
- ConfigureIntent: durable intent to change service config.
- Configured: SCM query confirms exact expected post-config.
- StatePublished: destination path/state manifest atomically published and verified.
- StartIntent: durable intent to start.
- RunningVerified: service is running under expected SID and exact binary/state path; identity opens correctly.
- Committed: durable success and audit record.
- RollbackIntent / RolledBack: rollback only to journal-authenticated original state.
- NeedsOperator: mismatch, ambiguous side effect, journal corruption or unsafe rollback; broker rejects further mutation for that service until explicit recovery procedure.
- FailedNoSideEffect: request rejected before any SCM/filesystem mutation.

Every phase transition is flushed to disk before the next side effect. The journal is bounded, schema-versioned, protected by owner/DACL and hash chained. Audit append and journal commit ordering must be specified and crash-tested; never mark committed before postconditions and audit durability are confirmed.

### 9.2 Broker restart and crash handling

At broker restart:
1. Validate broker binary, policy, service configuration, journal root and ACL.
2. Acquire the global mutation gate.
3. Verify journal integrity and scan for non-terminal transactions.
4. Re-query actual SCM config/status/DACL and protected filesystem identities.
5. Compare observed state against recorded pre-state, intended state and last durable phase.
6. Continue only if exactly one safe deterministic transition is proven.
7. Roll back only when all original artifacts and current transaction-owned state verify.
8. Otherwise set NeedsOperator, leave the agent stopped if it is running against an unverified path, retain backups and reject new mutation requests.
9. Rotate boot epoch and invalidate all prior challenges before opening the pipe.

Never auto-start an agent solely because the previous journal says it was running. It must pass full binary, account SID, state path, DACL and identity checks first.

### 9.3 Idempotency and timeouts

- Each mutating transaction has a random 128-bit ID; each operation has a sequence.
- QueryTransaction returns the durable outcome for an existing transaction.
- Repeated request with same transaction ID and same digest returns current status; different payload for same ID is rejected.
- Client timeout/disconnect does not cause automatic duplicate execution.
- Non-idempotent operations are never retried without a broker status query.
- If SCM returns an ambiguous error or process interruption occurs after the call but before journal update, broker re-queries actual SCM state and reconciles only known states; otherwise NeedsOperator.

## 10. Audit and secret hygiene

Record both successful and failed authorization/operation outcomes in a broker-owned append-only local audit stream and Windows Event Log. Audit events include UTC timestamp, boot epoch, transaction ID, operation enum, caller user SID, caller process image file ID/hash and publisher identity, session ID, target fixed service name, package digest/version, pre/post configuration digests, result category, Win32 error code and journal phase.

Never log passwords, recovery bearer, private key, pairing secret, access token, raw request body, secret frame, process environment, command-line secrets, or unredacted protected metadata. Do not include arbitrary caller paths or raw exception text. Use stable safe error codes and sanitized messages. Audit file owner/DACL must prevent standard user and agent modification. A hash chain detects accidental/tamper modification but does not defeat SYSTEM/Administrators; do not claim otherwise.

Authorization rejection, malformed request, replay, stale challenge, identity mismatch, unexpected SCM state, postcondition mismatch, broker crash recovery and rollback must all be auditable. If audit storage is unavailable or cannot be durably flushed, privileged mutations fail closed before side effects. A failure to write the final audit record after an SCM mutation moves the transaction to an explicit uncertain/NeedsOperator state, never a false success.

## 11. Transition plan for each existing file

### 11.1 Install-WeDecent.ps1

- Replace fresh-install Invoke-AgentServiceInstall's direct service install call with PrepareInstall/CreateAgentService/ApplyAgentServiceDacl broker transactions. Continue passing service-account password only through the dedicated bounded secret channel; do not move recovery bearer into broker.
- Replace line 1590 stop for interrupted-install recovery with RecoverStop; line 1649 start with RecoverStart; line 1657 best-effort stop with a typed stop-if-transaction-owned operation; line 1795 stop with StopForUpgrade.
- Replace line 2251 start after upgrade with StartAgentService; line 2260 and 2305 stop-on-failure with StopForRollback; line 2294 rollback start with RestorePreviousState.
- Replace line 2433 stop and line 2436 sc.exe delete for fresh-install rollback with DeletePartiallyInstalledService, which checks the broker-owned install journal and verified service identity.
- Keep ShouldProcess and operator confirmation in the installer UI, but the broker independently checks elevated token and signed transaction capability. ShouldProcess alone is not broker authorization.
- Installer must never fall back to Stop-Service, Start-Service or sc.exe when the pipe is unavailable.

### 11.2 Recover-WeDecentInstall.ps1

- Replace line 270/284 Stop-Service with RecoverStop and line 289 Start-Service with RecoverStart.
- Broker loads and validates the protected installer recovery journal itself; caller supplies only transaction ID and signed recovery descriptor reference.
- Preserve source/destination manifest, service SID, account name, executable path, state path and phase checks. Move authoritative checks into broker rather than trusting PowerShell's CIM result.
- If broker is unavailable, journal is ambiguous or identity differs, keep the service stopped where verified safe and report manual recovery; never use direct SCM fallback.
- Retain the existing LockServiceDatabase no-op comment; do not reintroduce a false lock claim.

### 11.3 StateMigration.psm1

- Replace Set-WeDecentMigrationServicePath line 903 sc.exe config with ConfigureAgentStatePath. Caller supplies transaction ID and source/destination role enum, not BinaryPath.
- Replace line 1190/1212 rollback stop/start and line 2065/2131 forward migration stop/start with broker typed operations.
- Broker owns the service mutation phase in the migration journal and verifies the exact service command line after config.
- Keep the module's filesystem migration logic initially, but require a broker-issued transaction lease/capability bound to source/destination manifests before filesystem publication. C363 must decide whether filesystem mutation authority also moves into broker or remains a separately constrained migration worker. Do not imply SCM brokering alone secures all filesystem races.
- Remove direct sc.exe/Stop-Service/Start-Service only after broker integration tests cover forward, rollback and recovery.

### 11.4 Uninstall-WeDecent.ps1

- Replace line 284 Stop-Service and line 291 sc.exe delete with PrepareUninstall/StopForUninstall/DeleteAgentService.
- Remove the fallback to sc.exe when wd-agent.exe is missing. Missing client binary must not create an alternate privileged path. Use the separately protected broker client or fail closed and request verified repair media.
- Broker verifies explicit purge-versus-preserve authorization and retention rules before service deletion. Filesystem purge remains separately authorized and audited; no broad recursive deletion path is delegated to an arbitrary request.
- Service-account removal and logon-right removal remain a distinct typed operation, with account SID verified against protected metadata and no password passed to broker.

### 11.5 internal/winservice and cmd/wd-agent

- Move SCM mutation implementation into a dedicated broker package/service process. Agent's service start/stop/install/uninstall/secure CLI commands must become broker-client requests or be removed from the ordinary agent binary.
- Keep read-only service status in a minimal query path with SERVICE_QUERY_STATUS only.
- The agent service account must not be able to call broker mutation endpoints; broker validates token SID and elevated client image.
- Existing service DACL hardening is retained and extended with broker SID rights. No generic service name or raw access mask crosses IPC.

## 12. Adversarial test matrix

Every rejection test must capture before/after SCM service config, status, DACL, broker journal, audit, installer metadata, binary hashes/file IDs, state tree manifests and owner/DACL. A rejected request must prove zero protected side effects, not merely an error response.

| Attack / failure | Expected result |
|---|---|
| Standard user connects to pipe | DACL denial; no broker request accepted |
| Agent service account connects | DACL/token authorization denial |
| Unelevated filtered admin token | Reject: elevation type/integrity not full |
| Wrong admin SID/session/network logon/AppContainer | Reject before operation |
| Caller spoofs SID, PID, role or image path in payload | Ignore payload claim; derive actual OS token/PID; reject mismatch |
| Signed but wrong product executable/publisher | Reject |
| Unsigned/replaced/reparse-point client image | Reject |
| Pipe remote client | PIPE_REJECT_REMOTE_CLIENTS rejection |
| Duplicate/unknown JSON keys, invalid UTF-8, trailing bytes | Reject before journal reservation |
| Oversized/truncated/zero-length frame | Reject and close connection |
| Unknown protocol version/operation/field | Reject |
| Arbitrary service name, command, executable, account, path, ACL or SCM mask | Schema has no such field; reject |
| Expired challenge or signed transaction descriptor | Reject before mutation |
| Replayed challenge, transaction ID or sequence | Reject; no second side effect |
| Same transaction ID with changed payload | Reject |
| Broker restart followed by old challenge replay | Reject due boot epoch/nonce invalidation |
| Service account name/SID mismatch | Reject before stop/configure/start |
| Service path, arguments, start mode or dependency mismatch | Reject before mutation |
| Binary digest/signature/file ID mismatch | Reject before start |
| State root owner/DACL/reparse/hard-link/ancestor substitution | Reject before filesystem or SCM mutation |
| Broker journal corrupt, truncated, stale or hash-chain mismatch | Pipe remains unavailable; NeedsOperator |
| Concurrent second broker operation | Serialize; reject or wait with bounded deadline |
| Abandoned global mutex | Reconcile journal before accepting new mutation |
| Client disconnect during SCM operation | Broker finishes/reconciles; client queries transaction status |
| Broker process termination before SCM call | Journal remains prepared; restart reconciles no side effect |
| Broker termination after SCM call before journal phase update | Re-query SCM; continue only if exact known postcondition |
| Agent service crashes during upgrade | Keep stopped; recover only verified transaction state |
| Concurrent ordinary-user service mutation | Service-object DACL denies it |
| Concurrent local-admin/SYSTEM reconfiguration | Trusted-admin boundary; detect mismatch when observable, abort subsequent work; do not claim atomic prevention |
| Audit/journal disk full or ACL failure | Fail closed before mutation; uncertain post-mutation outcome is NeedsOperator |
| Service start after binary/state path changed | Reject unless exact expected signed binary, account SID, state path and DACL verify |
| Uninstall client missing | No sc.exe fallback; fail closed |

Native Windows tests must use real distinct tokens and actual named pipes/SCM, not only mocks. Test the service object's effective access under standard user, agent account, broker account, elevated installer, SYSTEM and local Administrators.

## 13. Persistent privileged Windows VM acceptance

Hosted GitHub Actions is not a substitute for persistent privileged VM evidence. The previous Windows cross-user/session process isolation probe skipped because the hosted runner lacked required process-token privileges; this remains NOT ESTABLISHED.

Before acceptance, record a named individual VM operator, accountable infrastructure owner, Windows edition/build, VM ID, persistent disk ID, clean and transaction snapshots, service-account SID, broker service SID, installer and broker binary SHA-256, signed test package identity and UTC acceptance window. Do not use production signing/publishing runners for fault injection.

Required cases:

1. Install broker as separate service under intended virtual service account; verify service SID, effective token groups/privileges, service DACL, binary and policy ACLs.
2. Verify pipe DACL and remote-client rejection; connect using standard user, agent service account, unelevated admin and elevated signed installer tokens.
3. Verify impersonated token values against independently captured token evidence: user SID, groups, elevation, integrity, session and process ID.
4. Verify service account and broker service identity separation; agent cannot connect as an authorized mutation client.
5. Verify actual service DACL: Authenticated Users query only; agent SID cannot start/stop/configure/delete/change DACL; broker SID has only required rights; SYSTEM/Administrators remain documented trusted authorities.
6. Execute fresh install, upgrade, state migration, rollback, interrupted recovery and uninstall on disposable snapshots. Confirm authorized terminal session and same Ed25519 device ID/fingerprint after each successful migration.
7. Test service-account password handling; confirm no secret in process command line, environment, logs, journal, crash dump or audit. Confirm recovery bearer remains in separate agent provisioning flow.
8. Terminate broker at every durable transaction phase using an independent hypervisor/VM supervisor; reboot the same persistent disk and verify deterministic recovery or NeedsOperator.
9. Reboot with pending journal, broker service stopped, agent service stopped and agent service running; prove no unverified auto-start.
10. Race two valid installer requests and a recovery request; verify broker serialization and idempotent transaction status.
11. Attempt concurrent ordinary-user SCM mutations; confirm actual access denied.
12. Attempt concurrent local-admin SCM reconfiguration and record the documented trusted-admin limitation. Confirm broker detects mismatches where possible and does not claim race-free atomic exclusion.
13. Confirm every success/failure audit event is durable and secret-free; test disk-full and journal ACL failures.
14. Verify Windows 1314 cross-user/session process-isolation tests genuinely execute with no privilege skip.
15. After acceptance, attach redacted before/after SCM configuration and DACL, effective token evidence, service SID, binary/file IDs, journal phase hashes, audit hashes, VM/disk/snapshot IDs, boot IDs and authorized terminal proof. Never retain passwords, recovery bearer, private keys or DPAPI blob contents.

A skipped, mock-only, hosted-runner or operator-unavailable case is NOT ESTABLISHED, not pass.

## 14. Implementation sequence and gates

### C363 — Broker service skeleton and token-authenticated pipe

- Add separate broker executable/service, protected service identity, service SID and install-time service DACL.
- Add dedicated pipe, remote rejection, strict framing, actual client PID/session/token impersonation, revert-on-all-paths and signed-client verification.
- No SCM mutation endpoint initially; only QueryBrokerHealth and authenticated handshake.
- Add Windows-native token/pipe tests and exact-head CI.
- Gate: security review of broker token, service/pipe DACL and client authentication.

### C364 — Typed authorization and replay-safe transaction engine

- Add operation enums, strict decoder, transaction descriptors, signed package binding, challenge/expiry/boot epoch, persistent transaction ID dedupe and audit/journal.
- Add policy-owned fixed service name/path/account rules.
- Gate: parser fuzzing, replay/restart tests, unauthorized token zero-side-effect tests.

### C365 — Broker-owned service create/configure/start/stop/DACL

- Add CreateAgentService, ApplyAgentServiceDacl, StopAgentService, ConfigureAgentBinary, ConfigureAgentStatePath and StartAgentService.
- Move SCM native calls out of wd-agent ordinary command path.
- Verify effective access masks and DACL on real Windows tokens.
- Gate: persistent VM service creation, DACL and account-SID acceptance.

### C366 — Installer/recovery/migration integration

- Migrate Install-WeDecent.ps1, Recover-WeDecentInstall.ps1 and StateMigration.psm1 paths.
- Replace direct mutations and remove PowerShell fallbacks.
- Keep transaction and filesystem migration state synchronized; verify crash windows.
- Gate: all forward/rollback/recovery cases on persistent VM.

### C367 — Uninstall, hardening and full adversarial acceptance

- Migrate Uninstall-WeDecent.ps1, remove sc.exe fallback and verify purge/preserve boundaries.
- Add service interruption, broker restart, admin race detection, disk-full, malformed IPC and audit integrity tests.
- Gate: independent Windows security review and named operator acceptance.

C363-C367 are proposed work partitions, not completed assignments or claims of implementation. The Manager may consolidate them, but must preserve the gates and source-path coverage.

## 15. Open decisions and blockers

- A named persistent privileged Windows VM operator and infrastructure owner are still required.
- Windows virtual service account effective privileges, named-pipe impersonation rights, SCM manager CREATE_SERVICE access and service-object broker SID ACEs must be validated on supported Windows builds before locking implementation details.
- SCM manager CREATE_SERVICE is broad; no per-service-name manager right exists. The exact delegated SCM DACL and blast radius require review.
- Existing dedicated local service-account password provisioning must be integrated without moving secrets into command lines, environment or durable broker state.
- The production broker publisher/trust anchor and signed installer authorization policy must be provisioned through the established release trust process; no new trust anchor is invented by this design.
- Local Administrators/SYSTEM concurrent reconfiguration remains a documented trusted authority boundary; Windows provides no atomic conditional SCM mutation.
- Filesystem migration mutations remain partly in StateMigration.psm1. SCM brokering does not by itself close filesystem path/ACL TOCTOU races. C363 must decide the separately constrained filesystem worker boundary.
- Windows 1314 hosted probe remains NOT ESTABLISHED until executed on the persistent privileged VM.

## 16. Security review checklist and acceptance statement

- [ ] Separate broker service and service SID implemented.
- [ ] Broker binary, policy, journal and audit ACLs verified.
- [ ] Dedicated local-only named pipe with remote rejection.
- [ ] Actual client token impersonation and guaranteed revert.
- [ ] Token, session, elevation, integrity and process-image authorization.
- [ ] Strict signed transaction descriptor and package binding.
- [ ] Closed typed operation allowlist; no generic command/SCM API.
- [ ] Service, executable, account SID, state root and DACL independently verified.
- [ ] One-use challenge, expiry, boot epoch and durable replay rejection.
- [ ] Global broker serialization and durable transaction state machine.
- [ ] Every direct mutation path migrated; no PowerShell or sc.exe fallback.
- [ ] Secret-free durable audit of successes and failures.
- [ ] Crash/restart/rollback and uncertain-outcome recovery verified.
- [ ] Native adversarial zero-side-effect tests pass.
- [ ] Persistent privileged Windows VM acceptance complete with named operator.
- [ ] Independent security review approves the implementation.
- [ ] Exact candidate CI and Windows/Linux/macOS regression workflows pass.

**C362 disposition:** Architecture proposal published for implementation planning. No broker code was written. No security race is claimed solved. PR #209 remains open, draft and unmerged. No history was rewritten. No production signing, deployment or activation was performed.
