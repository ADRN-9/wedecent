# C337 — Privileged executor integration verification

**Repository:** ADRN-9/wedecent  
**PR:** #209 — expected to remain open, draft, unmerged  
**Assessment date:** 2026-11-27  
**Source branch:** `security/c324-verified-update-admission-recovery`

## Current disposition

- **Updater admission and transaction library:** implemented.
- **PowerShell executor process adapter:** implemented, with explicit already-elevated token requirement added in C337.
- **Updater-to-executor process integration tests:** added in C337; hosted CI is pending for this exact revision.
- **Shipped product runtime callsite:** NOT ESTABLISHED; no production caller for `DiscoveryClient.ApplyStable` or `PowerShellInstallerExecutor` was found in the inspected agent, core, desktop, or CLI entrypoints.
- **Privileged Windows acceptance:** NOT ESTABLISHED; persistent VM and named operator remain unprovided in repository evidence.

This task does not claim that the production updater is fully integrated. The code path is available as a library primitive but no shipped runtime invokes it.

## Source inspection — exact boundary

### Authorization and transaction path

At the inspected PR HEAD, the library path is:

1. `DiscoveryClient.DiscoverStableVerified` fetches the stable pair and root-authorized keyset, verifies canonical bytes/signatures and checks protected installed-version/sequence state.
2. `DiscoveryClient.ApplyStable` invokes recovery and committed cleanup adapters before discovery, stages the installer archive, then calls `StateStore.applyVerifiedManifest`.
3. `applyVerifiedManifest` revalidates the opaque `VerifiedManifest`, protected keyset epoch/digest, sequence and Authenticode callback while holding the update lock.
4. It extracts and re-verifies the package, persists pending then executing transaction state, and calls `InstallerExecutor.Execute`.
5. On executor failure it leaves the sequence unchanged and persists recovery-required state. On success it persists commit, advances installed version/sequence, clears pending state and invokes committed cleanup.
6. `PowerShellInstallerExecutor.Execute` validates the transaction/package binding and script/executable paths, then invokes the verified package's preflight, installer, and postflight scripts using direct `exec.CommandContext` with `-NoProfile -NonInteractive -ExecutionPolicy AllSigned -File`.

The executor does **not** use PATH lookup, shell command construction, or implicit UAC elevation. C337 adds a Windows access-token elevation check before Execute, Recover, and FinalizeCommitted. A non-elevated caller is rejected before the PowerShell process starts. Non-Windows builds reject this Windows-only executor; test fixtures can explicitly inject a test elevation predicate from package-internal tests.

### Critical missing product integration

Inspection of these exact PR-head files found no updater wiring:

- `cmd/wd-agent/main.go`
- `cmd/wd-agent/service_windows.go`
- `cmd/wd-core/main.go`
- `cmd/wd/main.go`
- `cmd/wd-ui/main.go` and Windows UI bootstrap entrypoints

The service install path configures a dedicated local standard account. The service's normal `service run` command calls `runAgent`; it does not construct update state, a root-pinned `DiscoveryClient`, an Authenticode verifier, or a `PowerShellInstallerExecutor`.

The Windows installer itself checks for an elevated Administrator token before modifying Program Files/SCM state. The PowerShell executor does not request elevation; it must already be launched in a trusted elevated process. A standard-account Windows service cannot satisfy this requirement. No supported authenticated privileged broker, service IPC command, elevated UI handoff, or other product callsite is present in the inspected entrypoints.

Therefore the current `ApplyStable -> PowerShellInstallerExecutor -> Install-WeDecent.ps1` sequence is a valid library-level path, not an operational shipped update path. Do not treat the process integration fixture as evidence of an actual service upgrade.

## C337 code and test changes

1. `PowerShellInstallerExecutor.Execute`, `Recover`, and `FinalizeCommitted` now require an already elevated process context. Windows checks the current process token elevation state; it fails closed without attempting implicit UAC. Non-Windows builds reject use of the Windows PowerShell executor.
2. Added a negative test proving a non-elevated executor is rejected before its process runner is invoked.
3. Added process-boundary integration coverage that drives `StateStore.applyVerifiedManifest` and public `DiscoveryClient.ApplyStable` through `PowerShellInstallerExecutor` using a real child-process fixture rather than the injected command-runner hook. The tests verify the preflight/install/postflight order, transaction ID and digest arguments, committed cleanup invocation, and protected sequence transition.
4. Added a child-process failure case proving the sequence remains unchanged and the transaction remains in recovery-required state.

These integration tests execute a helper process in place of PowerShell. They prove that the updater API invokes the configured executable with the expected arguments and propagates process failure; they do not execute the actual installer scripts, perform an elevation transition, mutate Program Files, create/replace SCM services, or prove the shipped application calls this library.

## Trust and least-privilege assessment

- **Executable identity:** an absolute regular non-symlink PowerShell executable path is required; PATH lookup is forbidden. The code does not currently pin a PowerShell binary digest or publisher at runtime. The Windows platform path and system directory ownership therefore remain part of the host trust boundary and must be checked by privileged deployment acceptance.
- **Script identity:** package scripts are admitted through verified package content and Authenticode policy before executor invocation; script paths are checked as regular non-symlink files.
- **Staging:** package extraction is callback-scoped and re-hashed/re-verified immediately before executor invocation. The process receives the extracted directory path and transaction-bound digests. Actual ACL/owner and reparse-point behavior on the persistent Windows install/staging volumes remains unproven.
- **Authorization:** the transaction must be executing and its version/package digest must match the verified package. The PowerShell script receives transaction ID, package digest, manifest digest, previous version and sequence.
- **Privilege:** explicit already-elevated process requirement; no silent UAC prompt or fallback. The actual product mechanism for obtaining that elevated context is missing.
- **Rollback:** the installer owns the five-binary backup/rollback transaction. Hosted synthetic recovery tests from the previous cycle cover restoration and fail-closed recovery. No C337 claim is made about real privileged rollback.
- **Failure:** failed process invocation is returned as an installer failure; transaction state remains recovery-required and anti-rollback sequence is not advanced. Recovery unknown/error and cleanup failure block further updates.

## Evidence classification

| Evidence class | Result | Limits |
|---|---|---|
| Source inspection | Completed | No shipped callsite found; no privileged broker found |
| Library unit tests | Existing coverage | Not an end-to-end product integration |
| New process integration tests | Added; exact-HEAD CI pending | Child process fixture, not real PowerShell/elevation |
| Hosted Windows CI | Pending for C337 HEAD | Ephemeral runner; no persistent disk/reboot acceptance |
| Persistent privileged Windows VM | NOT ESTABLISHED | No VM identity or named operator evidenced |
| Actual shipped service update | NOT ESTABLISHED | No production callsite or privileged handoff |
| Five-binary actual service upgrade/rollback | NOT ESTABLISHED | Needs the real privileged VM and product path |

## Outstanding engineering work

A production integration must choose and implement one supported, auditable privilege handoff:

- **Elevated desktop handoff:** a signed, narrowly scoped update helper launched through explicit UAC consent by the interactive user, with authenticated IPC back to Local Core and no bearer secrets on command lines; or
- **Dedicated privileged broker/service:** a separate tightly ACLed service with authenticated caller identity, bounded request schema, package/transaction binding, anti-replay, protected staging, audit, and a non-admin caller contract.

The current WeDecent agent service runs under a dedicated standard account. Simply invoking PowerShell from that service or setting `Verb=RunAs` in a Session 0 service is not an acceptable solution. Do not elevate the existing general-purpose agent service or grant its normal account broad Program Files/SCM write access as a shortcut.

The selected handoff must be exercised from the actual product entrypoint, not only from package tests. Tests must prove denied callers, wrong signer/package, path substitution/reparse points, replay, non-elevated caller, executor process failure, interrupted process, rollback failure, and post-commit cleanup failure all fail closed while preserving five-binary backups.

## Human/infrastructure dependencies

- ADRN-9 remains the accountable infrastructure owner.
- A named individual operator and persistent privileged Windows VM identity/access are not evidenced.
- The VM must be isolated from production signing/publishing systems and use test-only signing/trust material. It must permit real process termination, same-disk reboot, SCM/ACL inspection, and five-binary before/after digest capture.
- The actual Windows update root public-key pin and Authenticode publisher policy are not proven provisioned for production.

## Release controls

PR #209 must remain open, draft, and unmerged. Do not sign production artifacts, publish manifests, deploy, or modify production trust anchors as part of C337. Hosted CI success is not production acceptance.
