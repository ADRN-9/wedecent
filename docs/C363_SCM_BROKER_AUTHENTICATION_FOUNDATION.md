# C363 — Windows SCM broker authentication foundation

**Status: PARTIAL IMPLEMENTATION; NOT READY FOR SECURITY REVIEW OR MUTATION ENABLEMENT**

The initial implementation adds `internal/scmbroker`:
- Platform-independent length-prefixed JSON request decoder with hard frame limits, UTF-8 validation, duplicate-key rejection, unknown-field rejection, trailing-data rejection and a two-operation read-only allowlist (`health`, `query`).
- Unit tests for allowed request parsing, operation rejection, duplicate/unknown fields, trailing data, oversized/truncated frames and response framing.
- Windows-only local named-pipe creation at `\\.\pipe\WeDecent.SCM.v1`, protected DACL limited to SYSTEM and Administrators, `PIPE_REJECT_REMOTE_CLIENTS`, kernel-reported client PID lookup, named-pipe client impersonation, thread-token opening, token elevation check, process-token/user-SID comparison and deferred `RevertToSelf` check that overrides authorization on revert failure.
- Non-Windows unsupported stub.

## Security status and deliberate fail-closed behavior

This is not yet an operational authenticated broker. `authenticateClient` currently returns false after its partial token checks. This is deliberate: publisher pinning, full administrator-group and high-integrity validation, stable process-image identity, protocol dispatch, service-host lifecycle and production installation/bootstrap flow have not been implemented/reviewed. The pipe therefore does not dispatch even read-only requests. No SCM mutation API exists in this package.

The Windows implementation is an initial code draft and has NOT been compiled or executed in this task. It must not be deployed. In particular:
- `ImpersonateNamedPipeClient`/`RevertToSelf` behavior and every failure path need native Windows tests.
- The client PID is obtained from the pipe, but process creation/reuse races and stable image-handle binding still need closure.
- Publisher verification must use native Authenticode/WinTrust verification plus an exact provisioned signer identity, not merely any trusted signature. Until a product signer thumbprint/publisher policy is provisioned and validated, authorization remains denied.
- Token checks still need enabled Administrators membership, full elevation type, high mandatory integrity, non-AppContainer and interactive local session validation.
- The named-pipe service DACL and default service-object DACL/bootstrap installation window need persistent Windows VM acceptance.
- A broker Windows service host using an independent service identity/service SID is not yet installed or wired to SCM service dispatch.
- The current `Run` pipe loop is a low-level listener prototype, not a production service lifecycle. Shutdown, cancellation, multiple-client handling, pipe instance ownership and resource exhaustion controls remain incomplete.

No credential is accepted on the command line, and this foundation has no credential logging or audit output. Do not add SCM mutation operations until the missing authentication and publisher review gates pass.

## Service identity / default-DACL installation requirements

The intended service name is `WeDecentSCMBroker`, with a dedicated virtual service account and unique service SID, separate from `WeDecentAgent`. The installer must provision the broker executable, policy, journal and audit directories under SYSTEM/Administrators-owned protected roots; configure the broker service DACL; enable the service SID; and verify effective token groups/privileges and all file/pipe ACLs on supported Windows builds.

Do not assume a service SID is automatically enabled or that a virtual account has the SCM manager rights required for future service creation. Do not grant the agent identity broker access. Do not use SYSTEM as an unreviewed shortcut.

For the pipe, the initial DACL is protected and grants only SYSTEM and BUILTIN\\Administrators. `PIPE_REJECT_REMOTE_CLIENTS` is set. The pipe is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`; installer startup must ensure no pre-existing pipe squatting, and startup must fail if first-instance creation fails. A named-pipe DACL does not replace impersonated-token authorization.

For the future agent service, `CreateServiceW` cannot atomically set its service-object DACL. The broker must create the fixed service disabled, apply and verify the intended DACL while retaining the service handle, and prove on persistent Windows VMs that the default descriptor denies untrusted mutation rights during the interval. If that cannot be demonstrated, bootstrap must be redesigned.

## Verification status

No Go tests, Windows builds, GitHub Actions workflows, persistent VM tests or security reviews were run by this code-writing operation. Cross-compilation and exact-commit CI remain mandatory. No SCM mutation operations, production signing, deployment or activation were added.

## C364 gate

Complete the service-host lifecycle, process-image handle binding, native exact-publisher verification, full token/session/elevation/integrity authorization, strict request/response dispatch, cancellation/connection limits, and Windows-native adversarial tests. Only after independent review of those results may a later task add the first narrowly scoped SCM query or mutation endpoint.

## C363 follow-on implementation (2026-11-28)

The follow-on work corrected two Windows build errors reported by the first exact-head CI run (wrong return arity for `DisconnectNamedPipe`; unavailable `syscall.GetCurrentThread`) and corrected the pipe path to the canonical local form `\\\\.\\pipe\\WeDecent.SCM.v1`. The pipe DACL now includes the deterministically derived SID for the fixed service name `WeDecentSCMBroker`, in addition to SYSTEM and BUILTIN\\Administrators. The service installer must still enable that service SID in the broker token before this ACE is effective.

Caller token checks now include:
- elevated token flag;
- enabled BUILTIN\\Administrators membership via `CheckTokenMembership`;
- full elevation type;
- rejection of AppContainer tokens;
- High-or-higher mandatory integrity RID;
- matching user SID between impersonation token and kernel-reported client process token.

Impersonation and reversion are factored into a helper with regression tests proving reversion occurs after both successful and failed authorization, and that reversion failure overrides an otherwise successful authorization. Windows-only tests cover the fixed service SID derivation, invalid pipe handle fail-closed behavior, local pipe name, and differing client user SIDs.

**Still deliberately unavailable:** authentication never returns authorized=true; the broker does not read/dispatch IPC requests. Exact Authenticode WinVerifyTrust publisher verification and provisioned signer thumbprint policy are not present. Repository search found no established broker publisher thumbprint/policy to safely pin. A dedicated broker service executable, service configuration/install transaction, service SID enablement, protected policy/audit directories, graceful shutdown/restart and persistent Windows VM cross-user process tests are also absent. No SCM mutation is exposed.

The first exact-head run for commit `391d067fbc1e54b1f63a951719b01d3c1d7692e4` failed as follows:
- Windows `go test ./...` failed to compile the new package because of the two Windows API call issues corrected in follow-on commits.
- Linux CI failed its repository-wide gofmt gate because the new protocol source/tests were not formatted; these files have since been formatted.
- Desktop shell and updater security workflow succeeded on that earlier commit.

The follow-on exact-head CI for `a5bf490fcb4b75b876557101115022d6422db506` was queued/pending when this addendum was written; no passing outcome is claimed. The independent local protocol/impersonation helper tests passed using the copied package source with Go 1.23.2, but this is not a substitute for the repository's Go 1.27 Windows CI.


## C363 continuation — dedicated entrypoint and lifecycle hardening

Follow-on commits after the earlier report added:
- `cmd/wd-scm-broker` Windows and non-Windows entrypoints. The Windows entrypoint uses the existing Windows SCM dispatcher under the fixed service name `WeDecentSCMBroker`.
- A cancellable broker run loop (`RunContext`) using bounded 100 ms connection polling so the service context can stop accepting new clients. It still dispatches no IPC request.
- A Windows test for already-cancelled service startup and cancellation before pipe connection.
- `runtime.LockOSThread` around named-pipe impersonation through `RevertToSelf`. Windows impersonation is thread-scoped; without this, Go goroutine migration could cause reversion to occur on a different OS thread. The helper's defer ordering reverts before unlocking the thread.

These are source-level foundations only. The new executable is not yet included in the Windows release/installer payload, registered by the installer, or provisioned with its virtual service account/service SID. The service has no installation, update, uninstall or recovery path. The named-pipe loop is not a completed broker service lifecycle acceptance test; cancellation while blocked on the pipe is not yet proven by an actual SCM stop/restart test.

No Authenticode verifier or protected publisher-policy loader was added. In particular, the broker does not call WinVerifyTrust, does not inspect the signer certificate against an exact allowlisted thumbprint, and does not verify the client process image/file identity. The caller authentication path continues to return unauthorized unconditionally. SCM mutation dispatch remains disabled.

### Exact-head workflow reconciliation

At HEAD `e5fa253dfc228acb046fad894d9a4367bde90456`, tree `2436f1e6d4e4587bb1f33897a1099c6b91e897ab`, the fresh workflow IDs were:
- CI: `46128164228` and `46128159786`
- Desktop shell: `46128164239` and `46128159835`
- C324 updater security: `46128164242` and `46128159799`

The later workflow instances were queued/pending when last inspected; earlier instances were still running when subsequent commits caused cancellation. These are not passing full CI results. An earlier exact-head updater run at `24292cdc...` passed (runs `46127578542` and `46127582510`), but it predates the new broker entrypoint/lifecycle code and is not exact-head verification for this addendum.

For the exact-head run on `1ae7453...`, CI `46128071036` was cancelled while its Windows agent job `140927046011` had completed the updater integration test and Go toolchain setup, but the diagnostic release build was cancelled and all later native agent/integration steps were skipped. Linux job `140927202939` was cancelled during the disposable R2 CAS step; all subsequent Linux formatting, all-package, vet, race and smoke tests were skipped. macOS job `140927046124` was still running. These are incomplete runs, not passes.

No Windows cross-user isolation, service SID provisioning, SCM race closure, broker image verification, actual broker stop/restart, or persistent Windows VM acceptance is claimed.


## C363 continuation — exact-head CI reconciliation (2026-11-28)

The branch was re-fetched before this update. The starting C363 head `f42035a3e8979f85d6ef6e11fa545245ea280f3b` and tree `9670a01f43d23876b5021ae4cdaff4d3f3cb9389` were live; PR #209 remained open, draft and unmerged.

At that exact head:
- CI `46128909130` and `46128912906` both completed **FAILURE**. In both, Windows agent was the only failing job; Linux, macOS agent, Windows release, Supabase, relay-worker, control-plane, route-capability-client and route-e2e completed successfully.
- Desktop `46128909205` and `46128912926` both completed **SUCCESS**, with Linux, Windows and macOS desktop jobs passing.
- Updater `46128909121` and `46128912900` both completed **SUCCESS**.

The Windows failure was not a runtime security test failure. Both Windows agent logs showed:
`internal/scmbroker/broker_windows_test.go:6:2: "errors" imported and not used`.
All package tests reached the compiler; the native Windows agent test did not run. Subsequent Windows service-state ancestor ACL, hostile-owner rejection, distinct service SID provisioning, native binary build and UI command checks were skipped. The temporary distinct test service account was successfully removed. The prior `GetCurrentThread` compilation issue was resolved.

Commit `ce71224e58a4190e9d99a1542ac09a1b51e1248f` removes the unused import only. This preserves the previous commit ancestry. It does not change broker behavior or enable authentication/dispatch.

Fresh exact-head workflow runs for `ce71224e58a4190e9d99a1542ac09a1b51e1248f`:
- CI: `46138445755` and `46138441383`
- Desktop: `46138445838` and `46138441367`
- Updater: `46138445772` and `46138441363`

Both updater runs completed **SUCCESS**. At the time of this documentation update, both CI and both desktop runs remained in progress. Early completed CI jobs included relay-worker, control-plane, route-capability-client and route-e2e; other platform jobs were still running. No full exact-head CI or desktop result is claimed for this commit yet.

### Publisher trust anchor and protected storage requirements

The broker must not derive a publisher thumbprint from the current client executable, an environment variable, request data, an unsigned manifest, or a certificate chain selected at runtime. The approved publisher thumbprint is a production trust anchor and must be provisioned from the actual release publisher certificate through an independently authenticated operator-controlled channel. It is not present in the repository evidence and must not be guessed.

The intended protected policy is a fixed-schema local file under a broker-owned ProgramData directory. The installer must create it before service startup, protect the directory and file with a protected DACL, and grant write access only to SYSTEM and local Administrators; the broker service SID receives read access only. The broker must reject reparse points, non-regular files, unexpected owner/DACL, malformed schema, unknown fields, duplicate JSON keys, non-canonical thumbprints and multiple ambiguous publisher entries. The policy must not be mutable by the agent service account, interactive users, or broker clients. Trust-root changes require an explicit signed release/rotation procedure and audit evidence. No policy loader or WinVerifyTrust implementation is claimed in this commit.

### Remaining exact C363 acceptance gates

- Native Authenticode verification (WinVerifyTrust) plus signer-certificate thumbprint extraction and exact comparison against the protected publisher policy.
- Client process image identity bound to the pipe client process, with handle lifetime and replacement-race analysis; matching user SID alone is insufficient.
- Dedicated broker service installation, protected executable/policy/journal/audit directories, explicit service SID configuration, and runtime verification that the expected service SID is enabled in the broker token.
- Real Windows cross-user pipe tests (authorized elevated signed installer versus standard user, service account, same-user unsigned executable, remote client, AppContainer, stale/reused PID, and impersonation failure/revert failure).
- SCM stop/restart/interruption tests on a persistent privileged Windows VM, including pipe cancellation and recovery.
- Adversarial concurrent SCM mutation testing. SCM does not provide an atomic compare-and-mutate primitive; broker serialization cannot prevent concurrent writes by Local Administrator/SYSTEM. This limitation remains explicit and the broker must revalidate before and after every operation, abort on mismatch, and never claim race elimination against an equally privileged administrator.
- The broker remains absent from the Windows installer payload and no production mutation endpoint is enabled.

The GitHub hosted Windows runner can run elevated integration tests in its ephemeral VM, but the required persistent privileged VM and independently provisioned production publisher trust anchor are not available in repository evidence. These are real acceptance dependencies, not reasons to guess credentials or weaken fail-closed behavior.


## C363 continuation — Authenticode and service identity work (2026-11-28)

### Exact requested workflow reconciliation at starting HEAD

The branch was re-fetched at starting HEAD `ef85bb8f5b8a0f1e61ae1ce75cf94f5c6d41aac2`, tree `13af59957da8d6e94d89a00cbdda6be05567dc8e`. PR #209 remained open, draft and unmerged.

- CI `46138590682`: **SUCCESS**. All jobs passed, including Windows agent, Windows release, Linux, macOS agent, Supabase, relay worker, control plane, route-capability client and route E2E. The Windows agent's native test, actual state ACL, hostile ancestor owner, service SID provisioning, cleanup, native binary build and UI command checks all passed.
- CI `46138585990`: **SUCCESS** with the same complete job matrix and Windows native acceptance steps passing.
- Desktop `46138590745`: **CANCELLED**. Linux and macOS checks passed; Windows Tauri shell check was cancelled.
- Desktop `46138585986`: **CANCELLED**. Linux and macOS checks passed; Windows Tauri shell and macOS job were cancelled before final completion (macOS later reported success in job detail, but the workflow itself remained cancelled).

Thus the two requested CI runs are fully successful at `ef85bb8...`; neither requested desktop workflow is a completed pass. These runs predate the publisher verification commits below.

### New source changes

- `internal/scmbroker/publisher_windows.go`: added native `WinVerifyTrust` verification using the generic Authenticode policy, chain revocation checking, no UI, signer certificate extraction through the WinTrust provider chain, and SHA-1 thumbprint extraction. The executable is opened read-only without write/delete sharing, reparse points are rejected, and the same open file handle is supplied to WinVerifyTrust to reduce replacement races.
- The pipe client's kernel-reported process is held open while querying its executable path and validating the signature. PID reuse is additionally constrained by matching the impersonation token's user SID with the primary process token.
- `internal/scmbroker/publisher_policy_windows.go`: added strict bounded policy parsing, duplicate-key and unknown-field rejection, uppercase 40-hex thumbprint validation, and exact protected owner/DACL checks for the product root, broker directory and policy file. Missing or malformed policy fails closed.
- `authenticateClient` now requires a valid Authenticode signature and exact match to the protected publisher thumbprint. It still returns unauthorized after those checks: additional IPC-specific authorization has not been established and no request is dispatched.
- `internal/winservice/service_windows.go`: added `EnableServiceSID`, which configures the unrestricted service SID through SCM and reads the configuration back for verification.
- `RunContext` now verifies that the dedicated broker service SID is actually enabled in the current process token before creating the pipe. A cancelled context exits before this service-only check.
- Added Windows-only tests for malformed publisher policies, invalid/missing executable paths, invalid process handles and absent policy fail-closed behavior.

### Critical provisioning and implementation gaps

The production publisher thumbprint remains intentionally absent. The policy path is `%ProgramData%\\WeDecent\\broker\\publisher-policy.json`; it requires a protected product root, broker directory and policy file with owner Administrators, SYSTEM/Administrators full control, and broker service SID read-only access. The installer does not yet create this directory/policy, and the dedicated broker executable is not yet part of the Windows release bundle or installer payload. Consequently the new broker will fail closed at startup until provisioning exists.

The WinTrust code and policy loader have been committed but **have not yet received completed exact-HEAD Windows CI**. The policy's exact SDDL assumptions, WinTrust structure layouts, provider-chain extraction, file-handle behavior and revocation behavior require hosted Windows execution and focused adversarial review. The added tests are not evidence of a passing Windows build until CI completes.

The service SID enable/verify helper is not yet wired into a dedicated broker install/upgrade/uninstall transaction. The installer currently installs the existing WeDecent agent, not `WeDecentSCMBroker`. Service account selection, service binary ACLs, broker service object DACL, policy creation, service SID enablement and rollback need one installer-owned transaction. The persistent privileged Windows VM remains necessary for stop/restart/interruption and cross-user tests.

No SCM mutation dispatch has been enabled. No publisher thumbprint has been guessed, copied from the updater trust root, or accepted from an untrusted request. SCM concurrency against an equally privileged administrator remains an architectural limitation; no code here claims to eliminate that race.

### Exact-head verification after these commits

Latest branch HEAD: `f4bf6f935e086684be40431451a1c3cbc367cfa0`, tree `8ba9356cd88f2b2c3d25da67966fdc4b9ba312de`, parent `993ec9541e171fc37ba949d73a7cc675b96d5ac4`.

Fresh runs triggered for that exact HEAD:
- CI: `46139483162`, `46139478320`
- Desktop: `46139483175`, `46139478243`
- Updater: `46139483166`, `46139478296`

At documentation time these workflows were queued, pending or in progress. The updater run `46139478296` was still running. No exact-head pass is claimed for `f4bf6f9...`. Later commits will naturally make these runs non-exact-head for the branch, so every source correction requires another fresh run.
