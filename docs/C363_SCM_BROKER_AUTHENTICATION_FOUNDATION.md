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