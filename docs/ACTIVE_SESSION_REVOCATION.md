# Active terminal-session revocation remediation

This document records the revocation, admission, connection-grant timing, relay cleanup, and repository-governance boundaries covered by PR #179.

## Session revocation and transport shutdown

The active-session registry retains the original transport `net.Conn`. Revocation uses an explicit abort path: it recursively unwraps `*tls.Conn` via `NetConn()`, and WebSocket relay connections expose `Abort()` to bypass the WebSocket write mutex and unwrap their outer TLS transport. It never sends a graceful TLS `close_notify` or waits for a WebSocket close frame. The underlying socket is closed before PTY/ConPTY cleanup and the `terminal.session_terminated` audit event.

The watcher snapshots active sessions while holding `activeSessionsMu`, releases that mutex, and only then reads the trust snapshot. The admission lock order is:

1. trust-store file lock;
2. trust-store mutex;
3. active-session registry mutex.

No code path may hold `activeSessionsMu` while acquiring the trust-store lock. Per-session termination is dispatched independently so a blocked session cannot serialize cleanup of another session.

## Termination completion and audit outcomes

The active-session cleanup registration has a readiness barrier. Revocation aborts the raw transport immediately, then waits for PTY/session initialization to either register its cleanup or finish without one. This prevents a revocation that races with PTY startup from recording termination success before the newly created PTY is closed. Each session's abort and cleanup execute independently of other sessions.

Transport-abort and resource-cleanup errors are retained and returned by synchronous termination/finish paths; asynchronous watcher termination logs them. Legacy PTY close, typed terminal PTYs, and typed file transfer children return cleanup errors to the session owner. A terminal.session_terminated event is marked failed if transport abort or cleanup fails. terminal.session_closed is appended only after finish/cleanup completes and is also marked failed when finish reports an error. The termination event therefore precedes the corresponding session-closed event.

Typed-stream admission treats an acceptance-frame write or write-deadline failure as terminal: the raw transport is aborted inside the admission reservation, the reservation is removed, and no follow-up error frame is attempted on a possibly blocked transport.

## Identity-certificate concurrency

Identity certificate creation and repair write and sync a temporary file before publishing it. First creation uses an atomic hard link that cannot replace an existing path; repair verifies that the existing regular file has not changed before atomically renaming the complete replacement. A concurrent winner is reloaded and strictly validated rather than exposing a partially written final certificate. The identity private key and Ed25519 device identity are not rotated by certificate repair. Concurrent create and repair regressions cover 32 simultaneous Ensure callers; their passing status is recorded only against the exact CI-tested commit.

## PTY admission boundary

Legacy PTY sessions first reserve admission through `Trust.WithTrustedPeer`. Only after the serialized reservation succeeds may `startTerminal` create a PTY or launch the shell. If revocation wins before reservation, the authorization callback fails and no shell initialization command runs.

If the reservation wins first, the session is registered for revocation before PTY startup. A later revocation closes its raw transport immediately, waits for a cleanup handle if PTY startup is still in progress, then closes the PTY before recording termination. An already terminated reservation does not send session acceptance. Typed-stream sessions continue to reserve the outer session before a terminal stream can create its PTY.

## Connection-grant expiration

`issue_connection_grant()` obtains `FOR SHARE` locks on the client and target device rows before capturing one `clock_timestamp()`. That value is reused for delegated `terminal.connect` expiration validation, `issued_at`, and `expires_at`. This avoids transaction-start `now()` incorrectly preserving an access grant that expires while issuance is waiting for a device row lock.

The deterministic database regression uses two independent `psql` processes against the explicitly disposable local Supabase PostgreSQL instance. One holds the target device row lock while the grant issuer is observed waiting in `pg_stat_activity`; the harness verifies the permission is still valid when the wait begins, allows it to expire, then releases the lock and verifies issuance fails without inserting a grant. An `EXIT` trap terminates outstanding sessions and removes fixtures after success or failure. The test uses no `dblink` functions and changes no database privileges. The pgTAP regression also asserts that only `service_role` can execute the issuer RPC.

## Worker/Durable Object relay process integration

The cross-process Go harness in `scripts/cloudflare-worker-process-e2e/main.go` starts a local Wrangler Worker runtime with SQLite Durable Object persistence, an independent Go `wd-agent` process, and two independent Go `wd` client processes. It pairs both clients using separate single-use pairing secrets, issues distinct `terminal.connect` grants, and establishes both terminal sessions through the Worker's WebSocket relay and Durable Object.

The process-level assertions cover:

- successful relay authorization and session-open audit outcomes for both clients;
- replay rejection after the first use of a connection grant;
- selective revocation of client A while client B remains connected and can still execute terminal input;
- successful `trust.client_revoke`, `terminal.session_terminated`, and `terminal.session_closed` audit outcomes for client A;
- absence of session termination/closure for client B during client A's revocation; and
- retrieval of both clients' validation/consumption evidence after stopping and restarting Wrangler with the same Durable Object persistence directory.

The CLI `wd connect` used by this process harness currently exercises the legacy terminal protocol, not typed streams. Accordingly, the process test asserts session-level authorization/open/termination/close events; typed stream lifecycle and concurrent typed close-reason behavior remain covered by the dedicated Go session regressions.

Only the disposable E2E agent binary is built with the `wedecent_smoke_test` build tag so that it may verify evidence against the local loopback Worker origin. The tag is excluded from release builds; production binaries retain the strict `https://relay.wedecent.com` authorization-origin allowlist.

The Node Worker/DO regression remains a separate component-level test with in-memory runtime doubles. It complements the real local Worker/SQLite Durable Object process test and is not represented as a substitute for it.

## Verification commands

- `go test ./internal/session ./internal/trust ./internal/transport -count=1`
- `go test -race ./internal/session ./internal/trust -count=1`
- `go test ./...`
- `go test -race ./...`
- `go test -race ./internal/session -run '^TestTypedSessionCloseReasonConcurrentReadCompletionAndAsyncRevocationCleanup
The session regression set includes TestRevocationDuringPTYStartupAbortsBeforeAcceptance, TestTypedStreamAdmissionWriteFailureAbortsWithoutErrorFrame, TestTerminationPropagatesAbortAndPTYCleanupErrors, TestRevocationPTYCleanupFailureMarksTerminationAndCloseAuditFailed, and the blocked WebSocket/TLS 1.3 KeyUpdate tests.
- `cd cloudflare/relay-worker && npm test` (Worker/DO component tests with in-memory runtime doubles)
- Wrangler `deploy --dry-run` (bundle/configuration validation, not runtime revocation)
- `supabase test db`
- `./scripts/test-connection-grant-expiration.sh` (separate-session lock-wait regression)

These are validation requirements. Results must be attributed to the exact tested commit and CI run; source changes alone are not proof.

## Repository governance observations (2026-11-21)

The repository-level active ruleset `Protect main` (ID `21507567`) targets only the default branch. Its pull-request rule currently sets:

- `required_approving_review_count = 0`;
- no required reviewers;
- code-owner review disabled;
- last-push approval disabled;
- stale-review dismissal disabled.

Its required status checks are `route-capability-client`, `route-e2e`, `linux`, `windows-agent`, `windows-release`, `relay-worker`, `control-plane`, and `supabase-db`. It does not require `macos-agent` or the Linux, Windows, and macOS desktop-shell jobs (`linux-tauri-check`, `windows-tauri-check`, `macos-tauri-check`).

The visible ruleset does not target PR #179's stacked feature branch. The classic branch-protection endpoint returned HTTP 403 to the repository integration, so any additional classic protection could not be independently verified. No ruleset or repository-wide protection setting was changed by this remediation.

Before merging the stacked production branch, repository administrators should require at least one independent approval and require all supported platform gates, including macOS agent and all three desktop-shell jobs. This PR remains draft and unmerged pending that independent review and governance remediation.
 -count=50`
- `go run ./scripts/cloudflare-worker-process-e2e`

The session regression set includes TestRevocationDuringPTYStartupAbortsBeforeAcceptance, TestTypedStreamAdmissionWriteFailureAbortsWithoutErrorFrame, TestTerminationPropagatesAbortAndPTYCleanupErrors, TestRevocationPTYCleanupFailureMarksTerminationAndCloseAuditFailed, and the blocked WebSocket/TLS 1.3 KeyUpdate tests.
- `cd cloudflare/relay-worker && npm test` (Worker/DO component tests with in-memory runtime doubles)
- Wrangler `deploy --dry-run` (bundle/configuration validation, not runtime revocation)
- `supabase test db`
- `./scripts/test-connection-grant-expiration.sh` (separate-session lock-wait regression)

These are validation requirements. Results must be attributed to the exact tested commit and CI run; source changes alone are not proof.

## Repository governance observations (2026-11-21)

The repository-level active ruleset `Protect main` (ID `21507567`) targets only the default branch. Its pull-request rule currently sets:

- `required_approving_review_count = 0`;
- no required reviewers;
- code-owner review disabled;
- last-push approval disabled;
- stale-review dismissal disabled.

Its required status checks are `route-capability-client`, `route-e2e`, `linux`, `windows-agent`, `windows-release`, `relay-worker`, `control-plane`, and `supabase-db`. It does not require `macos-agent` or the Linux, Windows, and macOS desktop-shell jobs (`linux-tauri-check`, `windows-tauri-check`, `macos-tauri-check`).

The visible ruleset does not target PR #179's stacked feature branch. The classic branch-protection endpoint returned HTTP 403 to the repository integration, so any additional classic protection could not be independently verified. No ruleset or repository-wide protection setting was changed by this remediation.

Before merging the stacked production branch, repository administrators should require at least one independent approval and require all supported platform gates, including macOS agent and all three desktop-shell jobs. This PR remains draft and unmerged pending that independent review and governance remediation.
