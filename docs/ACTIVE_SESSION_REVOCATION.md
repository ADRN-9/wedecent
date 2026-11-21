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

## Worker/Durable Object relay cleanup

An established relay is paired inside the `DeviceRelay` Durable Object. When the target agent's WebSocket closes because its local TLS session was revoked, the Durable Object's `webSocketClose` handler closes only the paired client socket. Other agent/client pairs remain open.

The Go integration test runs the production `WaitWebRelaySession` and `WebRelayDialer` adapters, the agent's `ServeParkedRelayConn`, inner TLS, and trust revocation through a framed WebSocket bridge implemented by an `httptest` server. It proves that the Go adapter's abort closes the established socket without waiting on its write mutex. The bridge is a test relay, not the deployed Worker runtime.

The Node regression imports the production Worker `fetch` handler and `DeviceRelay` Durable Object class. It exercises signed ticket/grant authorization, replay rejection, pairing, peer-close handling, and preservation of another pair. Its Worker namespace, Durable Object storage, and WebSocket pairs are in-memory test doubles; it is a component-level test, not a Cloudflare Workers runtime integration. CI validates the Worker bundle and configuration with Wrangler dry-run, but does not start a local or deployed Worker runtime and connect a Go agent to it. A cross-process Go-to-Worker/Durable Object revocation test therefore remains outstanding.

## Verification commands

- `go test ./internal/session ./internal/trust ./internal/transport -count=1`
- `go test -race ./internal/session ./internal/trust -count=1`
- `go test ./...`
- `go test -race ./...`

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
