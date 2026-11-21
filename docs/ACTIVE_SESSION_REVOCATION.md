# Active terminal-session revocation and audit guarantees

This document records the terminal-session revocation, typed-stream cleanup, Worker/Durable Object integration, verification, and repository-governance evidence in the current WeDecent PR stack.

## Session revocation and transport shutdown

The active-session registry retains the original transport net.Conn. Revocation uses an explicit abort path: it recursively unwraps *tls.Conn via NetConn(), and WebSocket relay connections expose Abort() to bypass the WebSocket write mutex and unwrap their outer TLS transport. It does not send a graceful TLS close_notify or wait for a WebSocket close frame. The underlying socket is closed before PTY/ConPTY cleanup and the terminal.session_terminated audit event.

The watcher snapshots active sessions while holding activeSessionsMu, releases that mutex, and only then reads the trust snapshot. The admission lock order is:

1. Trust-store file lock.
2. Trust-store mutex.
3. Active-session registry mutex.

No code path may hold activeSessionsMu while acquiring the trust-store lock. Per-session termination is dispatched independently so a blocked session cannot serialize cleanup of another session.

## Termination completion and audit outcomes

The active-session cleanup registration has a readiness barrier. Revocation aborts the raw transport immediately, then waits for PTY/session initialization to either register its cleanup or finish without one. This prevents a revocation that races with PTY startup from recording termination success before the newly created PTY is closed. Each session's abort and cleanup execute independently of other sessions.

Transport-abort and resource-cleanup errors are retained and returned by synchronous termination/finish paths; asynchronous watcher termination logs them. Legacy PTY close, typed terminal PTYs, and typed file-transfer children return cleanup errors to the session owner. A terminal.session_terminated event is marked failed if transport abort or cleanup fails. terminal.session_closed is appended only after finish/cleanup completes and is also marked failed when finish reports an error. The termination event therefore precedes the corresponding session-closed event.

Typed-stream admission treats an acceptance-frame write or write-deadline failure as terminal: the raw transport is aborted inside the admission reservation, the reservation is removed, and no follow-up error frame is attempted on a possibly blocked transport.

## Typed terminal stream cleanup and audit semantics

A typed stream is logically closed when it is removed from the stream registry and its stream-state entry is closed. PTY cleanup is attempted immediately after that logical transition. The terminal.stream_closed audit event is emitted after the PTY close attempt:

- Outcome=success means the PTY cleanup completed successfully.
- Outcome=failed means the logical stream is closed but its PTY resource cleanup returned an error.
- The logical termination reason (for example, client_revoked, peer_close, or process_exit) is preserved independently of the cleanup outcome.

The typed terminal server retains PTY cleanup errors even after a child stream has been removed from the stream map. Parent-session cleanup waits for any in-flight stream-close operation and its audit callback before it reports termination. This prevents a race in which a concurrent stream close could finish with an error after terminal.session_terminated had already been recorded as successful.

For revocation with a PTY close failure, the production lifecycle therefore records, in order:

1. terminal.stream_closed — failed outcome, original client_revoked reason, correct peer/session/transport/stream attribution.
2. terminal.session_terminated — failed outcome, client_revoked reason.
3. terminal.session_closed — failed outcome, client_revoked reason, after deferred finish/cleanup.

The regression TestTypedHandlerPTYCleanupFailureAuditsStreamTerminationAndSessionClose exercises the real server admission and handleTypedTerminalSession deferred cleanup path. It opens a typed stream through the production connection handler, injects a PTY close failure, revokes the client, and verifies the persisted audit events, outcomes, attribution, and event ordering. It does not manually construct substitute audit events.

Additional regressions cover tracker-level cleanup outcomes, logical stream closure despite PTY cleanup failure, retention of cleanup errors after stream removal, and parent cleanup waiting for an in-flight close operation.

### Parent-session termination and terminal stream admission

The typed terminal server now has a permanent parent-session closure gate. Stream reservation and registration of the in-flight open operation happen under the same mutex used by parent cleanup. Once CloseAllWithReason marks the server closed, every later terminal StreamOpen is rejected before PTY startup.

Parent cleanup closes the admission gate before draining children, then waits for all pre-existing open reservations and stream-close operations. An opener that returns a PTY after parent closure closes that PTY instead of publishing a child or sending StreamAccepted. PTY close errors are retained by the server and returned from CloseAllWithReason after the in-flight opener finishes, so terminal.session_terminated and terminal.session_closed cannot report successful cleanup while a late PTY close has failed.

The production dispatch path checks the parent active-session termination state before routing each buffered application frame. If revocation wins before dispatch, a buffered StreamOpen is discarded and its revocation reason is retained. If dispatch passed that check immediately before revocation, the server's synchronized permanent closure gate decides the race: either the reservation is registered before closure and drained by parent cleanup, or the reservation is rejected after closure. No PTY startup can occur after parent cleanup has returned.

StreamAccepted writes and stream lifecycle audit callbacks are serialized so terminal.stream_opened cannot be recorded after the corresponding terminal.stream_closed event. A stream that never received StreamAccepted is not recorded as an opened/closed stream; if its PTY cleanup fails, the error still makes the parent termination and session-close outcomes fail.

Regression coverage:
- `TestDispatchTypedSessionFrameRejectsBufferedOpenAfterRevocation` — a buffered frame dispatched after parent termination is rejected without invoking the PTY starter.
- `TestTypedTerminalServerRejectsBufferedOpenAfterParentCleanup` — the permanent server gate rejects a post-cleanup StreamOpen before PTY startup.
- `TestTypedTerminalServerParentCleanupWaitsForInFlightStreamOpen` — parent cleanup waits for a blocked starter, closes its late PTY, and returns the injected close failure.
- `TestTypedHandlerRevocationWaitsForInFlightStreamOpenCleanupFailure` — production revocation/deferred cleanup reports failed session-terminated and session-closed events with the original client_revoked reason and correct session/peer/transport attribution.
- The existing accepted-stream PTY cleanup regression continues to verify failed terminal.stream_closed, terminal.session_terminated, and terminal.session_closed event outcomes and ordering.

## Identity-certificate concurrency

Identity certificate creation and repair write and sync a temporary file before publishing it. First creation uses an atomic hard link that cannot replace an existing path; repair verifies that the existing regular file has not changed before atomically renaming the complete replacement. A concurrent winner is reloaded and strictly validated rather than exposing a partially written final certificate. The identity private key and Ed25519 device identity are not rotated by certificate repair. Concurrent create and repair regressions cover 32 simultaneous Ensure callers.

## PTY admission boundary

Legacy PTY sessions first reserve admission through Trust.WithTrustedPeer. Only after the serialized reservation succeeds may startTerminal create a PTY or launch the shell. If revocation wins before reservation, the authorization callback fails and no shell initialization command runs.

If the reservation wins first, the session is registered for revocation before PTY startup. A later revocation closes its raw transport immediately, waits for a cleanup handle if PTY startup is still in progress, then closes the PTY before recording termination. An already terminated reservation does not send session acceptance. Typed-stream sessions continue to reserve the outer session before a terminal stream can create its PTY.

## Connection-grant expiration

issue_connection_grant() obtains FOR SHARE locks on the client and target device rows before capturing one clock_timestamp(). That value is reused for delegated terminal.connect expiration validation, issued_at, and expires_at. This avoids transaction-start now() incorrectly preserving an access grant that expires while issuance is waiting for a device row lock.

The deterministic database regression uses two independent psql processes against the explicitly disposable local Supabase PostgreSQL instance. One holds the target device row lock while the grant issuer is observed waiting in pg_stat_activity; the harness verifies the permission is still valid when the wait begins, allows it to expire, then releases the lock and verifies issuance fails without inserting a grant. An EXIT trap terminates outstanding sessions and removes fixtures after success or failure. The test uses no dblink functions and changes no database privileges. The pgTAP regression also asserts that only service_role can execute the issuer RPC.

## Worker/Durable Object process integration

The cross-process Go harness in scripts/cloudflare-worker-process-e2e/main.go starts a local Wrangler Worker runtime with persistent SQLite Durable Object storage, an independent Go wd-agent process, and two independent Go wd client processes. It pairs both clients using separate single-use pairing secrets, issues distinct terminal.connect grants, and establishes both terminal sessions through the Worker's WebSocket relay and Durable Object.

The process-level assertions cover:

- Successful relay authorization and session-open audit outcomes for both clients.
- Replay rejection after first use of each connection grant.
- Selective revocation of client A while client B remains connected and can still execute terminal input.
- Successful trust.client_revoke, terminal.session_terminated, and terminal.session_closed audit outcomes for client A.
- Absence of session termination/closure for client B during client A's revocation.
- Stopping and restarting Wrangler with the same Durable Object persistence directory.
- Rejection after restart of the previously consumed client A and client B grants.
- Restarting the independent Go agent, issuing client B a fresh grant, and proving that the still-authorized unrelated device can establish a new terminal session and execute a command after restart.
- Verification that Durable Object validation/consumption evidence for the original and fresh grants remains available after restart, and that the agent audit file retains the revocation and unrelated-session outcomes.

The original client B WebSocket session is expected to be disconnected when the Worker process stops; the post-restart assertion is that the same still-authorized device reconnects with a fresh short-lived grant and remains operational. The test does not claim that an existing TCP/WebSocket session survives process restart.

The CLI wd connect used by this process harness currently exercises the legacy terminal protocol, not typed streams. Accordingly, the process test asserts session-level authorization/open/termination/close events; typed-stream lifecycle and concurrent typed close-reason behavior are covered by the dedicated Go session regressions.

This is local Wrangler/SQLite Durable Object process evidence. It is not production Cloudflare edge/runtime validation. The Node Worker/DO regression uses in-memory runtime doubles and is a separate component-level test. Wrangler deploy --dry-run validates bundle/configuration only; it is not proof of live production relay behavior.

Only the disposable E2E agent binary is built with the wedecent_smoke_test build tag so that it may verify evidence against the local loopback Worker origin. The tag is excluded from release builds; production binaries retain the strict https://relay.wedecent.com authorization-origin allowlist.

## Verification commands

The current Linux CI job executes the following commands successfully on each exact PR head in the verification snapshot below:

    go test ./...
    go test -race ./...
    go test -race ./internal/session -run '^TestTypedSessionCloseReason' -count=50
    go run ./scripts/cloudflare-worker-process-e2e

The complete focused close-reason race command is:

    go test -race ./internal/session -run '^TestTypedSessionCloseReason' -count=50

It runs all typed-session close-reason regressions 50 times. The PTY cleanup and production-handler audit regressions are included in both full Go test commands. For an isolated reproduction, run:

    go test -race ./internal/session -run '^(TestTypedTerminalAuditTrackerReportsPTYCleanupFailure|TestTypedTerminalServerPTYCleanupFailureClosesStreamAndPersistsError|TestTypedTerminalServerParentCleanupWaitsForInFlightStreamClose|TestTypedHandlerPTYCleanupFailureAuditsStreamTerminationAndSessionClose|TestRevocationPTYCleanupFailureMarksTerminationAndCloseAuditFailed)$' -count=1

For isolated reproduction of the new parent-session admission race regressions, run:

    go test -race ./internal/session -run '^(TestDispatchTypedSessionFrameRejectsBufferedOpenAfterRevocation|TestTypedTerminalServerRejectsBufferedOpenAfterParentCleanup|TestTypedTerminalServerParentCleanupWaitsForInFlightStreamOpen|TestTypedHandlerRevocationWaitsForInFlightStreamOpenCleanupFailure)

    cd cloudflare/relay-worker && npm test
    npx wrangler deploy --dry-run
    supabase test db
    ./scripts/test-connection-grant-expiration.sh

The Wrangler dry-run and in-memory Worker tests are not substitutes for the local process integration, and none of these commands constitutes production Cloudflare or physical/offline real-hardware validation. Results must be attributed to the exact tested commit and workflow run; source changes alone are not proof.

## Exact-head PR stack verification snapshot — 2026-11-21

The following implementation and documentation heads were checked in this remediation cycle. CI workflow ID is `342513994`; desktop-shell workflow ID is `367426414`. Each listed CI run completed 10/10 jobs, and each listed desktop run completed all three platform jobs.

| PR | Verified HEAD | Base HEAD | CI run | Desktop run |
|---|---|---|---|---|
| #179 | `20e1b1842df9577e34d42827d2efce8bf817b6e0` | `ed0bb462d829430eb50c7b2a6a74161854f62c73` | [44955760142](https://github.com/ADRN-9/wedecent/actions/runs/44955760142) | [44955760172](https://github.com/ADRN-9/wedecent/actions/runs/44955760172) |
| #180 | `424e3e75cff6204d826a108f0b8aa7b61014e8ce` | `20e1b1842df9577e34d42827d2efce8bf817b6e0` | [44956153046](https://github.com/ADRN-9/wedecent/actions/runs/44956153046) | [44956153051](https://github.com/ADRN-9/wedecent/actions/runs/44956153051) |
| #181 | `84e855f4791fb1523cdffccf366253c7fb2d254a` | `424e3e75cff6204d826a108f0b8aa7b61014e8ce` | [44956173311](https://github.com/ADRN-9/wedecent/actions/runs/44956173311) | [44956173301](https://github.com/ADRN-9/wedecent/actions/runs/44956173301) |
| #182 | `e378fade5109ca38bd32dc4802f9897ec1e7243e` | `84e855f4791fb1523cdffccf366253c7fb2d254a` | [44956300342](https://github.com/ADRN-9/wedecent/actions/runs/44956300342) | [44956300369](https://github.com/ADRN-9/wedecent/actions/runs/44956300369) |

The PR #182 row is the exact head before this final documentation snapshot refresh. This subsequent documentation-only commit is validated by its own exact-head CI and desktop runs, which are recorded in the current PR #182 description.

## Repository governance findings — 2026-11-21

The repository-level active ruleset Protect main (ID 21507567) targets only the default branch (~DEFAULT_BRANCH). It does not target the stacked feature branches used by PRs #179–#182.

The visible ruleset's pull-request rule currently sets:

- required_approving_review_count = 0;
- no required reviewers;
- code-owner review disabled;
- last-push approval disabled;
- stale-review dismissal disabled;
- required review-thread resolution enabled.

Its required status checks are route-capability-client, route-e2e, linux, windows-agent, windows-release, relay-worker, control-plane, and supabase-db. Strict required-status-check policy is disabled. The ruleset does not require macos-agent, relay-worker-process-e2e, or the desktop-shell checks linux-tauri-check, windows-tauri-check, and macos-tauri-check.

The classic branch-protection endpoint returned HTTP 403 (Resource not accessible by integration) for the default branch and the PR #179 base branch. The repository metadata response reports admin permission, but the connected GitHub tool exposes no branch-protection/ruleset mutation action and the classic protection read is forbidden. The other stacked target branches therefore cannot be verified for classic protection through this connection. No ruleset or branch-protection change was made.

Independent approval is not enforced by the visible ruleset. Complete required-check enforcement is not present. Because the ruleset only applies to the default branch and classic protection on stacked targets could not be inspected, safe merging of the stacked PRs without bypassing protection cannot be established.

Required administrator configuration before merging:

1. Apply a ruleset to the stacked branches (for example, the explicit security/* branches used by this release stack).
2. Require at least one independent approval and disallow approval by the last pusher; dismiss stale approvals after pushes.
3. Require strict status checks for Linux, Windows, macOS agent, Windows release, relay Worker, Worker process E2E, route capability, route E2E, control plane, Supabase DB, and all three desktop-shell platform checks.
4. Keep bypass actors empty or explicitly restricted to the minimum emergency role.

No PR was merged. PRs #179–#182 remain open, draft, and unmerged. No production infrastructure, database, credential, trust-anchor, signing, or deployment operation was performed.
 -count=1

These four regressions ran as part of the full `go test ./...` and `go test -race ./...` suites on each exact implementation head above. The isolated command was not separately recorded as a standalone CI step.

Other relevant verification commands:

    cd cloudflare/relay-worker && npm test
    npx wrangler deploy --dry-run
    supabase test db
    ./scripts/test-connection-grant-expiration.sh

The Wrangler dry-run and in-memory Worker tests are not substitutes for the local process integration, and none of these commands constitutes production Cloudflare or physical/offline real-hardware validation. Results must be attributed to the exact tested commit and workflow run; source changes alone are not proof.

## Exact-head PR stack verification snapshot — 2026-11-21

The following implementation and documentation heads were checked in this remediation cycle. CI workflow ID is `342513994`; desktop-shell workflow ID is `367426414`. Each listed CI run completed 10/10 jobs, and each listed desktop run completed all three platform jobs.

| PR | Verified HEAD | Base HEAD | CI run | Desktop run |
|---|---|---|---|---|
| #179 | `20e1b1842df9577e34d42827d2efce8bf817b6e0` | `ed0bb462d829430eb50c7b2a6a74161854f62c73` | [44955760142](https://github.com/ADRN-9/wedecent/actions/runs/44955760142) | [44955760172](https://github.com/ADRN-9/wedecent/actions/runs/44955760172) |
| #180 | `424e3e75cff6204d826a108f0b8aa7b61014e8ce` | `20e1b1842df9577e34d42827d2efce8bf817b6e0` | [44956153046](https://github.com/ADRN-9/wedecent/actions/runs/44956153046) | [44956153051](https://github.com/ADRN-9/wedecent/actions/runs/44956153051) |
| #181 | `84e855f4791fb1523cdffccf366253c7fb2d254a` | `424e3e75cff6204d826a108f0b8aa7b61014e8ce` | [44956173311](https://github.com/ADRN-9/wedecent/actions/runs/44956173311) | [44956173301](https://github.com/ADRN-9/wedecent/actions/runs/44956173301) |
| #182 | `e378fade5109ca38bd32dc4802f9897ec1e7243e` | `84e855f4791fb1523cdffccf366253c7fb2d254a` | [44956300342](https://github.com/ADRN-9/wedecent/actions/runs/44956300342) | [44956300369](https://github.com/ADRN-9/wedecent/actions/runs/44956300369) |

The PR #182 row is the exact head before this final documentation snapshot refresh. This subsequent documentation-only commit is validated by its own exact-head CI and desktop runs, which are recorded in the current PR #182 description.

## Repository governance findings — 2026-11-21

The repository-level active ruleset Protect main (ID 21507567) targets only the default branch (~DEFAULT_BRANCH). It does not target the stacked feature branches used by PRs #179–#182.

The visible ruleset's pull-request rule currently sets:

- required_approving_review_count = 0;
- no required reviewers;
- code-owner review disabled;
- last-push approval disabled;
- stale-review dismissal disabled;
- required review-thread resolution enabled.

Its required status checks are route-capability-client, route-e2e, linux, windows-agent, windows-release, relay-worker, control-plane, and supabase-db. Strict required-status-check policy is disabled. The ruleset does not require macos-agent, relay-worker-process-e2e, or the desktop-shell checks linux-tauri-check, windows-tauri-check, and macos-tauri-check.

The classic branch-protection endpoint returned HTTP 403 (Resource not accessible by integration) for the default branch and the PR #179 base branch. The repository metadata response reports admin permission, but the connected GitHub tool exposes no branch-protection/ruleset mutation action and the classic protection read is forbidden. The other stacked target branches therefore cannot be verified for classic protection through this connection. No ruleset or branch-protection change was made.

Independent approval is not enforced by the visible ruleset. Complete required-check enforcement is not present. Because the ruleset only applies to the default branch and classic protection on stacked targets could not be inspected, safe merging of the stacked PRs without bypassing protection cannot be established.

Required administrator configuration before merging:

1. Apply a ruleset to the stacked branches (for example, the explicit security/* branches used by this release stack).
2. Require at least one independent approval and disallow approval by the last pusher; dismiss stale approvals after pushes.
3. Require strict status checks for Linux, Windows, macOS agent, Windows release, relay Worker, Worker process E2E, route capability, route E2E, control plane, Supabase DB, and all three desktop-shell platform checks.
4. Keep bypass actors empty or explicitly restricted to the minimum emergency role.

No PR was merged. PRs #179–#182 remain open, draft, and unmerged. No production infrastructure, database, credential, trust-anchor, signing, or deployment operation was performed.
