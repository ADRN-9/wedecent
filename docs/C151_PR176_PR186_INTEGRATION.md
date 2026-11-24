# PR #176 / PR #186 integration plan

**Scope:** WeDecent only. This is an integration assessment, not approval to merge either draft PR.

## Repository state inspected

Both pull requests are open drafts and share base `acbca90e10a4d51cb0ca0ec9f066089fbac97bb7`.

- PR #176, `security/atomic-pairing-wd-c03`: `eaba551d5d18e540dd96f752aa2b049248b95505`
- PR #186, `feat/secure-port-forwarding-foundation`: `73f04ff26978ebc4b7a39e7bbc02f212884c1f5d` at assessment time

The branch compare reports the branches are diverged, with PR #186 553 commits ahead and 100 behind PR #176's head, using the shared base as merge base. This means a clean fast-forward is not available. The file lists confirm four direct overlaps: `internal/audit/log.go`, `internal/audit/log_test.go`, `internal/session/server.go` and `internal/trust/store.go`.

## Overlap analysis and required merge semantics

### `internal/audit/log.go` and `internal/audit/log_test.go`

PR #176 adds `AttemptID` to audit events, validates its pairing-attempt format, and syncs the parent directory after append and rotation. The sync is an acknowledgement/durability boundary for pairing's pending audit record; PR #176 also tests injected directory-sync failure.

PR #186 adds `ForwardingID`, `Direction` and `Destination` fields and their validation/tests, but its version of `Append` omits the directory sync and its event struct omits `AttemptID`.

**Required resolution:** union the event schema and validation (AttemptID plus all three forwarding fields); retain PR #176's directory fsync and rotation durability semantics and tests; add PR #186's forwarding-field tests to the combined suite. Do not resolve by choosing either entire file.

### `internal/session/server.go`

PR #176 adds an atomic pairing completion protocol: preflight pairing-secret validation, unique attempt IDs, durable pending audit and recovery records, a commit handler, and durable trust-store pairing commit. It deliberately does not consume the pairing secret or report success until required durable records and trust persistence succeed.

PR #186 adds router identity propagation and port-forward runtime wiring, and changes handshake deadline error handling. Its pairing path instead invalidates the pairing secret before calling ordinary `Trust.Put`, without PR #176's pending audit/recovery transaction or pairing-specific durable trust-store operation.

**Required resolution:** retain PR #176's full pairing state machine and its ordering/durability checks. Port PR #186's router identity propagation, forwarding runtime and deadline handling into the surrounding server path without replacing the pairing commit handler. Adapt any pairing-related routing/session code to call the PR #176 durable operation. Do not take PR #186's secret-invalidation-plus-ordinary-Put sequence as a replacement: it drops the pending recovery/audit evidence and the explicit pairing durability contract.

### `internal/trust/store.go`

PR #176 introduces `PutPairing`, pairing-specific durable replacement, directory synchronization, rollback/error semantics and test fault hooks. PR #186 adds context-aware `IsTrusted(ctx, id)` with explicit reload and cancellation errors, but retains the older generic `saveLocked()` path and does not contain the pairing durability machinery.

**Required resolution:** base the combined store on PR #176's durable implementation, then add `IsTrusted(ctx, id)` as a read-only, cancellation-aware method using the same lock and reload discipline. Preserve `PutPairing` and its separate durability contract; do not collapse it back into ordinary `Put` or change its commit hooks/signature without updating all callers and tests.

## Intended release integration sequence

1. Keep both PRs open and draft while CI/security review proceeds. No PR is approved or merged by this assessment.
2. Validate PR #176's atomic pairing independently, including Linux, Windows, macOS, directory-sync fault injection, recovery and trust-store durability tests. It is the prerequisite pairing/durability layer.
3. Integrate PR #176 into the PR #186 work branch using a normal merge/rebase workflow with explicit conflict resolution in the four overlap files. Because the branches diverged, review the resulting complete diff; do not force-push or blindly accept either side.
4. Resolve audit files by schema union plus PR #176 fsync semantics; resolve session server by retaining PR #176 pairing commit/recovery ordering and porting PR #186 routing/forwarding changes; resolve trust store by retaining PR #176 pairing durable commit and adding PR #186's context-aware trust query.
5. Run focused audit, trust, pairing/session, port-forwarding and witness tests; run `gofmt`; then require all nine CI jobs and all three Desktop platform jobs to pass against the same final integration SHA. Investigate any skipped, cancelled or platform-specific job; never count it as a pass.
6. Review the merged diff for pairing-secret consumption order, trust-store durability, audit durability, device identity and router authority boundaries. Obtain service-owner evidence for production witness/fencing claims separately; repository integration cannot prove distributed atomicity.
7. Only after the integration SHA is green and reviewed should PR #176/PR #186 ownership and closure be decided. Production signing, deployment and activation remain separate gated operations and require their own release evidence and protected approvals.

## Known blockers and non-claims

- The four overlapping files require manual semantic integration; no conflict resolution has been applied in this assessment.
- CI on the PR #186 starting head exposed a gofmt failure and an equivocation regression test failure; a focused correction was committed afterward, and the new exact-head workflows must establish whether those are resolved.
- No independently deployed production witness services, production endpoints, credentials, trust anchors or distributed fencing protocol are established by these two PRs. The C152 wire document is a proposal only.
- No merge, approval, production signing, deployment or activation is authorized by this integration plan.
