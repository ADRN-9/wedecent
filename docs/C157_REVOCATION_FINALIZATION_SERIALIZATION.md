# Checkpoint revocation, finalization and audit architecture (updated C164)

This document supersedes the earlier C157 audit-sink assessment where it described production audit integration as absent. It retains the C157 local serialization findings and records the C162/C164 implementation and remaining production limitations.

## Local serialization established by C157

The pending-store contract exposes `LockTransition(context.Context)`. The file-backed store uses the journal-wide OS lock; the memory implementation is test-only. Consume, finalization and revocation share this lock. Unlock errors are joined into operation results and missing lock support fails closed.

The deterministic concurrency regression `TestRevokeAndFinalizeShareTransitionLock` covers both acquisition orders. `TestFinalizationAuditSinkDeduplicatesAfterCompletionMarkerFailureAndRestart` exercises retry after audit commit but before the local completion marker. These are local-process/file-backed tests, not proof of distributed primary/witness atomicity.

## C162 production audit integration

The current production path is wired in `internal/coreapi/coreprocess/process.go`:

- Local Core requires a witnessed checkpoint provider and independently authenticated membership resolver.
- It opens a protected file-backed pending journal.
- It requires an authenticated Supabase account session.
- It injects `SupabaseCheckpointFinalizationAuditor`.
- It has no local JSONL fallback for checkpoint finalization audit.

The Go adapter is in `internal/portforward/checkpoint_audit_supabase.go`. It refreshes and verifies the account session, persists refreshed credentials, and sends authenticated requests over HTTPS. The C162 version validated TLS 1.3 and rejected redirects but did not independently pin the audit origin.

The Edge Function is `supabase/functions/port-forward-finalization-audit/index.ts`. It authenticates the bearer token with Supabase Auth and invokes the privileged transactional RPC. C162 verified the device signature over the checkpoint request but did not prove primary commitment or independent witness quorum before accepting a caller-selected terminal outcome.

## C164 security remediation

Terminal audit completion now carries a structured proof bundle assembled by `WitnessedReplayCheckpointProvider.FinalizeWithAudit`:

1. The primary signed checkpoint receipt, bound to the exact request fingerprint, JTI and authorization digest.
2. Distinct independent witness acknowledgements, each signed by its configured witness key and bound to the primary receipt digest and request fingerprint.
3. A primary signed head and matching independent witness heads for every participant in the signed membership vector, including the router when routed.
4. The exact route authorization JSON, grant ID and JTI are carried with the route digest and checked against the signed checkpoint request. For routed operations, the Edge Function independently verifies the route authorization signature against `WEDECENT_ROUTE_AUTH_KEY_ID` and `WEDECENT_ROUTE_AUTH_PUBLIC_KEY`; route, primary and witness public keys must be distinct.

The Edge Function verifies the proof using server-side, independently provisioned trust anchors. Caller-supplied keys are not trusted. Only `finalized` is accepted as a proof-bearing terminal outcome. `finalization_failed` is permitted only as a nonterminal event after start. `membership_unavailable` is permitted only when a participant membership is actually absent and the authenticated actor remains a member of their own organization; it is also nonterminal and can be followed by recovery and finalization. Both intermediate events carry an empty evidence object and cannot poison terminal state. `rejected_revocation` remains unsupported until an independently verifiable revocation proof transition is implemented.

The database RPC now persists canonical request and per-outcome evidence digests, locks all participant organizations and existing memberships, device-access rows, route grant and device rows in the authorization issuance lock order, then locks and rechecks the stored authorization transaction. It compares stored identities, organizations and revocation epochs to both the signed payload and current enrolled device state, and rechecks current destination and router access grants. Routed operations are bound to the stored route grant ID/JTI, organization, original validity window, revocation state, and source/destination/router identities. Membership-unavailable events are permitted only when an actual participant membership is absent while the actor's own membership remains valid; they are nonterminal and can recover after membership restoration.

The state machine requires a start event before completion, permits intermediate failure/unavailable events before completion, allows recovery to a later finalized state, makes exact retries idempotent, and rejects new events after terminal completion. Conflicting terminal outcomes remain mutually exclusive.

The Go audit adapter now requires an explicit independent hostname, port and one-to-four SHA-256 SPKI pins embedded in the release build metadata. The CLI rejects legacy single-provider replay URL/API-key flags and environment variables; there is no single-provider fallback. The account session URL must match that trust configuration exactly. TLS 1.3, system certificate verification, SPKI pin matching, redirect rejection, bounded timeout and context cancellation are enforced. Multiple pins permit controlled rotation; no trust anchor is inferred from the mutable account session.

## Required production configuration (not provisioned by this remediation)

The Edge Function must receive these independently administered secrets/configuration values:

- `WEDECENT_CHECKPOINT_PRIMARY_PUBLIC_KEY`: canonical standard-base64 Ed25519 public key.
- `WEDECENT_CHECKPOINT_WITNESS_KEYS`: JSON object mapping stable witness IDs to canonical standard-base64 Ed25519 public keys.
- `WEDECENT_CHECKPOINT_WITNESS_QUORUM`: integer strict-majority quorum.
- `WEDECENT_ROUTE_AUTH_KEY_ID` and `WEDECENT_ROUTE_AUTH_PUBLIC_KEY`: independent route-authorization signing key identity and Ed25519 public key, required for routed audit operations.

The Local Core constructor requires `Config.ForwardingAuditTrust` with the exact audit hostname, port and comma-separated SPKI SHA-256 pins. The production release workflow now requires `WEDECENT_CHECKPOINT_AUDIT_HOSTNAME`, `WEDECENT_CHECKPOINT_AUDIT_SPKI_SHA256`, and `WEDECENT_CHECKPOINT_AUDIT_APPROVAL_SHA256`; the approved values are embedded in `buildinfo`, checked by release metadata and binary inspection, and surfaced by `wd-core release-trust`. The approval digest is domain-separated with `wedecent-checkpoint-audit-approval-v1`. These values must come from a protected provisioning channel. They must not be copied from `account-session.json`, the renderer, or ordinary user-controlled config.

No production trust anchors, endpoint pins, credentials, migrations, or Edge Function deployments were provisioned here.

## Remaining limitations

- The current proof-bearing terminal outcome is only `finalized`. Revocation rejection and failure-state audit evidence need a separately designed signed proof transition.
- The primary and witness authorities must implement and preserve the receipt/head/ack protocol represented by the Go interfaces. Repository code alone cannot prove that external authorities are independently administered or correctly deployed.
- The SQL RPC relies on the server-side Edge Function as the cryptographic verification boundary. Service-role credentials remain privileged and must remain server-side.
- Positive Deno tests now generate real Ed25519 primary and independent witness keys, sign a primary receipt, witness quorum acknowledgements and participant heads, and verify both acceptance and tamper rejection. A separate routed authorization test signs and verifies the route capability with a distinct key. Shared canonical vectors are exercised by Go and TypeScript; SQL pgTAP tests cover the same numeric and ordering boundaries.
- `scripts/test-port-forward-db-concurrency.sh` now exercises independent-session races between finalization and device-epoch revocation, membership deletion, and route-grant revocation, plus exact duplicate and conflicting operation submissions. These remain implemented test coverage until the exact C164 CI run completes.
- Audit retention, immutable backups, restore testing, production secret ownership and endpoint pin rotation operations remain infrastructure decisions.
- The adapter pin trust configuration has been made mandatory in Local Core. Existing runtime/bootstrap callers must populate it before forwarding can initialize. A missing trust config intentionally fails closed.

## Verification interpretation

Historical C157/C159 workflow IDs validate their respective historical commits only. They do not validate C164 changes. C164 acceptance requires exact-HEAD Linux/Windows/macOS CI, Desktop checks, Supabase pgTAP and Edge tests, plus transaction-level revocation races and positive/negative cryptographic proof tests. No production readiness claim is made by this document.
