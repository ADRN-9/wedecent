# C166 — Distributed revocation fencing and production verification

Status: remediation review and contract definition. Distributed fencing is **not implemented**. Production authorization/finalization remains blocked until the primary and witness services implement and pass the protocol below.

## Repository evidence reviewed

The existing Go contracts are:

- `ReplayCheckpointProvider`: `Consume`, `Revoke`, and `Head` in `internal/portforward/replay_checkpoint.go`.
- `CheckpointWitness`: `Commit`, `Revoke`, `Acknowledge`, and `Head` in `internal/portforward/replay_witness.go`.

These calls return signed receipts, acknowledgements and heads. The deterministic witness implementation is explicitly a test harness. The provider contract requires the primary to serialize consume and revoke against its durable state, but neither interface carries a common monotonic fencing generation or a quorum-certified ordering token. The current client transition lock in `checkpoint_pending.go` serializes one local journal; it cannot serialize independent service instances, independent witnesses, or operations during a network partition.

The current code therefore does not prove that a finalization cannot be accepted after a revocation has committed at the remote authorities. A read of the primary head followed by independent witness reads is not an atomic distributed fence. In particular, a finalization can race with revocation between those reads and the external audit RPC.

## Exact missing provider contract

The remote primary and every independent witness need a durable, restart-safe fencing interface. The minimum contract is:

1. **Primary fence reservation (linearization point).** An atomic compare-and-swap per participant scope returns a signed `FenceToken` containing protocol version, scope (device/account/organization), monotonic fence generation, revocation epoch, action (`finalize` or `revoke`), stable operation ID, exact request fingerprint, authorization digest, primary head generation/hash, prior fence hash, issue/expiry bounds, and primary key ID/signature. A repeated operation ID with identical bytes returns the exact token; a conflicting retry is rejected.
2. **Witness fence commit.** Each witness durably verifies the primary signature and atomically advances its own per-scope fence generation. It rejects any token older than its persisted generation, any same-generation conflict, and any stale revocation epoch. It returns a signed `FenceAck` binding witness ID, scope, generation, action, operation ID, request fingerprint, authorization digest, revocation epoch, primary token digest, and witness key ID.
3. **Quorum intersection.** The witness set is fixed for the operation and independently administered. Finalization and revocation both require the same strict-majority quorum policy. A quorum that commits revocation must intersect every finalization quorum; the intersecting witness rejects a stale finalization token after observing the higher revocation generation. Witness membership/key rotation must not permit disjoint quorums or silently change quorum membership during an operation.
4. **Commit rule.** The primary must durably commit the action only after receiving a valid witness quorum for the exact token, and must reject a token if a later fence generation already superseded it. The audit service accepts finalization only with the primary token plus the independent quorum of witness fence acknowledgements, in addition to the existing checkpoint receipt, ordinary witness acknowledgements, request binding, route grant binding, and participant revocation proofs.
5. **Recovery.** The primary and witnesses persist tokens and acknowledgements before responding. After process restart or lost responses, clients query/retry the exact original operation ID and token. They may never mint a new generation or reconstruct evidence from newer heads for an ambiguous prior operation. A conflicting outcome for an existing operation ID is terminal and fail-closed.

Suggested Go boundary (names are illustrative but the semantics are mandatory):

```go
type CheckpointFenceAction string // "finalize" | "revoke"

type CheckpointFenceToken struct {
    Scope CheckpointWitnessScope
    Generation uint64
    RevocationEpoch uint64
    Action CheckpointFenceAction
    OperationID string
    RequestSHA256 [32]byte
    AuthorizationSHA256 [32]byte
    PrimaryHeadGeneration uint64
    PrimaryHeadSHA256 [32]byte
    PreviousFenceSHA256 [32]byte
    ExpiresAtUnixMS int64
    PrimaryKeyID string
    Signature []byte
}

type CheckpointFenceAck struct {
    WitnessID string
    Scope CheckpointWitnessScope
    Generation uint64
    RevocationEpoch uint64
    Action CheckpointFenceAction
    OperationID string
    RequestSHA256 [32]byte
    AuthorizationSHA256 [32]byte
    FenceTokenSHA256 [32]byte
    WitnessKeyID string
    Signature []byte
}

type CheckpointFencingPrimary interface {
    ReserveFence(context.Context, CheckpointFenceRequest) (CheckpointFenceToken, error)
    CommitFence(context.Context, CheckpointFenceToken, []CheckpointFenceAck) error
    LoadFence(context.Context, CheckpointWitnessScope, string) (CheckpointFenceToken, bool, error)
}

type CheckpointFencingWitness interface {
    CommitFence(context.Context, CheckpointFenceToken) (CheckpointFenceAck, error)
    LoadFence(context.Context, CheckpointWitnessScope) (CheckpointFenceAck, bool, error)
}
```

This is a required service contract, not a proposal to simulate distributed consensus with a client mutex. The token format, canonical serialization vectors, signature domain separators, idempotency rules, quorum membership versioning, and transactional persistence must be agreed by the service owners before implementation. The existing `CheckpointWitnessAck` is not a substitute: it attests a committed checkpoint receipt, not a monotonic fence shared by finalize and revoke.

## Durable evidence work already present

`checkpoint_pending.go` currently persists:

- stable `FinalizationOperationID`;
- complete `CheckpointFinalizationEvidence` (primary receipt, witness acknowledgements, primary heads and witness heads for participant scopes);
- canonical JSON-derived `FinalizationEvidenceSHA256`;
- completion marker state.

The file-backed store validates operation identity and evidence digest on load, refuses replacement with different evidence, uses bounded/permission-hardened journal storage, and survives restart. `FinalizeWithAudit` loads the persisted evidence on retry rather than reconstructing it from new provider heads.

Existing regression coverage in `internal/portforward/replay_witness_test.go` includes:

- `TestFinalizationEvidenceIsDurableImmutableAndTamperEvident`;
- `TestFinalizationAuditSinkDeduplicatesAfterCompletionMarkerFailureAndRestart` (injects completion-marker persistence failure, changes provider heads through revocation, restarts the client, and verifies identical operation ID/evidence on retry);
- `TestFinalizationCallbackIsIdempotentAcrossCompactionFailureAndRestart`;
- `TestWitnessFinalizationRecoversLostAckResponsesAfterRestart`;
- `TestWitnessedClientRestartRecoversLostPrimaryCommit`;
- `TestPendingJournalInterruptedPublicationPreservesPreviousEvidence`.

These are repository test cases, not results of a test execution in this assignment. They demonstrate local durable-retry semantics; they do not close the distributed fencing gap.

## Cryptographic interoperability

The shared fixture is `testdata/portforward/checkpoint_crypto_vectors.json`. Go consumes it in `internal/portforward/checkpoint_vectors_test.go`; the Deno Edge Function tests consume the same file in `supabase/functions/port-forward-finalization-audit/index_test.ts`.

The vectors cover the request fingerprint and stable operation ID, primary receipt, primary head, witness acknowledgement, witness head, and canonical payload digest. The TypeScript operation-ID test encodes the domain suffix as an actual newline (`\n`) and compares the resulting digest with the shared Go-generated fixture. The Deno suite also constructs positive Ed25519 evidence and rejects tampered acknowledgement evidence.

No Go/Deno test command was executable through the available GitHub file/PR integration in this assignment. The vectors and tests were inspected, not run. The CI workflows are the required execution evidence.

## Database concurrency gap

The SQL RPC and pgTAP suite exercise transaction state transitions, exact retries, conflicting outcomes, membership/revocation checks, and route-grant binding. The reviewed suite does not provide independent concurrent database sessions racing revocation against finalization, nor does it prove commit-then-lost-response behavior under two live sessions. pgTAP assertions are not a substitute for that integration test.

Required integration suite: run two independent PostgreSQL sessions with barriers around row-lock acquisition and commit. Exercise revoke-first, finalize-first, concurrent identical requests, conflicting payloads, rollback, committed RPC with dropped response, retry after membership/device/route revocation, and restart. Assert that only the operation ordered before revocation can finalize, and that the persisted fence token/quorum is identical on retry. This suite depends on the provider fencing API above.

## Production gates and dependencies

The following remain outstanding and must be separately provisioned/verified:

- independently administered primary and witness service deployments with durable fencing stores;
- fixed witness-set identity/version, strict-majority quorum, and independent operator ownership;
- primary/witness Ed25519 public-key provisioning and key-rotation ceremony;
- independent route-authorization verification key provisioning;
- Local Core audit hostname and SPKI pin provisioning, overlap during rotation, and emergency pin rollover procedure;
- Supabase migration deployment and schema-version confirmation;
- Edge Function deployment with independently provisioned primary, witness, route keys and quorum configuration;
- audit retention policy, immutable backup configuration, restore drills and evidence-retention validation;
- external transaction-level concurrency suite and exact-HEAD CI/Desktop results.

No production credentials, trust anchors, pins, database migrations, Edge Functions, or infrastructure were provisioned by this remediation. PR #186 must remain open and draft until the provider fencing contract is implemented, deployed to test infrastructure, and independently reviewed.

## C166 disposition

- Durable local evidence persistence: implementation and named regression tests exist; execution still required.
- Shared Go/TypeScript vectors: implementation and tests exist; execution still required.
- TypeScript operation-ID newline: inspected and matches the Go domain separator.
- Distributed revocation fencing: **not implemented; release-blocking**.
- Independent database-session concurrency: **not implemented/proven; release-blocking**.
- Exact-HEAD Go/Deno/Supabase/Linux/Windows/macOS/Desktop workflows: pending execution evidence.
- Production activation: not authorized by this remediation report.
