# C166 — Distributed revocation fencing and durable finalization evidence

## Scope and repository state

C166 extends the witnessed checkpoint finalization path. It does not claim production acceptance, deployment, or provider-side distributed fencing. The branch remains `feat/secure-port-forwarding-foundation`; PR #186 must remain open and draft pending independent acceptance.

## Priority 1 — Distributed revocation fencing: OPEN SECURITY GATE

The current interfaces are insufficient to prove a single authoritative order across primary and witness authorities:

- `ReplayCheckpointProvider`: `Consume`, `Revoke`, and `Head`.
- `CheckpointWitness`: `Commit`, `Revoke`, `Acknowledge`, and `Head`.
- `WitnessedReplayCheckpointProvider.Revoke` commits to the primary first, then calls witnesses independently and checks a quorum.
- `FinalizeWithAudit` gathers witness acknowledgements, reads primary and witness heads, and revalidates membership immediately before the audit boundary.

These calls do not expose a shared fencing generation or a distributed compare-and-append operation. A process-local lock serializes only callers sharing that pending journal. PostgreSQL row/advisory locks serialize only database transactions. Neither coordinates the primary checkpoint service, independent witness services, and audit database as one distributed authority.

### Exact missing provider contract

A production provider protocol must add a signed, durable fence operation on every independently administered authority, keyed by each participant scope and a stable operation ID. The minimum conceptual contract is:

```go
type CheckpointFenceAction string // "finalize" | "revoke"

type CheckpointFenceCommand struct {
    OperationID string
    Action CheckpointFenceAction
    ExpectedGeneration uint64
    ExpectedRevocationEpoch uint64
    RequestSHA256 [32]byte
    Participant CheckpointEndpoint
}

type CheckpointFenceReceipt struct {
    OperationID string
    Action CheckpointFenceAction
    Generation uint64
    RevocationEpoch uint64
    StateSHA256 [32]byte
    AuthorityID string
    Signature []byte
}

type CheckpointFencingAuthority interface {
    AdvanceFence(context.Context, CheckpointFenceCommand) (CheckpointFenceReceipt, error)
    ReadFence(context.Context, CheckpointEndpoint) (CheckpointFenceReceipt, error)
}
```

This is a protocol requirement, not an implemented interface. The primary and a strict independent witness quorum must atomically append the same operation digest at the same monotonically increasing generation. A revoke must fence every later finalize; a finalize ordered first may complete before a later revoke. Retries must be idempotent by operation ID, and recovery must reconcile partially acknowledged generations without permitting a stale finalize. The signed primary receipt and witness attestations must bind the fence generation, action, participant vector, expected epoch and resulting state digest.

The repository currently contains no production implementation of this contract and no provider-side transaction that can coordinate independent services. Therefore C166 leaves distributed fencing unimplemented and the security gate open. Do not interpret current local locking, membership revalidation, SQL transaction locks, or head reads as distributed fencing.

## Priority 2 — Durable finalization evidence

`internal/portforward/checkpoint_pending.go` now persists an immutable evidence bundle in the protected pending journal before the external audit callback:

- Primary checkpoint receipt.
- Independent witness acknowledgements.
- Primary heads and witness heads for every participant.
- Stable finalization operation ID.
- SHA-256 digest of the serialized evidence bundle.

The store rejects replacement with a different bundle for the same operation. Loads recompute and compare the evidence digest. The completion marker now requires a previously persisted, digest-valid evidence bundle.

`FinalizeWithAudit` now checks for persisted evidence before re-reading mutable provider heads. When a previous submission returned an ambiguous error, a restart retry submits the original stored proof bytes and operation ID. It does not reconstruct a different proof from newer heads. This preserves exact retry semantics even if provider heads advance after an ambiguous audit response.

Tests added:
- Durable evidence survives file-store restart.
- A conflicting evidence bundle cannot replace the original.
- Tampered persisted evidence is rejected.
- The audit retry after an ambiguous response uses the same evidence after a subsequent primary/witness revocation changes provider heads.

These are authored regression tests. They have not yet been executed in this environment.

## Priority 3 — Cryptographic interoperability

Shared vectors are in `testdata/portforward/checkpoint_crypto_vectors.json`. They cover:

- Signed checkpoint request wire bytes, request fingerprint and operation ID.
- Primary receipt encoding and digest.
- Primary head encoding.
- Witness acknowledgement encoding.
- Witness head encoding.
- Canonical JSON serialization and SHA-256 payload digest.

Go tests and Deno tests consume the same file. The TypeScript operation-ID test now uses an actual newline byte in the domain separator rather than the two-character sequence backslash+n. SQL pgTAP checks the canonical payload representation and digest against the same vector.

The existing Deno positive evidence test generates Ed25519 primary/witness keys, signs a receipt, quorum acknowledgements and participant heads, and verifies the proof. Forged acknowledgement rejection is also covered. However, a fixed signed proof bundle generated by Go and verified by TypeScript, and a TypeScript-generated signed bundle verified by Go, are not yet complete. Shared message encodings and digest vectors are not a substitute for those cross-runtime signature tests.

## Priority 4 — Database concurrency

The SQL pgTAP suite contains transaction-level checks for membership/device revocation, route-grant binding, exact retries, conflicting payloads and state transitions. The independent-session script `scripts/test-port-forward-db-concurrency.sh` already exercises participant revocation versus audit-start operations.

C166 extends the independent-session script with:
- Concurrent identical audit submissions for the same operation ID.
- Conflicting payload submissions for one operation ID.
- Terminal `finalized` versus participant-revocation races in both lock orderings.

The terminal race helper uses structurally valid but deliberately synthetic proof JSON. It exercises SQL lock ordering and state transitions only; it does not establish cryptographic evidence validity. Cryptographic verification remains the Edge Function's responsibility. These database tests have not yet been executed.

## Priority 5 — Verification status

No local Go, Deno, Supabase CLI, PostgreSQL client, or browser-based command execution is available through the current GitHub repository tools. Repository writes and file reads are available; that is not equivalent to running tests.

Required exact-HEAD evidence still pending:
- `gofmt` on changed Go files.
- `go test ./...`, `go test -race ./...`, and `go vet ./...`.
- Deno type check and test suite.
- Disposable Supabase database migration and full pgTAP suite.
- Independent-session database concurrency script.
- Linux, Windows and macOS CI and Desktop workflows.
- Relevant forwarding E2E tests.

The existing workflows are triggered by PR synchronization, but a workflow run must be observed against the final immutable commit SHA before it can be reported as evidence.

## Production dependencies and operational controls

The following are not provisioned by C166:

1. Primary checkpoint verification public key and key-rotation/retirement procedure.
2. Independently administered witness public keys, strict-majority quorum policy, operator separation, monitoring and disaster recovery.
3. Independent route-authorization verification key ID/public key.
4. Production audit hostname, SPKI pins, pin overlap/rotation procedure and secure release build provisioning.
5. Production migration execution and verification in the target Supabase project.
6. Audit retention, immutable backup policy, restore drills and evidence export/retention ownership.
7. A production primary/witness fencing protocol and independent authority implementations described above.

No credentials, private keys, trust anchors, production pins, migration deployments or external provider configuration were created or changed by this work.
