# C151 — production witness adapter feasibility and exact verification

Date: 2026-11-24

## Exact repository state recovered

- Repository: ADRN-9/wedecent
- PR: #186, open and draft; branch `feat/secure-port-forwarding-foundation`
- Exact inspected HEAD before this documentation commit: `7018b35a2fb4a2dccc7c86635a27b6f986b6bc30`
- The PR HEAD matched the C150 handoff. No C150/C149 source changes were duplicated or overwritten.
- Existing witness implementation: `internal/portforward/replay_witness.go`
- Existing durable pending journal: `internal/portforward/checkpoint_pending.go`
- Existing signed participant request: `internal/portforward/checkpoint_request.go`
- Existing deterministic adversarial suite: `internal/portforward/replay_witness_test.go`

## Adapter decision: do not invent a production wire protocol

The repository contains a provider-neutral Go interface, not a production network protocol contract.

`CheckpointWitness` exposes four semantic operations:

- `Commit(context.Context, CheckpointRequest, CheckpointReceipt)`
- `Revoke(context.Context, CheckpointEndpoint, uint64)`
- `Acknowledge(context.Context, CheckpointRequest, CheckpointReceipt)`
- `Head(context.Context, CheckpointWitnessScope)`

C126, C128 and C129 specify security and persistence semantics. They do not specify interoperable witness HTTP request/response envelopes, canonical serialization, endpoint paths, authentication headers or mutual-authentication policy, idempotency keys, error/status mapping, provider-side transaction schema, or an independently operated server implementation. C129 explicitly says network adapters are unavailable and must be implemented once the production services are supplied.

Consequently, adding a client with guessed JSON payloads or guessed routes would create an unsupported protocol that no production witness is known to implement. It would not satisfy the assignment's production requirement and could falsely imply that signed acknowledgements and quorum were remotely enforced. No such adapter was added.

The legacy `RemoteReplay` client is not reused: it speaks the Supabase single-provider protocol, and `NewProductionRemoteReplay` correctly rejects that path. The deterministic witness implementation remains test-only.

## Security contracts already present in source

- TLS 1.3 and leaf-certificate SPKI pinning exist in the legacy pinned replay transport, but do not constitute a witness adapter.
- Witness trust is independently represented by distinct `CheckpointWitnessTrust` Ed25519 public keys and IDs.
- `validWitnessSet` rejects duplicate IDs, duplicate signing keys, primary-key reuse and non-strict-majority quorum configurations.
- Receipts, acknowledgements and heads have distinct Ed25519 signed message encodings and key-ID binding.
- Witness receipt/head records bind generations, predecessor hashes, primary generations/heads and revocation epochs.
- Durable pending state is bounded, validates persisted evidence and requires quorum acknowledgements before compaction.
- The signed checkpoint request binds initiator, destination and, for routed requests, router identity/account/organization/revocation epoch.

These are repository-level protocol foundations, not proof of a running independent service.

## Existing adversarial regression inventory

Source inspection of `replay_witness_test.go` found existing coverage for:

- forged witness receipt signatures;
- malformed/forged acknowledgement signatures and signed wrong-scope/wrong-fingerprint acknowledgements;
- quorum loss and retry after unavailable witnesses;
- primary and witness ledger-plus-signing-key rollback simulations;
- conflicting JTI/request fingerprints;
- signed wrong-scope heads and quorum scope mismatch;
- lost acknowledgement responses and recovery after restart;
- interrupted acknowledgement persistence and compaction;
- corrupt/ambiguous pending journal recovery;
- stale initiator, destination and router revocation epochs;
- commit/acknowledgement versus revocation races in the deterministic witness;
- persisted acknowledgements rejected after later membership revocation.

Important limitations:
- These tests use deterministic in-memory authorities or local file journals; they are not network integration tests.
- The source suite does not prove independent administrative ownership, KMS/HSM non-exportability, real TLS pin rotation, service-side durability, multi-region failover, or real provider rollback resistance.
- No explicit test was found for a single configured witness equivocating by returning two differently signed acknowledgement bodies for the same operation across retries. The production protocol must define and test equivocation detection and durable witness-side idempotency.

## Distributed revocation/finalization analysis

The existing `FinalizeWithAudit` flow authenticates historical witness acknowledgements and rechecks the complete signed participant vector before the audit callback. The source comment correctly states that this does not eliminate the cross-service race. C139 also correctly limits the deterministic witness mutex to its local test fixture.

The current API has no shared durable finalize/revoke fence or prepare/commit operation. A client-side second read of primary and witness heads cannot make a distributed check-and-release atomic: revocation can advance after the last read and before the finalization callback/session release. A process mutex or the existing PostgreSQL primary transaction cannot order an independent witness service.

A production protocol must be designed and implemented jointly by the primary authority, all witnesses and the membership/revocation authority. At minimum its server-side contract must provide:
1. A canonical, signed participant vector with immutable account/organization IDs and monotonic epochs for initiator, destination and router.
2. A durable operation ID and exact request/receipt digest binding, with replay-safe idempotency.
3. A durable fencing/lease or transactional state machine that orders revocation against finalization across every participant and every authority whose approval is required.
4. A prepare phase that prevents a participant epoch from changing unnoticed, followed by a quorum-backed commit decision; or an equivalent consensus/transaction protocol with a documented linearization point and crash recovery.
5. A durable terminal outcome for committed, revoked, aborted and ambiguous operations. Session release must be forbidden unless the final committed decision is authenticated; timeout or partial commit must remain unavailable pending reconciliation.
6. Witness-side monotonic generation and anti-equivocation state, including durable rejection of conflicting operation IDs, request digests, participant vectors or terminal outcomes.
7. Explicit failure/recovery semantics for partition, quorum loss, service restart, key rotation, stale fencing tokens, rollback and delayed messages.

No service owner, canonical membership transaction, participant-fencing endpoint, or provider protocol specification is present in the repository context inspected for C151. Implementing a client-side imitation would not establish the guarantee.

## Exact-HEAD verification recovered

- CI run 45355993989: completed successfully on exact pre-documentation HEAD `7018b35a2fb4a2dccc7c86635a27b6f986b6bc30`.
- Desktop run 45355994044: exact same HEAD; Windows and macOS Tauri jobs succeeded. Linux Tauri remained `in_progress` on the latest retrieved jobs response; prerequisite installation and shell compilation had not completed. No full Desktop pass is claimed.
- These runs predate this C151 documentation-only commit. They are not exact-HEAD verification for the new commit.
- No local checkout or Go toolchain was available through the GitHub connector. No local test command was run.
- No production witness adapter, endpoint, credential, pin, trust anchor, or infrastructure was provisioned.
- No merge, approval, force-push or deployment was performed. PR #186 remains open and draft.

## Required external inputs to resume adapter implementation

The service owners must supply a versioned, reviewed protocol specification and test server contract covering:
- primary checkpoint consume/recover/head/revoke operations;
- witness commit/acknowledge/head/revoke operations;
- canonical wire encoding and strict decoding rules;
- TLS hostname/port/SPKI pin provisioning and rotation;
- independent Ed25519 public-key IDs, signing key custody and rotation;
- authentication/authorization of Local Core to each service;
- participant membership and revocation authority semantics;
- durable transaction, generation, idempotency, equivocation and rollback behavior;
- bounded request/response sizes, timeout/retry and ambiguous-outcome rules;
- independent operator, backup, restore and audit domains.

Until those contracts and authorities exist, production witness integration and distributed finalization acceptance remain blocked by design. The existing production forwarding path must continue to fail closed rather than fall back to single-provider replay.
