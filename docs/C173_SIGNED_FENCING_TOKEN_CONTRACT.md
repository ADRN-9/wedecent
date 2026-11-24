# C173 — signed common fencing token contract

## Scope and status

This increment adds a provider-neutral signed token wire contract in
`internal/portforward/checkpoint_fence.go`. It is not a production primary,
witness service, network adapter, durable store, or integration into
`WitnessedReplayCheckpointProvider`. The legacy Consume/Revoke/Head path remains
unchanged and must not be treated as distributed finalization fencing.

## Authoritative ordering rule

One primary assigns the next per-scope fence generation using an atomic durable
compare-and-append against `ExpectedFenceGeneration`. A successful operation has
exactly `Generation = ExpectedFenceGeneration + 1`. Both `finalize` and `revoke`
consume this same sequence. A finalize token preserves the expected revocation
epoch. A revoke token advances it by exactly one. A primary must durably reserve
the stable operation ID and its complete request fingerprint before returning
the signed token. An exact retry returns the byte-identical token; reusing the
operation ID with different action, generation, request, authorization, scope,
or witness set is a terminal conflict.

The primary signature covers the canonical token payload, including participant
scope, both expected and resulting epochs, expected and resulting fence generation,
stable operation ID, request and authorization digests, primary head binding,
previous fence digest, witness-set version and sorted witness IDs, expiry, and
primary key ID. Witness IDs are sorted only for canonical encoding; duplicates
are rejected. A three-or-more-member fixed witness set is mandatory and its
strict-majority threshold is `floor(n/2)+1`.

Each witness must verify the primary token and atomically compare its own durable
generation. It rejects lower generations, same-generation/different-token
conflicts, stale epochs, expired tokens, and tokens from an unconfigured witness
set. It persists its acknowledgement before responding. The primary commits the
outcome only after receiving a valid strict-majority of acknowledgements bound to
the exact token digest. The finalization audit boundary must independently verify
the primary token and matching witness quorum; ordinary checkpoint acknowledgments
and current-head reads do not substitute for fence acknowledgments.

## Race semantics

- **Revocation first:** revoke reserves generation N and commits with quorum.
  Any finalize token based on generation N-1 is rejected by the primary and by
  every witness that has observed N. A finalize retry cannot obtain a new
  generation under the old operation ID.
- **Finalization first:** finalize reserves generation N and commits with quorum.
  It is valid at that authoritative ordering point if its expected revocation
  epoch matched. A later revoke may reserve N+1, but cannot retroactively
  invalidate the already committed ordering decision. The service must retain
  both outcomes in its durable history.
- **Partial quorum / partition:** neither operation is considered committed
  without the primary plus strict-majority commitment. No single-provider,
  local-lock, or stale-head fallback is permitted.
- **Lost response / restart:** retry or load by the original operation ID and
  exact token. Never mint a replacement generation or rebuild evidence from
  newer heads. Conflicting operation outcomes fail closed.

## Code added

- `CheckpointFenceToken` and `CheckpointFenceRequest`.
- Primary and witness service interfaces for reserve, quorum commit, and exact
  operation/generation recovery.
- Canonical domain-separated token encoding and SHA-256 digest.
- Ed25519 primary token signing and verification, including expiry, key ID,
  monotonic generation, action-specific revocation epoch transition, and fixed
  witness-set validation.
- Strict-majority calculation requiring at least three witnesses.
- Unit tests for canonical witness ordering, signature tampering through payload
  mutation, stale generation, expiry, epoch transition, duplicate witness IDs,
  and quorum sizing.

## Explicit limitations

The current increment does **not** implement witness acknowledgement signatures
or validation, primary/witness durable transactions, quorum collection, network
transport, TLS 1.3/SPKI pinning, endpoint trust provisioning, witness-set rotation,
or production recovery. The new interfaces are a compile-time contract only.
The deterministic checkpoint/witness implementations remain test harnesses.

The new contract has not yet been wired into the consume/revoke/finalize lifecycle.
The two race orderings therefore remain unproven in the running system. No
production authorization or finalization may rely on this token model until the
primary and all witnesses implement the durable protocol and the external
cross-host adversarial suite passes.
