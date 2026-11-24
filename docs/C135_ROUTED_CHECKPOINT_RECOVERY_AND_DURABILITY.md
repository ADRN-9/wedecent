# C135 — Routed checkpoint recovery, revocation reconciliation and durability

## Scope and exact implementation

C135 starts from C134 HEAD `9cd38b0c71538e6ff768262857d856ba686bf1e4`. It addresses the routed-recovery and current-membership gaps found by independent source inspection.

### Routed historical finalization

- `mesh.RouteAuthorizationVerifier.VerifyHistorical` validates the route capability's syntax, key ID, Ed25519 signature and exact router/route binding. It deliberately does not check the current expiry and does not consume the route JTI.
- The ordinary `VerifyAndConsume` path is unchanged: it still rejects expired capabilities and consumes the JTI for new routed operations.
- `MeshCheckpointRouteAuthorizationVerifier` exposes distinct normal-consumption and historical-verification methods. Finalization requires the historical interface and fails closed if it is absent.
- `CheckpointRequest.RouteAuthorizationSHA256` binds the exact independent route capability JSON (including its signed JTI/signature) into the device-signed checkpoint request and primary receipt. The extension is encoded only when nonzero, preserving the previous request encoding for non-routed operations. Finalization recomputes and compares it, preventing substitution of another valid route capability for the same route.
- Regression coverage runs a routed operation through checkpoint commitment, advances beyond both capability expiries, then finalizes the exact historical operation without another primary consumption or witness commitment. Mesh-level tests prove historical verification does not consume the route JTI and that expired capabilities still cannot initiate fresh operations.

### Current membership and revocation

- Finalization now requires a current `CheckpointMembershipResolver` and a `CheckpointFinalizationAuditor`; missing dependencies fail closed.
- Both endpoint memberships are resolved again immediately before historical finalization. Device IDs, account IDs, organization IDs and revocation epochs must exactly match the signed original checkpoint request.
- Revocation epoch changes, missing/revoked membership and organization/device mismatches produce a rejected-revocation audit outcome and prevent finalization.
- Membership-service failures are separately recorded as membership-unavailable and fail closed.
- The audit contract records `finalization_started`, `finalized`, `rejected_revocation`, `membership_unavailable` and `finalization_failed`. An audit sink failure is not treated as success.
- Regression coverage injects a durable local-resolution failure after witness commitment, advances time beyond expiry, changes an endpoint revocation epoch, and proves finalization rejects the historical operation without changing witness history.

## Production integration assessment

The repository currently exposes `supabase/functions/port-forward-replay` for the legacy single-provider replay protocol, plus route-authorization issuance. It does not contain a production checkpoint primary recovery endpoint, independent witness commit/ack/head/revoke endpoints, or an authoritative membership-resolution endpoint for this checkpoint protocol. `NewProductionRemoteReplay` explicitly rejects single-provider production fallback. The pinned legacy client does demonstrate TLS 1.3 and optional SPKI pinning, but it is not a witnessed checkpoint adapter and cannot safely be repurposed as one.

Accordingly, no production primary recovery or witness network adapter is claimed or substituted with deterministic providers. Safe integration requires independently operated service contracts/endpoints and provisioning of:
1. Primary checkpoint consume/recover/head/revoke endpoint and signing public key/key ID.
2. At least three independently administered witness endpoints, distinct signing keys/key IDs and quorum policy.
3. Per-endpoint TLS 1.3 hostname/port and SPKI pin sets.
4. Authenticated membership/revocation resolver with stable account/organization IDs and monotonic revocation epochs.
5. A durable audit sink and operational retention policy.

These are infrastructure and trust-anchor inputs, not values that can be inferred or safely fabricated in repository code. Once supplied, independent adapters and real-provider rollback/recovery tests can be integrated. Until then, production finalization must remain unavailable.

## Durability and concurrency status

C134's structural journal validation, byte/entry bounds, duplicate-key rejection, unrelated-entry corruption rejection, and whole-publication interruption preservation remain in place. C135 does not yet add process-termination injection at every atomic-publication stage (temporary-file creation, partial write, file sync, close, replacement, directory sync and lock release), nor a cross-process concurrent-finalization test across separate provider processes. The existing same-process idempotence/concurrency coverage is not a substitute for those tests.

Journal-wide cryptographic verification of every acknowledgement in every unrelated entry against immutable trust anchors also remains incomplete. Exact-operation acknowledgement loading and compaction verify signatures against configured witness trust; that does not prove all unrelated entries are cryptographically checked on every journal read-modify-write.

## Acceptance boundary

This document records source changes and outstanding work. Deterministic tests are not production-provider acceptance. No production credentials, trust anchors, signing keys or infrastructure endpoints were provisioned. No merge, production signing, deployment or activation was performed. PR #186 remains open and draft pending exact-HEAD CI, all Desktop workflows and independent security acceptance.
