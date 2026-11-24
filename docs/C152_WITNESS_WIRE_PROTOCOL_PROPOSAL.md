# C152 — Witness wire protocol proposal

**Status: proposal only — requires review and approval by the primary, witness and identity-service owners.**

This document proposes a versioned protocol for the existing provider-neutral replay/witness interfaces. It does not describe a deployed protocol. It defines no production hostnames, URLs, credentials, TLS pins, signing keys, or trust anchors. No adapter may be enabled against this proposal until the service owners approve a normative contract and provide independently operated conformance endpoints.

## 1. Security goals and non-goals

The protocol must preserve the signed Local Core checkpoint request as the source of device and participant identity. Network addresses, TLS client certificates, account login sessions, transport identifiers and service routing are not device identity.

Required properties:

- TLS 1.3 for every primary and witness connection, with exact configured endpoint SPKI pin verification in addition to normal certificate-chain and hostname verification.
- Separate, independently provisioned Ed25519 signing trust anchors for the primary and each witness. A witness key must not be reused as a primary, device, route-authority or control-plane key.
- Independent client authentication to each service. Proposed deployment profile: per-service mTLS client identity plus an application-level Ed25519 request proof bound to the canonical body, audience, method, protocol version, timestamp window and one-time nonce. The client identity authorizes the Local Core installation; the device-signed checkpoint capability remains the device authorization.
- Strict-majority witness quorum: for N configured distinct witnesses, Q must satisfy floor(N/2) < Q <= N. Duplicate witness IDs or public keys invalidate configuration.
- Durable idempotency, monotonic generations, anti-equivocation and fail-closed ambiguous-outcome recovery.
- No fallback to the legacy single-provider replay endpoint or deterministic in-memory witnesses.

The protocol does not claim that TLS, mTLS, signatures or a local journal alone provide distributed atomicity.

## 2. Versioning and canonical serialization

Proposed media type: `application/vnd.wedecent.checkpoint+cbor; version=1`.

Proposed encoding: deterministic CBOR under RFC 8949, with a closed schema for every message. Maps use integer field labels in strictly increasing canonical order. Integers use shortest encodings. Text is UTF-8 and must be valid Unicode. Byte strings carry hashes, public keys and signatures. Indefinite-length values, duplicate map keys, unknown critical fields, trailing bytes, non-canonical encodings, invalid UTF-8, oversized bodies and unsupported versions are rejected before signature or state processing.

Every signed object includes:
- protocol name and version;
- message type and operation;
- service audience and configured service identity;
- canonical operation ID;
- canonical request digest;
- exact participant vector digest;
- issue time and bounded validity where applicable;
- signer key ID and Ed25519 signature.

Signatures use domain-separated, length-delimited message construction over the deterministic CBOR payload with the signature field omitted. A hash is SHA-256 over the exact canonical unsigned payload. JSON translation or reserialization by intermediaries is forbidden.

All request and response schemas have explicit maximum encoded sizes, string lengths, array counts, nesting depth and deadline bounds. Unknown optional fields are allowed only in a version-defined extension map; unknown critical extensions fail closed.

## 3. Common operation and participant binding

Each logical operation has a cryptographically random 256-bit `operation_id` generated once by Local Core and durably recorded before the first network call. Retries reuse the same ID and byte-identical canonical request. A different request must never reuse an operation ID.

The canonical request binds:
- JTI and authorization digest;
- complete signed checkpoint request and device signature;
- primary receipt digest when one exists;
- initiator, destination and optional router device/account/organization IDs;
- each participant's monotonic revocation epoch;
- route authorization digest and route authority key ID when routed;
- Local Core identity and intended service audience.

The server recomputes all digests and verifies device/control-plane/route signatures independently. It must not trust a client-supplied participant digest without recomputing it from the full signed vector. Membership and permission records are loaded from the canonical authorization source, not inferred from an account login token.

A duplicate operation ID with a different request digest, participant vector, audience, operation type or authorization digest returns a signed conflict response and creates no new state.

## 4. Primary service operations

The primary service owns the authoritative single-use replay ledger and primary receipt chain.

### Consume

Accepts a signed checkpoint request, operation ID and client proof. In one durable transaction, validates device signature, authorization digest, complete participant membership, organization/device permissions and revocation epochs; checks JTI uniqueness; records the consume; increments the monotonic primary generation; and creates a signed primary receipt.

The transaction must bind the exact participant vector and observed membership/revocation versions. If the membership authority is external, it must participate in a supported fencing/transaction protocol; pre-read membership checks are not sufficient.

A repeated identical operation returns the exact previously committed receipt and a distinct `recovered` disposition. A different request using the same operation ID or JTI returns a signed conflict/replay response.

### Recover

Queries durable operation state by operation ID and request digest. It returns one signed, terminally classified result: committed with the exact receipt, aborted, revoked, pending/ambiguous, or unknown. Unknown or pending never means safe to retry with a new operation ID.

### Head

Returns a signed primary generation, record hash, previous hash, key ID and current revocation epoch for an exact participant scope. A head response is informational; it does not itself reserve membership or authorize finalization.

### Revoke

Advances a participant's monotonic revocation epoch. The update must use compare-and-set against the expected prior epoch and durably fence every outstanding operation containing that participant. Replays of the same revoke operation are idempotent; lower epochs and conflicting same-epoch content fail.

## 5. Witness service operations

Each independently administered witness has its own durable ledger, signing key, backup/restore domain and operator authorization.

### Prepare / Commit

The witness validates the primary receipt signature, request digest, operation ID, full participant vector, primary generation and participant revocation fences. It durably records one immutable vote for that operation and advances its own monotonic witness generation and hash chain.

A witness may not vote twice with different request digests, receipt digests, participant vectors, primary generations or outcomes. Repeated identical requests return the exact same signed vote. A conflict is durably recorded as equivocation evidence and returns a signed conflict; it is never counted toward quorum.

### Acknowledge

Acknowledgement is a durable terminal vote over the exact prepared operation, primary receipt digest, participant vector and final decision. The canonical signed object carries an explicit `decision` value (initially `committed`, `revoked` or `aborted`). Repeated requests return the same canonical terminal outcome. The service must not alternate semantic terminal outcomes such as committed and revoked for the same operation.

A response status such as `already_acknowledged` may be used only as transport/retry metadata. It is not part of the signed terminal decision and must not change the signature. The signed `decision` value remains identical across retries. Clients compare decision and operation bindings, not retry status.

The current provider-neutral Go representation follows this rule with an explicit `Decision` field and unsigned `Status` metadata. Its acknowledgement signature domain is versioned as `wedecent-independent-witness-ack-v2`; the decision is signed and status is excluded. This is an internal compatibility boundary, not a deployed CBOR wire adapter. A production adapter must map the same decision/status separation into the approved deterministic-CBOR schema and publish conformance vectors before deployment.

A persisted acknowledgement and a later, correctly signed acknowledgement for the same witness, operation ID, request digest, receipt digest and participant scope but a different terminal decision are equivocation. The client must preserve the original vote, durably append both signed objects as evidence, make the operation terminally conflicted, and deny finalization. Invalid signatures, malformed decisions, or responses bound to a different operation are not equivocation evidence and must not poison the journal.

The local pending-journal schema is versioned independently from the proposed remote CBOR protocol. The Decision/signature-domain change advances the local journal to version 3. Version-2 journals containing status-signed acknowledgements are rejected rather than silently reinterpreted as version-2 terminal decisions. A production rollout must provide a reviewed migration/recovery path for existing in-flight version-2 journals; this repository change does not fabricate replacement witness signatures or discard old evidence.

### Head

Returns a signed witness generation, record hash, previous hash, primary generation/head, participant revocation epoch, witness key ID and scope. A witness head must be monotonic and must not be restored from backup without reconciliation against independent witnesses and an external monotonic anchor.

### Revoke

Advances the witness's own participant revocation fence using compare-and-set and fences any prepared operation that has not crossed the agreed finalization linearization point. It is durable and idempotent.

## 6. Distributed prepare, finalize and revocation ordering

A client-side sequence of primary consume, witness commits, acknowledgements and repeated head reads cannot atomically order revocation against session release. The production design therefore requires a service-side distributed state machine, not a client mutex or a local database transaction.

Proposed states:

1. `NEW`: operation ID and canonical request are durably recorded by Local Core.
2. `PRIMARY_COMMITTED`: primary has atomically consumed the JTI and returned its signed receipt.
3. `PREPARED`: a strict majority of witnesses have durably voted for the exact receipt and participant vector.
4. `FINALIZE_PENDING`: the coordinator has durably recorded the exact prepare quorum and requested the terminal decision.
5. `FINALIZED`: the primary and witness quorum have durably accepted the same committed decision under a shared fencing token/epoch.
6. `REVOKED` or `ABORTED`: the operation has a durable terminal negative decision.
7. `AMBIGUOUS`: a timeout or partial commit prevents proof of one terminal decision; no session may be released.

The linearization point must be specified and implemented by the service owners. The proposed requirement is a durable fencing token issued by a membership/revocation authority, bound to the complete participant vector and checked transactionally by the primary and every witness during finalize. Revocation and finalization must contend on the same authoritative participant fences. A service may not acknowledge finalization using a stale token.

If the authorities cannot share a transactional fencing service, the owners must provide an equivalent consensus protocol with formal safety properties, durable prepare records, commit certificates, idempotent recovery and a proof that a successful revocation cannot be ordered before a later stale finalize. A collection of sequential HTTP calls is not an equivalent.

Session release requires a signed finalization certificate containing the operation ID, request and receipt digests, full participant-vector digest, fencing token, primary decision and distinct witness quorum signatures. Any timeout, missing signature, disagreement, stale epoch, unavailable authority or ambiguous state denies release.

## 7. Quorum and disagreement rules

- Count only distinct configured witness IDs with valid signatures, expected key IDs, exact scope, operation ID, request digest, receipt digest, participant vector and compatible generation chain.
- Reject duplicate witness IDs, duplicate signing keys, primary-key reuse, malformed signatures and unknown key IDs.
- A strict majority is mandatory. No configurable minority fallback exists.
- Any two valid but incompatible signed decisions for the same operation constitute equivocation. Do not choose the newest response, majority of conflicting responses, or first response. Preserve evidence, fail closed and require service-owner incident handling.
- A quorum of acknowledgements cannot override a primary conflict, stale participant epoch, missing route authorization or revoked terminal outcome.
- A witness timeout is unavailable, not a negative vote. Quorum loss is unavailable; it must never downgrade to single-provider mode.

## 8. Crash recovery and ambiguous outcomes

Local Core persists the operation ID, canonical request, exact primary receipt, each signed witness vote, each signed terminal acknowledgement and finalization certificate in an owner-only durable journal before advancing its local state.

After restart:
- Query primary Recover with the original operation ID and request digest.
- Query witness heads and operation status using the original operation ID.
- Validate all signatures, key IDs, generations, hash-chain links and participant fences.
- Resume only the missing idempotent protocol step.
- Never create a new operation ID for an ambiguous operation.
- Never treat absence from the local journal as proof that the primary or witnesses did not commit.
- Never release a session from a `PRIMARY_COMMITTED`, `PREPARED`, `FINALIZE_PENDING` or `AMBIGUOUS` state.

The services must retain idempotency and equivocation records for at least the maximum authorization lifetime plus the configured replay/audit retention period. Journal compaction requires a verifiable finalization certificate and durable service-side retention guarantees.

## 9. Key rotation, restoration and endpoint pins

Key records have stable key IDs, purpose, service identity, validity window, activation time and revocation state. Rotation uses overlapping trust periods with an authenticated transition signed by both the old and new key, plus out-of-band operator approval for trust-anchor changes. A missing or invalid transition fails closed.

TLS SPKI pins are provisioned out of band for each exact service hostname and are separate from Ed25519 signing anchors. Pin rotation requires an authenticated signed configuration update with overlap; hostname verification, normal chain validation and TLS 1.3 remain mandatory. No trust-on-first-use or silent pin refresh is permitted.

Witness restore procedures must compare restored generation/hash state with independently administered witnesses and a monotonic external checkpoint. Restoring both a database and its matching signing key from the same historical backup must not make old history appear current. If a witness cannot prove it has not rolled back, it is removed from quorum until reconciled and re-enrolled under a reviewed procedure.

## 10. Client behavior and transport requirements

The proposed Go adapter must implement the existing `CheckpointWitness` and primary provider interfaces without changing device identity semantics. It must use bounded HTTP/2 or HTTP/3 only if approved by service owners; the initial interoperable profile should choose one transport explicitly. Each request has strict deadlines, bounded bodies, context cancellation, no redirects, no proxy bypass of configured pin enforcement and no credential forwarding across origins.

Retries are limited to idempotent operations with the exact same operation ID and canonical request. A timeout after a potentially committed operation is ambiguous and must invoke Recover, not issue a new operation. Error mapping is typed and fail-closed. Response decoding rejects duplicate keys, unknown critical fields, non-canonical payloads and signature mismatch.

The adapter must have adversarial integration tests against independently running primary and witness services for replay, conflicting acknowledgements, delayed responses, quorum partition, concurrent revoke/finalize, stale generations, service restart, key rotation, database/key rollback, backup restore and malformed wire encodings.

## 11. Required service-owner decisions before implementation

The following are unresolved and cannot be inferred from this repository:

- Whether the primary, membership/revocation authority and witnesses can participate in a shared fencing/consensus protocol.
- Canonical membership and device-group authorization schema and transaction ownership.
- Service identity and independent client-authentication mechanism.
- Production endpoint names, ports, TLS certificate issuance, SPKI pins and rotation channel.
- Ed25519 signing-key custody, KMS/HSM requirements, key IDs and recovery.
- Witness operator independence, quorum size, regions, backup/restore and audit retention.
- Canonical deterministic CBOR schema registry and conformance vectors.
- Idempotency retention, operation status, conflict/equivocation incident procedures and service SLOs.

This proposal intentionally invents none of these production values. The next deliverable is a jointly reviewed normative protocol and service-side implementation plan, followed by independently operated conformance environments. Until then, production witnessed forwarding remains unavailable and must fail closed.
