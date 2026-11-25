# Distributed checkpoint fencing

## Current implementation boundary

The local protocol model is present in `internal/portforward/replay_checkpoint.go` and
`internal/portforward/replay_witness.go`:

- Primary receipts and heads are signed and chained by monotonic generations.
- Witness receipts, acknowledgements, and heads are signed and bound to request,
  scope, primary receipt, and revocation state.
- `WitnessedReplayCheckpointProvider` requires a strict-majority witness quorum.
- `FileCheckpointPendingStore` persists client intent and recovery evidence. It is
  explicitly not replay authority.
- `deterministicCheckpointWitness` is a test harness only, not a production provider.
- `NewProductionRemoteReplay` rejects the legacy single-provider replay path.

These pieces do not yet constitute a deployed distributed fencing service. There is
no production `CheckpointWitness` network adapter or independently operated witness
service in this repository. The in-memory deterministic witness tests cannot prove
cross-host durability or availability independence.

## Required authority topology

Production must provision one primary authority and at least three witness authorities
for a quorum of two, with independent state and signing keys. The primary and each
witness must run in separately administered failure domains. A single Supabase project,
a shared database, or several processes sharing one database is not an independent
witness quorum.

Each authority must expose an authenticated, TLS 1.3 endpoint with independently
approved hostname and SPKI pins. The device identity and signed authorization remain
the authority's input; network address, relay, or transport identity is never an
authorization substitute.

## Required durable operation contract

Every authority must implement the following operations using a transaction or
durable compare-and-append primitive local to that authority:

1. **Consume**: validate the device-signed request and exact primary receipt; reject
   stale revocation epochs; compare the expected previous head; append exactly one
   record with generation `previous + 1`; return a signed receipt.
2. **Revoke**: serialize against consume for every affected endpoint; append the
   revocation epoch and new generation; return a signed receipt.
3. **Acknowledge**: acknowledge only a previously committed exact receipt and request
   fingerprint; return a signed, idempotent acknowledgement.
4. **Head**: return the signed current generation, record hash, and revocation epoch.

The operation key is the stable tuple of endpoint scope and JTI, bound to the
canonical request fingerprint. Repeating an identical operation must return the
original signed result. Reusing an operation key with different bytes must fail as a
conflict. A crash after durable append but before response must be recoverable by an
exact retry. A partial quorum must never authorize finalization.

Finalization and revocation must have a single linearization order at the primary and
at each witness. A witness may acknowledge only if its durable state has not advanced
past the request's endpoint revocation epochs. The client must collect a strict
majority of independently verified witness acknowledgements and persist the exact
evidence before the external audit sink is called.

## Required verification before production

- Run at least three independently configured witness services with separate signing
  keys and durable stores.
- Race consume/finalize against revoke in both orders across separate processes and
  hosts; prove that no acknowledgement is issued after the revocation fence wins.
- Kill and restart each service between append and response, and between quorum
  acknowledgement and finalization audit submission.
- Verify exact retries, conflicting retries, stale generations, stale epochs,
  malformed signatures, forged receipts, witness equivocation, unavailable primary,
  unavailable minority, and unavailable quorum.
- Demonstrate that loss or rollback of one witness cannot make an old generation
  authoritative and that witness state cannot be reset by the application service
  account.

## Provisioning dependencies

The repository owner must provision and independently approve:

- the primary authority endpoint, durable storage, signing key, and rotation policy;
- at least three witness endpoints, each with its own durable storage, signing key,
  operator boundary, and rotation policy;
- the strict-majority quorum configuration and per-endpoint TLS hostname/SPKI pins;
- service-to-service credentials with least privilege and no application ability to
  delete, reset, or rewrite authority history;
- operational monitoring, backup/restore procedures that preserve monotonic heads,
  and an incident procedure for suspected witness rollback or equivocation.

Until a production network adapter, independent witness services, and cross-host race
evidence exist, distributed fencing remains an implementation and infrastructure
acceptance blocker. Do not enable the single-provider replay path as a fallback.
