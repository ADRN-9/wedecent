# C126 — provider-independent replay checkpoint contract

Status: **Contract and deterministic test harness only. No production checkpoint provider is implemented or configured.** The current production RemoteReplay path still uses the Supabase RPC documented in C124 and therefore remains inside the Supabase database rollback domain.

## Contract added

internal/portforward/replay_checkpoint.go defines ReplayCheckpointProvider with Consume, Revoke and Head operations. The contract is provider-neutral and deliberately does not choose Cloudflare, Supabase, a second SQL database, or a particular vendor.

Each request binds:
- both forwarding endpoint device IDs;
- each endpoint's immutable canonical account UUID and organization UUID;
- each endpoint's current revocation epoch;
- the consuming endpoint's Ed25519 public key and proof;
- the single-use JTI and exact SHA-256 digest of the signed authorization.

The consumer public key must derive the claimed WeDecent device ID. Both endpoints must be members of the same organization; provider implementations must independently check current membership for each endpoint. The request proof covers all fields, including both account identities and revocation epochs.

The provider commits one monotonically increasing generation per consuming device/account/organization namespace and an append-only hash-chain record. A provider-signed receipt binds the request fingerprint, exact authorization digest, JTI, consumer identity, generation, previous hash and record hash. A signed head supports recovery/reconciliation. Receipt verification is pinned to the independently provisioned provider Ed25519 public key; provider key IDs are derived from that public key.

## Idempotency and linearization

An exact request retry returns the same durable receipt, including after an ambiguous lost response, but the result is explicitly marked Recovered rather than Committed. Reuse of a JTI with a different request fingerprint or authorization digest is a conflict. A Recovered result may resolve only a locally recorded pending operation with the exact request fingerprint; if the caller cannot prove that pending operation, it must fail closed and must not start a new forwarding session. This prevents an idempotency response from becoming a second authorization. The provider must serialize Consume and Revoke against the same durable state:
- If consumption linearizes first, that consumption is committed, but subsequent operations using the old revocation epoch are rejected.
- If revocation linearizes first, consumption with the old epoch is rejected.
- A new request must carry current endpoint membership and revocation epochs.
- A timeout with unknown commit outcome is ambiguous; the caller retries the exact same signed request and verifies the returned receipt.
- No local replay fallback, generation reset, or automatic reinitialization is permitted.

The contract returns a disposition with every receipt: Committed means this call created the durable record; Recovered means the exact record already existed. VerifyCheckpointResult checks the provider signature and this disposition. The contract's Head returns the provider's signed current generation, chain head and revocation epoch. Recovery must compare this result to retained receipts and independently protected state. It must not infer a zero generation from a missing local cache.

## Deterministic fake-provider harness

internal/portforward/replay_checkpoint_test.go supplies a deterministic in-memory provider implementing the contract. It exercises:
- concurrent identical consumption and exact-request idempotency;
- concurrent revocation/consumption ordering;
- crash before commit and crash after commit with lost response;
- exact retry and receipt recovery;
- conflicting JTI reuse with a changed authorization digest;
- unavailable authority and malformed identity;
- forged/corrupted receipts;
- simulated full primary-database snapshot restoration while the external fake checkpoint remains intact;
- independent device replay namespaces and cross-account membership rejection;
- provider restart and signed-head reconciliation;
- a simulated single-provider compromise that restores its own state and signing key.

The fake provider is deliberately not production storage. The simulated primary-database restore demonstrates only that a distinct checkpoint state object is not rolled back when a separate primary-state map is restored. It does not demonstrate real backup/restore, provider durability, network authentication, administrative separation, or rollback resistance. The compromise test deliberately demonstrates that a single provider which can roll back its own ledger and signing authority can replay its own valid history.

## Production integration contract and infrastructure gates

A production implementation must satisfy all of the following before it can replace the current replay authority:

1. **Independent ownership:** provider organization, cloud account, administrators, break-glass access, service credentials and destructive recovery authority must be outside the Supabase project/database administrator's control. A second schema, database or bucket with shared administrative recovery is not independent.
2. **Durable transaction:** atomically serialize membership/revocation checks, unique (consumer device, account, organization, JTI) enforcement, generation allocation, hash-chain append and receipt creation. A durable receipt must survive process restart and region failover.
3. **Append-only/tamper evidence:** application principals must not update/delete historical records or rewind generation. Export verifiable receipts/checkpoints to independent retention or witness storage.
4. **Independent backups:** checkpoint backups, retention locks, restore permissions and recovery tests must be separately controlled. Restoring the primary database must not restore or rewind checkpoint history.
5. **Authentication and TLS:** authenticate endpoint Ed25519 proofs and both endpoint memberships. Provision a separately reviewed provider endpoint hostname and TLS trust pins; do not accept URL, API key, DNS, relay metadata or account-session values as identity.
6. **Signing keys:** provider receipt signing keys must be held in a managed non-exportable KMS/HSM where possible, with documented rotation, overlap, revocation and recovery. Pin public key IDs in endpoint release trust configuration. Device private keys never leave their existing identity boundary.
7. **Administrative auditability:** log membership decisions, revocations, consumption, conflicts, recovery, key operations, backup/restore, administrative access and policy changes in a separately retained audit trail.
8. **Provider compromise:** assume a provider administrator or provider signing-key compromise can rewrite its own history. Freeze consumption, revoke/rotate provider signing keys, compare against independently retained witness checkpoints, reconcile all device heads and revocation epochs, and require explicit operator approval before resuming. Never auto-reset to generation zero.
9. **Independent witness / quorum:** a single provider-signed hash chain does not protect against compromise of that provider's database and signing key. Production should require a second independently administered witness or quorum-backed checkpoint, with each witness retaining monotonic sequence/head commitments and cross-verifying receipts. The second witness must not share the first provider's administrator, credentials, backups or restore domain. Quorum loss fails closed.

## Existing production path and limitations

RemoteReplay currently posts the full verified capability and device proof to the Supabase Edge Function. The Edge Function invokes a SECURITY DEFINER RPC which updates the authority row and append-only ledger in the same Supabase Postgres database. This remains useful against endpoint-local filesystem rollback and ordinary Data API access, but a complete privileged Supabase database restore can restore both tables. C126 does not change that runtime path and does not claim whole-database rollback protection.

No local FileReplay fallback is introduced. The deterministic provider is test-only and cannot be selected by production configuration. The provider interface is groundwork for a future adapter, not evidence that the production system is now protected.

## Validation and delivery status

The new Go contract and fake-provider regression suite are committed in this PR. Exact-HEAD CI and Desktop workflows must complete successfully before this batch is considered repository-verified. The fake tests are not substitutes for a real external provider, independent backup/restore exercise, provider security audit, or real two-witness rollback test.

Outstanding human/infrastructure dependencies:
- provision the independent provider and witness accounts;
- approve provider endpoint hostname/TLS pins and provider signing-key provisioning;
- configure separately controlled KMS/HSM keys and backup/restore policies;
- demonstrate admin and audit separation;
- run real complete-Supabase-restore and provider-compromise recovery exercises.

PR #186 remains open and draft. No merge, production signing, deployment or activation is authorized by this contract-only change.
