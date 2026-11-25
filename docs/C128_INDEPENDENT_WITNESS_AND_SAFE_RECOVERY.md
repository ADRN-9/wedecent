# C128 — independent checkpoint witnesses and safe recovery

Status: **Provider-independent quorum protocol and deterministic simulations implemented. No real witness account, provider, KMS/HSM key, or production adapter is provisioned. Production rollback resistance is NOT established.**

## Architecture

C128 adds `internal/portforward/replay_witness.go`, `checkpoint_pending.go`, and `checkpoint_request.go`.

- `CheckpointWitness` is a provider-neutral independent witness contract: monotonic `Commit`, `Revoke`, signed `Head`, and signed completion acknowledgement.
- `WitnessedReplayCheckpointProvider` wraps the primary `ReplayCheckpointProvider`. A successful consume requires a strict-majority quorum (at least two witnesses) with distinct witness IDs and distinct Ed25519 public keys. One witness, duplicate keys, invalid quorum sizes, disagreement, or quorum loss fail closed.
- Every witness keeps its own monotonic generation and append-only hash chain, separately tracking the primary provider generation/head. Witness receipts bind scope (device/account/organization), primary receipt digest, request fingerprint, JTI, exact authorization digest, revocation epoch, predecessor and record hash.
- Witnesses independently verify the primary provider's signed receipt using a separately pinned primary public key. A witness rejects a primary generation rollback, predecessor mismatch, reused JTI with a different receipt, and endpoint revocation-epoch mismatch.
- Witness heads are signed by witness-specific keys. The client compares witness quorum heads with the primary head; a historical primary head or inconsistent witness history is rejected.
- Revocation is committed to the primary and then to the witness quorum. The primary head is checked first so retries can finish witness propagation after an ambiguous response. Any partial quorum or disagreement leaves forwarding unavailable.

The quorum configuration can enforce distinct key material and a strict majority, but cannot prove separate legal ownership or administrator/backup boundaries. Those require infrastructure and operator evidence; do not treat a configuration file with three endpoints as proof of independence.

## Safe client recovery and historical receipt rejection

`FileCheckpointPendingStore` stores an exact request fingerprint keyed by consuming device, immutable account and organization IDs, and JTI. It uses the existing protected replay-file primitives: private regular files, atomic staged replacement, fsync, secure directory checks, and cross-process file locking. It is durable client intent only, never replay authority or a local replay fallback.

The consumption ordering is:

1. Persist `pending` before contacting the primary provider.
2. Submit the exact signed request to the primary. A timeout after commit remains ambiguous; the exact same request is retried.
3. Verify the primary receipt and disposition. `Recovered` is accepted only if a matching pending record already existed before this call.
4. Preflight independently signed witness heads and reject historical or conflicting primary generations.
5. Obtain witness quorum commit receipts.
6. Persist the local pending record as `resolved`.
7. Obtain signed witness acknowledgements from a strict majority. Any already-acknowledged response rejects the operation as historical.
8. Only then return success to the caller, allowing the caller to proceed with session establishment.

The final acknowledgement closes the local-journal rollback gap: restoring an old `pending` snapshot after a session was authorized cannot turn a previously acknowledged witness record into a new session. A crash after local resolution but before witness acknowledgement fails closed; the capability may need to be reissued rather than replayed. This is an intentional availability trade-off.

The pending journal is not a cryptographic rollback anchor. Its safety depends on the independent witness acknowledgements remaining available and uncompromised. The deterministic memory pending store is test-only.

## Capability-to-checkpoint binding

`BuildCheckpointRequest` verifies the same signed forwarding capability (issuer key, canonical claims, JTI, expiry, direction and route binding), derives the exact digest from canonical capability bytes plus its signature, resolves both endpoint memberships and revocation epochs through a trusted `CheckpointMembershipResolver`, checks the local endpoint is one of the authorized endpoints, and signs the complete checkpoint request with that device's Ed25519 signer.

The membership resolver is a security-critical Local Core integration point. It must return immutable account/organization identity and current revocation epoch from the same independently verified control-plane membership source used for the forwarding authorization decision. The primary checkpoint provider must transactionally revalidate both endpoint memberships and epochs at consume time. A caller-supplied endpoint, transport identifier, or IP address is never an identity source.

This helper is implemented and tested, but the current `RemoteReplay` production transport has not yet been replaced with the witnessed adapter. The existing production path remains the Supabase replay RPC. No production provider credentials, independent membership resolver, witness keys or trust pins are present in this PR. Therefore the new protocol is not yet enforcing production forwarding requests.

## Deterministic adversarial tests

`internal/portforward/replay_witness_test.go` covers:

- two-of-three independent witness receipts and signed acknowledgements;
- exact primary commit lost-response recovery across a client process restart;
- provider ledger and matching signing-key rollback together;
- one witness ledger and its signing key rolled back together, detected by the remaining quorum;
- conflicting witness heads and stale revocation epochs;
- quorum loss and recovery retry;
- restored local pending journal after witness acknowledgement;
- resolved JTI replay rejection and conflicting JTI digest rejection;
- file journal restart and restrictive file permissions;
- request derivation from the signed capability and both endpoint membership records.

Existing C126 tests continue to cover concurrent consumption/revocation, crash-before/after-primary-commit, cross-device/account isolation, malformed receipts, and provider compromise. These are deterministic in-memory simulations. They are not a real provider backup/restore, signing-key recovery, independent-admin audit, or hardware/KMS test.

## Human/infrastructure prerequisites

Before production activation, obtain and independently verify:

1. At least three independently administered witness instances/accounts with a documented strict-majority quorum; independent cloud tenant/org ownership, administrators, break-glass identities, service credentials, and destructive recovery permissions.
2. A primary checkpoint provider account separate from the Supabase project administrator and its recovery domain.
3. Non-exportable KMS/HSM keys for primary receipt signing and each witness key, including provisioning ceremonies, rotation, revocation, overlap, disaster recovery, and pinned public-key publication.
4. Approved TLS 1.3 hostnames and SPKI pins for the primary and each witness endpoint, provisioned into trusted Local Core configuration; no URL, DNS, API key, relay, or IP value is accepted as identity.
5. Independently controlled immutable backups, retention locks, restore roles, audit log retention and tested recovery procedures for every witness and provider.
6. Real tests that restore the complete primary database and its signing key together, restore one witness database and its signing key together, partition the quorum, reconcile generations and revocation epochs, and demonstrate that every ambiguous state fails closed.
7. A reviewed Local Core membership resolver wired to the same verified authorization context, plus production RemoteReplay adapter integration and end-to-end negative tests.

A second database under the same administrative control is not an independent witness. A single provider's own hash chain and signing key do not protect against restoration of that provider and key together. Cloudflare Durable Objects or another hosted service must not be assumed rollback-immune without evidence.

## Current production status

- The new witness/quorum and pending-operation contracts are provider-neutral.
- Deterministic tests prove protocol behavior under simulated rollback and quorum failure.
- The existing RemoteReplay runtime still uses the same-Supabase database replay authority from C124/C126.
- No production activation, deployment, external signing, or publication is justified by these simulations.
- PR #186 remains open, draft and unmerged pending exact-SHA CI/Desktop validation and independent infrastructure acceptance.
