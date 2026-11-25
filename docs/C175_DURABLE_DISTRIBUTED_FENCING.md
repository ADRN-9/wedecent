# C175 — durable distributed fencing authorities

## Delivery scope

C175 adds executable, append-only durable primary and witness journals plus a quorum coordinator. It does not claim production deployment or integration into the replay-checkpoint authorization lifecycle.

## Durable primary

`OpenFileCheckpointFencePrimary` opens one Linux journal and one primary Ed25519 signing key. Every operation takes an advisory exclusive file lock, replays the complete journal, validates the event chain, then performs one transaction.

- `ReserveFence` atomically compares the expected generation, revocation epoch, previous fence digest and primary-head link.
- The operation ID is globally unique within that primary journal, including across scopes.
- The signed reservation is appended and `fsync` completes before the token is returned.
- A retry with the same operation payload returns the stored byte-identical token.
- Reuse of an operation ID with a different payload fails with conflict.
- Only one uncommitted reservation may exist per scope. A pending reservation survives restart and blocks later operations until exact recovery completes.
- `CommitFence` verifies a strict majority of distinct configured witness signatures, each bound to the exact token digest, operation ID, action and generation. The commit event is fsynced before success is returned.
- `LoadFence` recovers reserved or committed operation state by stable operation ID.

The primary refuses a stale expected generation, stale revocation epoch, mismatched previous-fence digest, primary-head rollback, or a second concurrent reservation. The primary-head value is currently supplied by the caller and checked for monotonic consistency within this fence journal; it is not yet atomically read from the replay-checkpoint provider. That cross-store comparison is a hard integration blocker, not a completed guarantee.

## Durable witness

`OpenFileCheckpointFenceWitness` opens a separate journal and independent Ed25519 key for one witness identity.

- The witness validates the primary signature, fixed witness-set version and exact membership.
- It compares the expected generation, revocation epoch and previous-fence digest with its own durable state.
- It rejects same-generation equivocation, operation-ID reuse across scopes or generations, and skipped generations.
- It signs an acknowledgement containing the exact token digest, action, operation ID, generation, key ID and commit timestamp.
- The journal is fsynced before the acknowledgement is returned.
- Exact retries recover the same acknowledgement, including after token expiry. Expired tokens cannot create a new witness commitment.

Witness state and keys must not be shared between witness identities or administrative domains.

## Quorum coordinator

`CheckpointFenceCoordinator.Execute` reserves at the primary, requests witness commits concurrently, verifies distinct acknowledgements against configured witness public keys, and asks the primary to commit only after strict majority. If fewer than quorum acknowledge, the reservation remains pending and the call fails closed. Retrying the exact request resumes the same generation; it does not mint a replacement token. If the reservation expires before a strict majority is durable, already-committed witnesses can return their exact acknowledgements but uncommitted witnesses reject the expired token. There is no automatic abort or generation-reuse path; this blocks progress pending a future quorum-safe recovery protocol or operator-led reconciliation.

If the primary commit response is ambiguous, the coordinator reads the stable operation ID back from the primary and only returns success when a matching committed operation is durably present.

The quorum is always `floor(n/2)+1`; between three and 31 configured witnesses are accepted. No single-provider fallback exists.

## TLS and endpoint pinning

`NewPinnedCheckpointFenceHTTPClient` creates an HTTP client restricted to TLS 1.3, an exact configured DNS hostname and an exact SHA-256 pin of the leaf certificate SubjectPublicKeyInfo. Standard PKI chain and hostname verification remain enabled; SPKI pinning is additional. The client refuses IP literals, URL-like host strings, empty pins and malformed hostnames. Its dialer permits only the exact configured hostname on TCP 443, and redirects are returned without following them.

This is a secure transport primitive, not a completed remote RPC protocol. Primary and witness HTTP service handlers, request/response schemas, mTLS/client authentication and deployment manifests are still required before these stores can be operated across hosts.

## Storage and operations

The journal implementation currently has a Linux `flock` adapter. Non-Linux builds deliberately fail closed with `ErrCheckpointFenceStore`; they do not silently fall back to process-local mutexes. The file is opened without following a final-component symlink, must be a private regular file with mode 0600, and its containing directory must not be symlinked or group/world writable. Each append is JSON encoded, newline framed, bounded to 1 MiB and fsynced. A truncated final record is discarded during recovery; malformed complete records fail closed.

Operate the primary and each witness on separately administered hosts or trust domains, with separate durable volumes and separately provisioned private keys. Keep host clocks synchronized and monitor drift: token expiry is issued by the primary and witness acknowledgement timestamps are signed by witness-local clocks; significant skew must fail closed operationally rather than be normalized into a permissive fallback. A shared filesystem, common administrator, shared credentials, or three processes under one provider do not establish independent witnesses. Backups must preserve append-only history; restoring an older primary journal is expected to be rejected by witnesses that have advanced, causing fail-closed unavailability rather than accepting stale generations.

The file journal is a single-node durable authority, not a replicated database or high-availability primary. Each operation currently replays the append-only log under the file lock, so journal growth increases operation cost; production compaction must preserve signed history and operation-ID uniqueness. It has no automated anti-rollback anchor, backup restore reconciliation, key rotation protocol, remote replication, or operator-safe compaction. Protect the journal and private keys with host access controls and encrypted backups. Never copy a primary private key to witnesses.

## Verification added

The durable tests exercise:
- primary reservation and strict-majority commitment;
- witness signature validation and exact token-digest binding;
- restart recovery of committed operations and witness acknowledgements;
- partial quorum followed by exact reservation retry and completion;
- conflicting operation IDs and forged acknowledgements;
- same-generation witness equivocation;
- expired-token rejection and truncated-tail recovery;
- concurrent primary reservations with one winner;
- revocation-first durable ordering rejecting stale finalization;
- finalization-first remaining committed before a later revocation;
- coordinator strict-majority execution;
- TLS 1.3 and exact SPKI pin enforcement.

These are local filesystem integration tests. They do not prove cross-host consensus, network fault behavior, administrative independence, real TLS deployment, or production infrastructure.

## Integration boundary and remaining blockers

The signed reservation token is not by itself proof of a committed authorization decision; consumers must require a `CheckpointFenceOperation` with `Committed=true` and a verified quorum. The existing `WitnessedReplayCheckpointProvider` still uses its legacy `Consume`, `Revoke`, witness receipt and pending-store flow. C175 does not route authorization consumption, finalization or revocation through `CheckpointFenceCoordinator`. Do not enable this journal as the production authorization path until an explicit lifecycle migration preserves pending finalization recovery and verifies the same committed fence evidence at every authorization boundary.

Remaining work:
1. Add remote primary/witness RPC servers and clients using the pinned TLS transport; bind every RPC to the configured authority identity and reject endpoint changes.
2. Provision one primary plus three independently administered witness hosts, volumes, keys, exact hostnames and SPKI pins.
3. Implement backup/restore anti-rollback and disaster recovery without allowing stale-generation acceptance.
4. Integrate the coordinator into consume/finalize/revoke and durable pending-operation recovery; remove any path that can silently use only the legacy local transition lock.
5. Run cross-host concurrent race, crash, partition, partial quorum, replay, equivocation and restart tests against the independently administered authorities.
6. Add native Windows and macOS durable lock adapters before supporting local journal operation on those platforms.

No production credentials, signing, deployment or activation are included in this increment.
