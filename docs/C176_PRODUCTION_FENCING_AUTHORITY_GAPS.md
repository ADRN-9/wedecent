# C176-B3 production fencing authority status

## Implemented in this increment

- Added a macOS durable fencing journal adapter using O_NOFOLLOW, a private regular-file check, directory fsync, and nonblocking flock with context cancellation.
- Added a Windows durable fencing journal adapter using protected replay-directory ACLs, reparse-point-aware file opening, DACL validation before owner repair, and exclusive LockFileEx/UnlockFileEx locking.
- Restricted the unsupported-platform stub to platforms other than Linux, macOS, and Windows.
- Corrected the two Go formatting failures previously reported by the Linux CI formatting gate.

The Windows adapter deliberately fails closed when its directory/file ACL cannot be verified. The macOS adapter deliberately rejects symlinked or group/world-writable journal directories and symlinked journal files. These adapters use the existing append/fsync journal implementation; they do not provide replicated storage or an anti-rollback root outside the host.

## Production authority gaps — not implemented

The current CheckpointFenceAtomicPrimary in checkpoint_fence.go is an interface. The concrete testAtomicCheckpointPrimary in replay_witness_test.go is a test fixture, not a production authority. The production file journal FileCheckpointFencePrimary implements the reservation/commit store interface but does not implement CheckpointFenceAtomicPrimary: it cannot atomically read the authoritative replay-checkpoint participant heads and reserve/commit a fence in the same transaction.

CheckpointFenceCoordinator.ExecuteWithCheckpointHeads correctly refuses to proceed unless the configured primary implements that atomic interface. Do not replace that guard with the test fixture, a local mutex, a file-only comparison, or a legacy single-provider fallback.

The TLS helper in checkpoint_fence_tls.go constructs a TLS 1.3 client with exact hostname and SPKI pinning. It is not a witness RPC protocol. The current coordinator witness clients call the in-process CheckpointFencingWitness interface; there are no production HTTP RPC request/response handlers or remote primary/witness service implementations in this increment.

## Required production deployment

Before production activation, provide:

1. A production atomic primary adapter backed by one authoritative transactional store. Within one serializable transaction it must read and validate every participant checkpoint head, validate authorization/revocation fingerprints and scopes, reserve or recover the exact operation ID, then at commit re-read/compare the participant heads and persist the quorum-verified fence. A changed participant head must abort the transaction.
2. Authenticated primary and witness RPC services with versioned bounded schemas, request authentication, replay-resistant operation IDs, TLS 1.3, exact DNS endpoint binding and independently approved SPKI pins. Clients must verify signed primary tokens and witness acknowledgements against separately provisioned Ed25519 trust anchors.
3. One primary and at least three witnesses under independently administered security domains, with separate private keys, persistent volumes, independent operators, network policies, monitored clocks, and distinct backup/restore authority.
4. Protected secret provisioning and rotation for the primary signing key, each witness key, TLS certificates, and client pins. Private signing keys must never be shared across authorities.
5. Anti-rollback backup and disaster recovery. Restoring an older journal must not permit generation reuse or stale participant-head acceptance. Recovery must reconcile against independently durable witness heads.
6. Cross-host fault-injection verification covering simultaneous finalization/revocation, reservation/commit head changes, lost RPC responses, primary and witness restarts, partial quorum, partitions, replay, conflicting IDs, and restore rollback.
7. Native Windows and macOS CI execution of the new durable adapters. Repository source presence is not proof of runtime correctness on those operating systems.

## Verification status

The previous exact-HEAD CI run 45461517848 failed. Its Windows job showed the non-Linux fencing stub error, and its Linux job identified formatting differences in replay_witness.go and replay_witness_test.go. The macOS job was cancelled while a later push superseded that run; the workflow concurrency group has cancel-in-progress enabled.

This increment adds the platform adapters and formatting corrections. The new exact-HEAD CI and Desktop runs must finish before claiming these changes pass. No local Go test execution is claimed here.

No production distributed-consensus guarantee is claimed. The primary atomic adapter, remote RPC protocol/services, independent authority infrastructure, trust provisioning, anti-rollback recovery, and cross-host fault-injection evidence remain hard activation gates.
