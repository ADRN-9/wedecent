# C323 updater runtime integration contract

This document records the supported runtime boundary for the capability-gated updater.

## Authority and ownership

The updater is an internal Local Core service. The desktop shell and CLI are presentation/request surfaces only. They must not hold the update root private key, verify manifests independently, mutate protected updater state, choose an installer executable, or invoke an installer directly.

The shipped Local Core service must own:
- provisioned Ed25519 root key ID and public key;
- protected `StateStore` location and OS ACL/owner policy;
- discovery and v2 keyset/manifest verification;
- installer staging and package hashing;
- the production Authenticode publisher policy;
- the privileged installer executor and its service authorization protocol;
- pending transaction recovery before any new update admission.

## Required API sequence

1. Local Core obtains its current installed semantic version from its trusted installation metadata.
2. Local Core calls `DiscoveryClient.DiscoverStableVerified(ctx, currentVersion, highestSequence)`.
3. The returned opaque `VerifiedManifest` is passed unchanged to `StateStore.ApplyVerifiedManifest`; callers must not reconstruct it from `Manifest` fields.
4. `ApplyVerifiedManifest` revalidates the capability digest and persisted keyset epoch/digest under the cross-process update lock.
5. Installer archive staging, checksum verification, restricted extraction and the production Authenticode verifier complete before mutation.
6. A durable pending transaction is written before the privileged executor is called.
7. The privileged executor must bind the request to the Local Core service identity, exact transaction ID, target version and verified package directory. It must reject replayed transaction IDs and any caller outside the service authorization boundary.
8. On successful installation, sequence advancement and pending-journal removal are committed atomically in protected state.
9. On restart, Local Core must call `RecoverPendingInstall` with a production recovery adapter before another update can be admitted. Unknown or unverifiable outcomes remain blocked.

## Recovery adapter contract

The production `InstallerRecovery` implementation must inspect the actual installed product state and reconcile it to one of two known outcomes:
- `InstallRecoveryApplied`: independently verify the target version and package identity are installed;
- `InstallRecoveryNotApplied`: complete rollback/repair and independently verify the previous version is restored.

It must return `InstallRecoveryUnknown` for partial, ambiguous, inaccessible or untrusted state. It must be idempotent because the process can terminate during recovery itself. A mock/test recovery function is not production trust evidence.

## Desktop bridge contract

The desktop bridge may expose status and user intent such as `check-for-updates`, `download-update`, `apply-update`, and `update-status`. These requests must be authenticated by the existing Local Core IPC boundary and scoped to the logged-in local user. Local Core alone performs discovery, cryptographic verification, staging, authorization, recovery and execution.

The bridge response should distinguish:
- update available;
- download/staging in progress;
- verified and awaiting user approval;
- installation in progress;
- restart required;
- recovery required;
- rejected by security policy;
- temporary network/provider failure.

No bridge request may accept a manifest, signer ID, keyset digest, installer path, executable path, command line or privilege token as caller-authoritative input.

## Remaining implementation and acceptance

The current C323 change introduces the capability boundary and durable pending transaction state/recovery interface. It does not yet supply the production Windows service executor, production Authenticode policy, Local Core runtime orchestration, or a platform recovery adapter.

Before production enablement, add exact-commit tests for:
- Windows service IPC caller authorization and replay rejection;
- process termination before executor invocation, during mutation, after install success and before final state commit;
- repeated recovery termination and idempotent reconciliation;
- real Authenticode publisher/certificate-chain/timestamp policy;
- exact raw candidate SHA CI plus Linux, macOS and Windows Desktop validation;
- privileged Windows VM service restart, reboot and rollback acceptance.

Production root provisioning, signing, publication and deployment remain separate protected operations.
