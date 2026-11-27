# C324 updater admission and recovery contract

## Capability admission

Only `VerifiedManifest` is accepted by the private `StateStore.applyVerifiedManifest` method. Its fields are private and it is created by `VerifyManifestV2Capability` only after the root-authorized keyset and Ed25519 manifest signature pass the existing v2 validation rules.

The capability binds:
- canonical manifest SHA-256;
- signing key ID;
- keyset epoch and canonical keyset digest;
- previous installed version supplied to discovery;
- sequence baseline used for anti-rollback verification.

`DiscoveryClient.DiscoverStableVerified` is the runtime discovery entrypoint. `ApplyStable` carries the returned capability without reconstructing authority from a caller-provided `Manifest`. The installer admission boundary validates the capability and compares its keyset epoch/digest with protected persisted state while holding the same cross-process lock used for sequence and journal updates.

The old exported manifest-only installer methods are absent. A plain, structurally valid `Manifest` is not accepted by any installer admission method.

## Durable install journal

The protected state record includes one optional pending transaction:
- unpredictable transaction ID;
- stable sequence;
- canonical manifest and package SHA-256 digests;
- previous and target versions;
- phase: pending, executing, committed, or recovery-required.

The transaction is durably written before executor invocation. The executing phase is persisted before the privileged boundary. On executor failure, the journal is marked recovery-required and the stable sequence remains unchanged. On success, committed is persisted before the sequence update and journal removal are atomically written.

Any pending transaction blocks new installs, manual sequence advancement and keyset rotation. A restart must run recovery before accepting a new update.

## Privileged executor and backup contract

The executor receives the complete `InstallTransaction` alongside the verified package. The production service adapter must:
1. authenticate the calling Local Core/service identity;
2. reject duplicate or replayed transaction IDs;
3. verify the target version and package digest against the transaction;
4. prepare a replacement without deleting or overwriting the only known-good installation;
5. retain a recoverable previous-version backup through replacement and health confirmation;
6. report success only after the new installation is independently confirmed;
7. retain backup state until the committed transaction is durable.

The `InstallerRecovery` adapter must be idempotent and may return Applied only after independently confirming target version and package identity. NotApplied is permitted only after restoring and verifying the previous version. Unknown or inaccessible state must remain blocked. A backup must not be discarded during retry or recovery until target confirmation succeeds.

## Verification status and outstanding dependencies

C324 supplies the opaque capability, protected journal, fail-closed recovery interface, transaction-bound executor contract and deterministic process-termination tests around journal/executor/commit boundaries.

It does not implement a production Windows service executor, actual atomic directory replacement/rollback adapter, Authenticode publisher/certificate-chain policy, or a platform-specific recovery adapter. Those are production acceptance dependencies, not claims satisfied by the interface or unit tests.

Hosted exact-head updater CI, repository CI and Desktop workflows must pass before merge. Windows service restart/reboot/rollback E2E must verify backup retention and replay rejection. Production trust provisioning, signing, publication and deployment remain separately gated.
