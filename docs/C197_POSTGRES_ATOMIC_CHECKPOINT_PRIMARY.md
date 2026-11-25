# C197 — Production PostgreSQL Atomic Checkpoint Primary

## Status

Implementation candidate on \`feat/secure-port-forwarding-foundation\`. This work adds a concrete PostgreSQL-backed \`CheckpointFenceAtomicPrimary\`, a scope-level fence ordering ledger, a pinned Go RPC adapter, and negative verification. It is not production acceptance. No production keys, witness endpoints, service-role credentials, or production database are provisioned by this change.

## Reconciliation

- Starting/reference HEAD: \`b723967ae03ed84b0693ebf324ac1776a38877d0\`.
- The branch was confirmed at that SHA before editing.
- C195 migration, pgTAP tests, concurrency script and documentation were preserved.
- No reset, force-push or history rewrite was performed.
- PR #186 and PR #176 remain open, draft and unmerged.

## Authority model

\`public.port_forward_replay_authority\` remains the only mutable per-device participant-head authority. The C195 checkpoint head generation/hash remain columns on that existing row.

The new \`public.checkpoint_fence_authority\` table is a different, organization-scoped ordering record. It stores the organization fence generation/digest, revocation epoch, current primary participant-vector digest, and one pending organization operation lease. It contains no per-device participant generation or hash. Its purpose is to serialize organization-scoped finalization/revocation order even when two operations have disjoint device sets.

The immutable operation, participant snapshot, event and active-reservation tables retain their C195 roles. Direct service-role access to the underlying C195 reserve/commit RPCs is revoked by the new migration; the fence-wrapped RPCs are the service-role entry points.

## Go primary adapter

\`internal/portforward/checkpoint_fence_supabase.go\` implements:

- \`CheckpointFenceAtomicPrimary\`
- \`CheckpointFencingPrimary\` (legacy non-atomic methods fail closed)
- \`CheckpointFenceHeadReader\`
- \`CheckpointAuthorityBinding\`

The adapter:

1. Requires a server-side service-role credential, authenticated actor UUID, independently configured SPKI pin(s), primary Ed25519 \`crypto.Signer\`, separate checkpoint-head verification key, and at least three distinct witness trust keys.
2. Uses HTTPS with TLS 1.3, exact hostname and SPKI pin validation, no redirects, bounded response bodies and a bounded HTTP timeout.
3. Verifies every participant checkpoint-head signature and canonicalizes participants by device ID.
4. Calls the fence reservation RPC, which composes the existing C195 atomic participant reservation. It checks the returned operation fingerprint, expected organization fence generation, prior fence digest, lease expiry and primary participant-vector digest.
5. Signs the resulting fence token using \`crypto.Signer\` (including HSM/KMS-backed implementations that support Ed25519), verifies the signature locally, and persists the signed token receipt.
6. On commit, re-verifies the primary token, participant checkpoint-head signatures, exact participant-vector digest, configured witness membership, distinct witness identities/keys, each Ed25519 acknowledgement, operation/action/generation/token binding, expiry and strict-majority quorum.
7. Calls the fence commit RPC. The RPC invokes the C195 commit RPC in the same transaction, then advances organization fence ordering state and appends the fence commit receipt. Any error rolls back both participant-head and scope-fence changes.
8. Recovers lost reserve/record-token responses by exact operation retry, and lost commit responses by loading and cryptographically verifying the durable receipt.

The adapter's legacy \`ReserveFence\` and \`CommitFence\` methods deliberately return \`ErrCheckpointUnavailable\`; callers cannot silently fall back to a non-atomic/file-backed implementation.

## PostgreSQL protocol

New migration: \`supabase/migrations/20261124180000_postgres_checkpoint_fence_primary.sql\`.

New security-definer RPCs (service-role execute only):

- \`reserve_checkpoint_fence_operation\`: locks the organization fence row, serializes distinct operations for that organization, then invokes C195's existing participant reservation RPC. It returns the current fence generation/digest and the reserved primary-head link.
- \`record_checkpoint_fence_token\`: appends the exact signed primary token and digest. It binds operation, actor-derived request fingerprint, action, organization, expected fence generation, expiry, primary-head link and canonical participant identity vector.
- \`commit_checkpoint_fence_operation\`: checks the exact persisted token digest and acknowledgement operation/token/generation binding, invokes C195's atomic participant commit, then advances the organization fence head and appends a durable fence commit receipt in the same transaction.
- \`load_checkpoint_fence_operation\` and \`load_checkpoint_fence_head\`: expose bounded recovery state to the trusted Go adapter.

The scope-level fence hash is the canonical token digest, matching the existing file-primary/witness ordering semantics. The primary participant-vector digest includes the signed checkpoint-head messages and signatures; Go verifies these signatures before calling SQL. SQL independently compares the expected participant generations/hashes against \`port_forward_replay_authority\` at reserve and commit time.

SQL does not verify Ed25519 signatures, prove witness administration independence, or establish quorum authenticity. The trusted Go adapter must do that before commit. The SQL pgTAP fixture uses placeholder signatures only to exercise the transaction contract; it is not cryptographic evidence.

## Tests added

- \`internal/portforward/checkpoint_fence_supabase_test.go\`
  - primary, checkpoint-head and witness key separation;
  - duplicate witness key rejection;
  - valid strict-majority Ed25519 quorum;
  - insufficient quorum;
  - duplicate, forged, stale-token, expired and unconfigured-witness acknowledgements;
  - signed token and acknowledgement wire round trips;
  - legacy non-atomic method fail-closed behavior.
- \`supabase/tests/database/checkpoint_fence_primary.test.sql\`
  - 22 pgTAP assertions;
  - service-role grants and revocation of direct C195 RPC access;
  - organization-wide serialization even for disjoint participant sets;
  - durable signed-token receipt and lost-reservation recovery;
  - atomic fence/participant commit;
  - exact retry without double advancement;
  - conflicting token rejection and append-only receipt evidence.
- Existing C195 database and independent-session tests remain in place. CI's \`supabase test db\` automatically discovers the new pgTAP file.

## Known gaps and production blockers

1. **No production wiring yet.** The adapter is concrete and can be injected as \`CheckpointFenceCoordinator.Primary\`, but the production \`WitnessedReplayCheckpointProvider\` construction/configuration path has not yet been switched to it. The existing file-backed primary remains available for isolated tests and non-production scenarios; the adapter's non-atomic methods fail closed.
2. **No production witness service deployment.** The adapter verifies configured witness keys and acknowledgements, but the independent witness network clients, their durable monotonic storage, separate cloud/admin accounts, backup separation and operational quorum are not provisioned here.
3. **Human-controlled credentials/trust anchors.** Production requires an externally provisioned Ed25519 primary signing key (preferably KMS/HSM via \`crypto.Signer\`), a distinct checkpoint-head verification key, at least three independently controlled witness public keys, exact Supabase endpoint SPKI pins, a server-side service-role credential and an authenticated actor identity. These secrets must not be embedded in Local Core, desktop binaries, renderers or installers.
4. **Production database acceptance.** The new migration and RPCs still require exact-HEAD disposable PostgreSQL CI, then a separately approved production migration, backup/restore rehearsal and operational monitoring.
5. **Rollback boundary.** The organization fence row and C195 participant heads live in the same PostgreSQL project/database. A complete database snapshot restoration can restore both together. This is not independent anti-rollback protection; external witness quorum and separately administered monotonic state remain required.
6. **SQL trust boundary.** PostgreSQL checks token/ack structural binding but cannot prove that Go actually verified Ed25519. Only the trusted adapter may hold the service-role credential and invoke commit. Compromise of that service-role principal or trusted Go runtime remains a critical authority compromise.
7. **Verification scope.** The C197 SQL test's placeholder acknowledgements test transaction plumbing, not signature validity. Go unit tests cover signature/quorum validation. Real independent witness E2E, production key operations and complete database-restore adversarial exercises remain outstanding.

## Exact-candidate verification

The branch commits in this assignment are pushed directly to PR #186's existing head branch. Exact final HEAD and CI/Desktop run IDs/results must be refreshed after the final correction commits. No earlier C195 run is evidence for C197.

PR #186 remains open/draft/unmerged. PR #176 remains open/draft/unmerged. No production signing, deployment, merge, migration or activation is performed by this implementation alone.
