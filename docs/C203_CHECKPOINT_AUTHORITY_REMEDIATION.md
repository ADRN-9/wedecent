# C203 — Checkpoint authority security remediation

Baseline: `7773660e0481427ebffb0c53a0ed7bcce1b1db03`

Candidate branch: `security/c203-checkpoint-authority`

## Privilege boundary

Migration `20261124190000_checkpoint_authority_principal.sql` creates the non-login PostgREST role `wedecent_checkpoint_authority` and grants it to `authenticator`, without granting membership to `service_role`.

The existing fence RPCs are renamed to internal callees. Public wrappers are executable only by the dedicated role. The shared `service_role`, `authenticated`, `anon`, and `PUBLIC` have no execute privilege on the privileged reservation, token-recording, commit, or recovery RPCs. The underlying C195 reservation/commit RPCs are also inaccessible to those roles.

The wrappers require `auth.uid() = checkpoint_operations.actor_id` (or the actor supplied at reservation). The token source mints short-lived JWTs for each RPC. The adapter sends the project's non-privileged anon API key in the `apikey` header and the actor-bound authority JWT in `Authorization: Bearer`. Each JWT must contain:

- `role = wedecent_checkpoint_authority`
- `sub = <authenticated actor UUID>`
- `exp - iat <= 300 seconds`

The Go adapter validates the role, actor, algorithm marker, and short lifetime. Supabase/PostgREST validates the JWT signature before setting the role and claims. The token source is called for every RPC so credentials can rotate. The JWT signing key must exist only on the dedicated trusted authority host; it must not be present in general Edge Functions, Local Core, desktop binaries, or installers. Reusing the shared service-role JWT is explicitly unsupported.

## Database cryptographic boundary

The migration provisions two trust registries:

- `checkpoint_fence_primary_trust`: Ed25519 public keys for primary commit attestations.
- `checkpoint_fence_witness_trust`: versioned, unique witness IDs and Ed25519 public keys.

The registry tables have no grants to application roles. Provisioning or rotation is a privileged infrastructure operation.

Before committing, PostgreSQL independently:

1. Loads the exact persisted reservation token for the operation and checks its digest and actor binding.
2. Requires the token witness IDs to equal the configured versioned database witness set.
3. Calculates strict majority as `floor(n/2)+1`.
4. Binds every acknowledgement to operation ID, action, token digest, generation, witness ID and key ID.
5. Requires witness commit timestamps to fall between the persisted token receipt time and token expiry.
6. Verifies every Ed25519 witness acknowledgement using pgsodium.
7. Verifies a primary Ed25519 commit attestation over the operation fingerprint, token digest, canonical token JSON digest, canonical acknowledgement JSON digest, and actor ID.

The trusted Go authority verifies the original primary token signature and all witness acknowledgements before producing the primary commit attestation. PostgreSQL verifies that attestation and independently verifies each witness acknowledgement. A service-role caller cannot manufacture a structurally valid quorum and call the commit RPC.

The pgsodium extension is currently used for Ed25519 verification because it exposes libsodium's detached-signature verifier. Supabase has marked pgsodium as pending deprecation. Production adoption therefore requires an explicit compatibility check for the target Supabase/PostgreSQL version and a migration plan to a supported Ed25519 verification primitive before relying on this long-term.

## Expired-operation recovery

The coordinator now treats an expired token as recovery-only:

- It loads the original token for the exact operation before considering the request.
- It does not ask witnesses to create new acknowledgements after expiry.
- It loads each witness's durable acknowledgement for the exact scope and generation.
- It verifies the original acknowledgement signature, token digest, action, operation, generation, and signed commit timestamp.
- It requires a strict majority of pre-expiry acknowledgements.
- The database verifies the timestamps against the original persisted token receipt and expiry.
- Only after both cryptographic checks does the database renew the short commit lease and set the transaction-local C195 expiry exception.
- An expired pending operation cannot be replaced by a different operation. A persisted reservation token cannot be replaced by a different token at the same operation/generation.

The C195 participant reservation remains present and must match the original operation fingerprint. Participant-head and organization-fence advancement still occur in one PostgreSQL transaction. If the participant rows or original reservation evidence are missing, recovery fails closed.

## Regression coverage added

- JWT role, actor and lifetime validation.
- Dedicated role privilege assertions; shared service-role execute is absent.
- Forged actor subject rejection.
- Database-generated Ed25519 witness keys and signed acknowledgement fixtures.
- Insufficient quorum rejection.
- Fabricated acknowledgement signature rejection even when a primary commit attestation is supplied.
- Exact token preservation.
- Expired token and participant lease recovery using pre-expiry witness acknowledgements.
- Existing atomic participant commit and organization-fence assertions remain in the database test.

The database test uses generated ephemeral test keys only. No production trust keys are included.

## Operational requirements and remaining acceptance

- Provision the dedicated authority JWT issuer/key in a separate trusted runtime; do not expose the Supabase JWT signing key to general Edge Functions.
- Provision the primary Ed25519 public trust anchor and the complete versioned witness public-key set in the database.
- Confirm pgsodium availability/schema/API against the target Supabase project and define its deprecation replacement.
- Run the full exact-HEAD Go, pgTAP, independent-session, restart/recovery and desktop CI workflows.
- Independently review the final candidate SHA and test logs.
- Conduct production credential provisioning, migration, backup/restore rehearsal and deployment only after the above gates pass.

No production credentials, trust anchors, migrations, signing, deployment, merge, or activation are performed by this branch.
