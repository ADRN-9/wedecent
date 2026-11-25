# C124 — independent replay checkpoint: implementation gate

Date: 2026-11-23  
Inspected revision: `d422d3b3151708019505272915c120ddbe73f293`  
PR: [#186](https://github.com/ADRN-9/wedecent/pull/186)

## Decision

**Whole-primary-database rollback protection is not implemented or proven.** The current production `RemoteReplay` implementation delegates to a Supabase Edge Function whose `consume_port_forward_authorization` RPC writes both `port_forward_replay_authority` and `port_forward_replay_entries` in the same Supabase Postgres database. A full database snapshot restore or privileged restore of that project can roll back both tables together. A hash chain between tables in one restore domain does not prevent restoration of the complete database to a mutually consistent earlier snapshot.

The SQL comments and application documentation calling this ledger “independent” describe separation from the endpoint's local filesystem and ordinary Data API roles, **not independence from the primary database's backup/administrative rollback domain**. Do not interpret the existing SQL replay tests as whole-database rollback evidence.

## Evidence inspected at `d422d3b3151708019505272915c120ddbe73f293`

- `supabase/migrations/20261123080000_port_forward_replay_authority.sql` creates both replay tables in the same database and updates them in one `SECURITY DEFINER` RPC transaction.
- `supabase/functions/port-forward-replay/index.ts` creates a Supabase client using the Edge Function service-role secret and calls that RPC.
- `supabase/tests/database/port_forward_replay_authority.test.sql` checks RLS, service-role direct table privileges, duplicate JTI rejection, per-device generations, a deliberately rewound authority row while the ledger remains intact, hash mismatch and revoked-device rejection. Its transaction is rolled back at test end. It does **not** restore a complete database snapshot, because the authority and ledger share the same database.
- `internal/portforward/replay_remote.go` validates TLS 1.3, embedded hostname/SPKI pins, device identity and Ed25519 proof, and fails closed on unavailable/malformed responses. It cannot distinguish a whole-database restore performed by the Supabase project/database administrator.
- `internal/portforward/replay_store.go` explicitly documents that paired local snapshot-and-anchor restoration can replay a consumed JTI. FileReplay remains development/test only; it is not a safe fallback.
- The Cloudflare Durable Objects currently visible in `cloudflare/relay-worker/src/index.js` and `grant-replay.js` are used for connection-grant/relay state, not the port-forward replay authority. Their presence is not evidence that port-forward checkpointing is configured in a separately administered rollback domain.

## Required production architecture

1. Move the authoritative monotonic checkpoint to a separately provisioned service and durable storage whose administrative credentials, backup/restore controls and retention policy are outside the Supabase project/database administrator's control. A second schema, table, database or bucket governed by the same primary restore authority is insufficient.
2. The checkpoint service must authenticate the enrolled device's Ed25519 proof and verify the exact capability digest; it must not trust transport addresses, caller-supplied device IDs, or a bearer API key as device identity.
3. Atomically enforce a unique `(device_id, jti)`, a monotonically increasing per-device generation, and an append-only hash chain. Scope authorization to the endpoint device and account/organization. Maintain revocation epochs or an independently authenticated revocation feed so restoring the account database cannot silently reinstate revoked authority.
4. Return an authenticated, durable receipt binding device, JTI, capability digest, generation and checkpoint hash. On retry after an ambiguous timeout, return the same committed receipt only for the exact same request; conflicting payloads fail closed. A request whose commit outcome cannot be established must not fall back to local replay state.
5. Checkpoint unavailability, stale generation, chain/hash mismatch, replay, identity/account mismatch, stale revocation epoch, and ambiguous commit outcomes must fail closed. Recovery requires explicit reconciliation against the independently retained checkpoint; no automatic reset or “start fresh” path.
6. Add real integration tests that snapshot the complete Supabase project database after consuming a capability, restore the entire snapshot, and prove that the independent checkpoint still rejects that capability. Also test cross-device/account isolation, concurrent duplicate consumption, revocation-vs-consumption linearization, crash before/after checkpoint commit, lost response/idempotent retry, service restart, corrupted/stale receipt, and authority outage.
7. Demonstrate database grants and infrastructure administration separation: application/Edge Function roles cannot update/delete checkpoint history, and Supabase project administrators cannot restore or delete the external checkpoint. Obtain independent provider audit/backup evidence.

## Safe behavior until that gate is met

- Keep the current remote Supabase ledger as defense against local endpoint filesystem rollback and ordinary Data API access, but do not claim it resists whole-database restore.
- Keep production replay consumption fail-closed when the configured authority cannot be reached or its state is malformed.
- Do not add local replay fallback, reset endpoint state automatically, or treat the current same-database hash chain as an external checkpoint.
- Preserve existing device identity, endpoint authorization, capability validation and revocation checks.
- Keep PR #186 open and draft. No merge, signing, deployment or activation is implied by this checkpoint note.

## Outstanding external dependencies

- A separately administered checkpoint provider/account and durable append-only or hardware-backed monotonic storage.
- Independent provider credentials, service identity, endpoint hostname/TLS trust pins and production key provisioning.
- Provider backup/restore and administrative separation evidence.
- A controlled deployment and recovery procedure, including how revocation epochs are reconciled across the two trust domains.

These are infrastructure/provisioning blockers, not permission to weaken the trust model. The current code is groundwork only; this C124 task does not mark whole-database rollback protection complete.
