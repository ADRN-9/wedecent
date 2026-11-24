# C143 — Supabase authorization recovery and blocking defects

Date: 2026-11-24

## Exact branch state

- Repository: ADRN-9/wedecent
- Pull request: #186 (open, draft, unmerged)
- Branch: feat/secure-port-forwarding-foundation
- C143 implementation commit: 51c5108f5d00b07aa3afd0712b0b06c7fad16c79
- No force-push, merge, approval, deployment, or production operation was performed.

## Verified existing implementation

The current `supabase/migrations/20261124070000_atomic_port_forward_authorization.sql` contains all three device-ID checks using `pg_catalog.substr(text, integer)`; no qualified `substring` call remains. Each identifier is constrained to the exact 19-character `wd_` + base32 form.

The migration's canonical participant lock loop sorts device IDs and locks each row with `FOR SHARE`. For initiator, destination, and router, the locked row is compared to the corresponding pre-lock discovery snapshot; only the currently locked row is assigned to `v_initiator`, `v_destination`, or `v_router`. Destination and router comparisons use `v_locked_device`, not an unrelated row variable. The code then evaluates revocation, owner, organization membership, device-access permissions, and route-grant binding from the locked snapshots.

## C143 regression coverage added

Updated `supabase/tests/database/port_forward_replay_authority.test.sql`:

- Expanded the fixture with a distinct enrolled fourth device for mismatch tests.
- Preserved the positive routed authorization and endpoint idempotent-retry tests.
- Preserved the positive direct authorization test.
- Added a routed authorization missing its router participant.
- Added a destination participant that disagrees with the signed route destination.
- Added a router participant that disagrees with the locked route-grant router.
- Asserted failed participant checks leave no authorization transaction and consume no JTI.

The pgTAP plan is 30 and the file contains 30 `ok`, `is`, or `throws_ok` assertions.

Existing regressions also cover revoked initiator, destination and router; revoked destination access; missing organization membership; route-grant revocation; duplicate JTI; conflicting forwarding transaction retry; stale membership epoch; and savepoint rollback.

## Concurrency boundary

No deterministic independent-database-session race test was added in C143. The existing pgTAP cases execute sequentially inside a test transaction and must not be represented as proof of concurrent safety.

The SQL mutation triggers and authorization RPC use row locks and canonical ordering, but the following races remain to be exercised with separate PostgreSQL sessions and explicit barriers:

1. Organization membership removal/role change versus authorization consumption.
2. Device-access permission revocation versus authorization consumption.
3. Initiator, destination, and router device revocation versus authorization consumption.
4. Route-grant revocation versus authorization consumption.

Required assertions: if revocation/change linearizes first, consumption rejects; if authorization consumption linearizes first, the mutation waits and the resulting committed authorization snapshot is the one that was valid at the authorization commit. A sequential test or process-local lock is not a substitute.

## CI status at report time

The pre-C143 exact HEAD `47fe0415f109a8a7bd376797c427b0e06bb58f09` had a completed CI run (45342374391) with Supabase DB, Windows agent/release, macOS agent, control plane, relay worker, route client and route E2E successful; Linux was still running. Its Desktop run (45342374284) had Linux, Windows and macOS Tauri jobs still running.

After the C143 test commit, exact HEAD `51c5108f5d00b07aa3afd0712b0b06c7fad16c79` started CI run 45343038322 and Desktop run 45343038328. At the time of this report, Supabase DB and platform jobs were in progress; no result is claimed for the new tests until the exact-HEAD run completes.

## Remaining blockers

- Independent-session concurrency/race tests described above.
- Completion of exact-HEAD CI and all three Desktop Tauri workflows for 51c5108f5d00b07aa3afd0712b0b06c7fad16c79.
- Production primary/witness services, independent trust anchors, and production credentials remain external dependencies. Supabase transaction atomicity does not imply cross-service witness atomicity.
- PR #186 remains draft and is not approved, merged, or deployed.
