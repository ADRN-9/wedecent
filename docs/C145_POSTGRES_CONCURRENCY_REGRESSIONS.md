# C145 — deterministic authorization concurrency regressions

Date: 2026-11-24

## Scope and exact starting state

- Repository: ADRN-9/wedecent
- PR: #186 (must remain open and draft)
- Starting PR HEAD: `092d2edb46c5bb5adf2f007b43dc9f0c113f2c14`
- C144 corrections recovered: `f26e6ea0b16b13762a4fe7729c8310f946cbb674` and `092d2edb46c5bb5adf2f007b43dc9f0c113f2c14`
- C144 exact-HEAD CI run: 45351013167; all nine jobs ultimately succeeded, including Supabase DB and Linux.
- C144 exact-HEAD Desktop run: 45351013154; Windows and macOS succeeded; Linux Tauri check was cancelled. Desktop is therefore not a complete pass.

## Implementation

Added `scripts/test-port-forward-db-concurrency.sh` and wired it into the `supabase-db` CI job immediately after the disposable database starts and the pgTAP suite completes.

The test uses two independent `psql` processes per race. Each session is tagged with a distinct PostgreSQL `application_name`. It does not infer order from elapsed time: the harness polls `pg_stat_activity` until the competing transaction is observably waiting on a PostgreSQL lock, then commits the lock holder. The committed database state is checked after both sessions finish.

The harness exercises both orderings for:
- Initiator device revocation.
- Destination device revocation.
- Router device revocation.
- Initiator organization membership removal.
- Destination `port_forward.local` permission removal.
- Router route-grant revocation.

It also exercises concurrent duplicate forwarding-ID/JTI consumption (same signed authorization) and concurrent JTI reuse under a different forwarding ID. Expected outcomes are idempotent replay for the exact same transaction and `jti-conflict` for reuse by a different transaction.

The existing migration's canonical lock order and independent participant checks are unchanged. The test only validates PostgreSQL primary transaction ordering. It does not claim atomicity with independent replay witnesses.

## Important verification boundary

No local shell, Docker, or PostgreSQL execution was available through the repository connector. The new harness is committed and scheduled in GitHub Actions, but its runtime result must be read from the exact-HEAD CI run before it can be called verified. The script has not been represented as passing.

## Protected operations

No force-push, merge, approval, deployment, or production operation was performed. PR #186 remains open and draft.

## CI infrastructure recovery

The first CI attempt containing the concurrency harness (run 45352068936) failed before pgTAP or the new harness ran: Docker could not bind the default Supabase database port 54322 because it was already occupied on the hosted runner. This was an infrastructure port collision, not a migration or test assertion failure.

The CI workflow now probes an available host port and appends a temporary `[db]` port override to the checked-out local Supabase config before startup. The repository's committed `supabase/config.toml` is unchanged. The test harness reads the actual `DB_URL` reported by `supabase status -o env`, so it follows the selected port.

The retry at CI run 45352285692 was still in progress at the time of this report. The database startup step had not yet completed; no concurrency test result is claimed.

## C146 exact-HEAD execution evidence

CI run 45352598153 was executed against `396584e0478d19585cf8d301194f291665f08f27`.

- All 72 existing pgTAP assertions passed (4 files).
- All 12 revocation-ordering cases completed successfully: consume-first and revoke-first for initiator, destination, router, organization membership, destination access permission, and route-grant revocation.
- Each race observed the competing session in a PostgreSQL lock wait before allowing the lock holder to commit, then asserted the committed authorization-transaction state and revocation postcondition.
- The first harness attempt failed after those 12 cases while setting up the duplicate/JTI scenarios: test fixture route-grant JTIs collided with previously inserted unique route-grant JTIs. This was test-data namespace collision, not an authorization race failure.

Corrective change in commit `4c09830db4eefe467b6b171472ec92b6934acb30` gives route-grant JTIs and forwarding transaction JTIs disjoint unique values for the duplicate and reuse cases. The exact-HEAD rerun is pending; no claim is made yet that duplicate retry and JTI-reuse tests passed.

Run 45352598153 also had successful Windows agent, control-plane, relay-worker, Windows release, macOS agent, route-capability-client and route-E2E jobs. Linux was still running when inspected. The Supabase job failed only in the harness step after the 12 successful races; database startup and all pgTAP tests succeeded. Desktop run 45352598149 had Windows, macOS and Linux Tauri checks in progress at last inspection.

The Supabase startup step initially encountered public registry `Data limit exceeded` responses but its configured retry/fallback recovered and startup completed. This did not fail the database job.
