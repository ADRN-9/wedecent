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

## C146 retry and idempotency follow-up

CI run 45353560190 tested commit `70116d6f77404d0055418c74c2cdec65d80b9193`.

- All 72 pgTAP assertions passed.
- All 12 revocation-ordering scenarios passed again, with committed-state assertions.
- The concurrent exact-forwarding retry exposed a second fixture defect: the test helper generated fresh `issued_at` and `expires_at` timestamps on each invocation. The production function correctly treated the changed signed-capability tuple as an idempotency conflict rather than a replay.
- The helper now captures one timestamp pair once and reuses those exact values for both concurrent retry calls and the JTI-reuse pair. This correction is commit `f18ecb42296f8d8f949dfd1bb2d053673bc4cd44`.

The run against `70116d6f77404d0055418c74c2cdec65d80b9193` therefore did not pass the duplicate-forwarding/JTI tests; the observed result was `{"reason":"idempotency-conflict","accepted":false}`. This was caused by inconsistent retry fixture inputs, not a replay acceptance or authorization bypass.

A new exact-HEAD CI run (45353560190) and Desktop run (45353559983) were started for `f18ecb42296f8d8f949dfd1bb2d053673bc4cd44`. At documentation time, the corrected Supabase concurrency step had not yet completed; Linux, Windows, macOS CI and all three Desktop platform checks were still running. No pass is claimed for the corrected duplicate/JTI tests until that exact-HEAD run completes.

## C146 capability-lifetime fixture correction

CI run 45353560190 tested commit `f18ecb42296f8d8f949dfd1bb2d053673bc4cd44`. The existing 72 pgTAP assertions passed, but the concurrency harness failed on its first authorization attempt because the fixed test expiry was set 10 minutes after issue time. The production authorization correctly enforces a maximum capability lifetime of 120 seconds.

The fixture now sets the expiry 90 seconds after the current time while retaining one captured issue/expiry pair for all retries. With the issue time captured one second before the test starts, the signed lifetime remains within the production 120-second bound and identical across idempotent retries. This correction is commit `8a6b82b312949142679b5a1f6563d02ca569e0c0`.

Exact-HEAD CI run 45353868208 and Desktop run 45353868172 were started for this correction. Their final results are pending. Do not treat the duplicate-forwarding or JTI-reuse cases as verified until the concurrency job passes on this SHA.

## C147 exact-HEAD concurrency verification

### Baseline exact-HEAD run: `98239463f3f85947aaba7ff8c5933f559880bb05`

CI run 45353967851 and Desktop run 45353967846 were recovered for the live PR head.

- Supabase job 138309126904 completed successfully.
- All four pgTAP files passed: 72 assertions.
- The 12 revocation-ordering cases passed, covering consume-first and revoke-first for initiator, destination, router, organization membership, device permission and route grant.
- Concurrent duplicate forwarding used identical capability fields and the same forwarding ID/JTI. The retry returned `replayed: true`; committed-state assertions found exactly one forwarding transaction and one replay entry.
- Concurrent reuse of one JTI under a different forwarding ID was rejected with `jti-conflict`; committed-state assertions found exactly one transaction for that JTI and no transaction for the competing forwarding ID.
- The harness completed with `All deterministic multi-session authorization races passed.`

The baseline run's Windows agent, macOS agent, Windows release, relay worker, route-capability client, control plane, route E2E and Supabase jobs succeeded. Its Linux job was cancelled when the follow-up rollback regression commit superseded this SHA. Desktop Windows and macOS succeeded; Desktop Linux was still running when superseded.

### Rollback regression: `932ffb9aad0f0464154fb8cbcd40a5556bd29da8`

CI run 45355055535 passed all 72 pgTAP assertions and all 12 revocation races, but the newly added rollback test failed because its shell `printf` emitted literal backslash-n text rather than line delimiters. This was a harness command-framing defect. No production authorization check was weakened.

### Corrected rollback regression: `7b6c16323d097ff24fa6429cf8df63058f0791dd`

The rollback command now sends actual line delimiters and a PostgreSQL `\\q` meta-command. The harness reports failure logs if the rollback psql process exits nonzero.

CI run 45355468789, Supabase job 138312159085, completed successfully:

- All four pgTAP files passed: 72 assertions.
- All 12 revocation-ordering scenarios passed.
- Rollback-after-authorization passed: no forwarding transaction row, no replay entry, and unchanged replay-authority generation and state hash after rollback.
- Exact retry after rollback succeeded with the same forwarding ID, JTI, route grant and capability timestamps; final state contained exactly one transaction and one replay entry, and replay generation advanced by exactly one.
- The concurrent duplicate-forwarding and concurrent JTI-reuse checks also completed successfully as part of the same harness step.
- The Supabase job concluded `success`.

At documentation time, the same exact-HEAD CI run 45355468789 had these other results: control-plane, Windows release, macOS agent, route-capability client, relay worker, Windows agent, route E2E and Supabase all succeeded; Linux was still running its final race detector and transport smoke tests. Desktop run 45355468781 had all three Tauri jobs running (Linux, macOS and Windows). No final pass is claimed for those still-running jobs.

### Remaining limits

- The SQL transaction proves atomicity only within the Supabase/PostgreSQL primary. It does not prove atomic commitment with independently operated replay witnesses or establish independent witness quorum.
- Production acceptance remains withheld pending independent witness infrastructure/security verification and production infrastructure/trust-anchor gates.
- No real-hardware Bluetooth or USB validation is established by these CI runs.
