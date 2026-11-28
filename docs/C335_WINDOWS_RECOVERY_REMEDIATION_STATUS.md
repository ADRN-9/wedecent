# C335 — Windows recovery remediation and verification

**Repository:** `ADRN-9/wedecent`  
**PR:** #209 — open, draft, unmerged  
**Source branch:** `security/c324-verified-update-admission-recovery`  
**Base branch:** `security/c298-transport-override-fail-closed`  
**Base SHA:** `629456e4a2f594adad7433589aaa3591454503d5`  
**Exact code HEAD validated:** `f9dff472fc6fe34df113e4a3e7926050eda3c044`  
**Validation date:** 2026-11-27

## Disposition

**Repository implementation and hosted CI validation: PASS.**  
**Production acceptance: BLOCKED pending persistent privileged Windows VM acceptance and remaining SCM identity review.**

GitHub PR metadata confirms the exact source branch and HEAD above, open/draft=true/merged=false. GitHub compare reports 215 commits ahead, 0 behind, and merge-base exactly equal to the PR base SHA. No history rewrite or merge was performed.

## Implementation delivered

### 1. Durable installer metadata preservation

`installer/windows/Install-WeDecent.ps1` now:
- Snapshots the exact previous `ProgramData\WeDecent\installer.json` bytes to a transaction-specific backup before changing metadata.
- Verifies the snapshot SHA-256 and applies the protected metadata ACL.
- Binds metadata path, prior-existence flag, digest, and backup path into the transaction journal.
- Validates the snapshot during interrupted-transaction recovery.
- Restores and verifies the prior metadata as part of rollback.
- Cleans the metadata snapshot only after the transaction is durably committed and the snapshot digest is verified.
- Gates service restart on successful restoration of binaries, metadata, and the rollback journal.

If binary restoration, metadata restoration, or journal publication fails, the service is intentionally not restarted. If a rollback restart itself fails, the service is stopped again and the operation reports failure.

### 2. SCM recovery and ordering

Both installer recovery paths now require the named SCM service to exist and require its command line to match the expected quoted `wd-agent.exe` path and authenticated state-directory argument.

Recovery:
1. Verifies the transaction journal, five binary entries, metadata snapshot and backups.
2. Verifies SCM service identity and confirms the service is stopped.
3. Restores all five prior binaries and verifies their hashes.
4. Restores the exact prior installer metadata and verifies its hash.
5. Durably writes the `rolled-back` journal phase.
6. Only then attempts to restart the service if the journal says it was previously running.
7. Verifies the expected Running/Stopped state. A failed restart triggers another stop attempt and returns failure.

The installer now runs the interactive user-process preflight before invoking interrupted transaction recovery, so recovery cannot stop the service before the normal user-process guard has run.

The committed recovery finalizer also verifies and removes a committed metadata snapshot after durable commit, alongside the binary backup cleanup.

### 3. Adversarial tests

`scripts/test-windows-install-recovery.ps1` now exercises:
- Interrupted metadata restore using a pre-existing partial restore temporary file.
- Exact prior metadata byte/hash restoration and repeated idempotent restoration.
- Corrupted metadata snapshot rejection.
- Missing snapshot plus corrupted current metadata rejection.
- Inconsistent metadata journal path rejection.
- Missing SCM service rejection.
- Mismatched SCM image-path rejection.
- Restart failure with service left stopped, rollback journal persisted, and all five original binary hashes preserved.
- Committed metadata snapshot cleanup.
- Existing repeated recovery, inconsistent binary journals, missing/corrupt/replaced/misassociated binary backups, and five-binary integrity cases.

The installer metadata helper functions are parsed from the production installer AST and executed against isolated ACL-protected synthetic metadata fixtures. The SCM cases create and remove a temporary Windows service on the hosted Windows runner; they are not a persistent-VM or reboot acceptance test.

`scripts/test-windows-upgrade-preflight.ps1` was updated to verify that interactive user-process preflight precedes interrupted recovery and normal service mutation.

## Exact-HEAD GitHub Actions evidence

All three requested workflows completed successfully for code HEAD `f9dff472fc6fe34df113e4a3e7926050eda3c044`.

| Workflow | Run ID | Result |
|---|---:|---|
| C324 updater exact-head security tests | `46034829057` | SUCCESS |
| Repository CI | `46034827067` | SUCCESS — 9/9 jobs |
| Desktop shell | `46034826974` | SUCCESS — 3/3 platforms |

### Repository CI jobs

| Job | Job ID | Result |
|---|---:|---|
| relay-worker | `140627600353` | SUCCESS |
| control-plane | `140627600883` | SUCCESS |
| supabase-db | `140627600921` | SUCCESS |
| windows-agent | `140627601134` | SUCCESS |
| macos-agent | `140627601153` | SUCCESS |
| windows-release | `140627601412` | SUCCESS |
| route-capability-client | `140627602133` | SUCCESS |
| route-e2e | `140627748606` | SUCCESS |
| linux | `140627863320` | SUCCESS |

The Windows-agent job passed the installer recovery/backup integrity test, SCM recovery credential contract, state-migration coordinator, replay-store regressions, native Windows agent test, state ancestor ACL tests, hostile ancestor rejection, service SID provisioning, native binary build, and version/UI autostart checks.

### Desktop shell jobs

| Platform | Job ID | Result |
|---|---:|---|
| Windows | `140627636958` | SUCCESS |
| Linux | `140627637255` | SUCCESS |
| macOS | `140627637266` | SUCCESS |

These are actual hosted GitHub Actions results tied to the exact code HEAD. No tests were run locally by this operator.

## Remaining blockers and limitations

### Persistent privileged Windows acceptance — NOT ESTABLISHED

Hosted `windows-latest` CI now exercises an ephemeral SCM service, service stop/start failures, ACL behavior, service-account provisioning, and native Windows builds. It does **not** establish a persistent privileged Windows VM or prove recovery across an actual power loss/reboot with a durable Program Files and ProgramData installation.

Required acceptance still includes interruption at each journal/metadata/binary replacement boundary, reboot, repeated recovery, five-binary and metadata hash verification, SCM state verification, and corrupted/missing backup cases on the same persistent VM.

- Accountable organization: **ADRN-9**.
- Named individual VM provisioning/operator: **not designated**.
- Persistent VM identity, availability and access: **not evidenced**.

ADRN-9 must designate the individual operator and confirm/provision the isolated persistent privileged Windows VM. Hosted CI is not a substitute.

### SCM account binding review

The recovery path verifies SCM service existence, executable path, state-directory argument, and expected service state. It does not yet compare the SCM `StartName` account SID to the `service_account_sid` recorded in protected installer metadata. That remains a security-hardening item before production acceptance.

### Release controls

PR #209 remains open, draft and unmerged. No production signing, publication, deployment, credential provisioning, or trust-anchor changes were performed. Repository readiness must remain separate from production publication.

## Final C335 status

- Metadata snapshot/restore implementation: **delivered**.
- SCM existence/path/state handling and journal/restart ordering: **delivered**.
- Hosted adversarial recovery tests: **passed**.
- Exact-HEAD updater security, repository CI, and Windows/Linux/macOS Desktop workflows: **passed**.
- Persistent privileged Windows acceptance: **blocked / not established**.
- SCM service-account SID cross-check: **outstanding**.
- PR merge, production signing/publication/deployment: **not performed**.
