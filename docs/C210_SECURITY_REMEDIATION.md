# C210 — history-preserving recovery remediation

## Refreshed baseline

Repository: ADRN-9/wedecent

- main: `acbca90e10a4d51cb0ca0ec9f066089fbac97bb7`
- PR #176: `eaba551d5d18e540dd96f752aa2b049248b95505`
- PR #186: `7773660e0481427ebffb0c53a0ed7bcce1b1db03`
- PR #188 at refresh: `dfd61f6dc655cb51f51f38d82ad9adb6ce1929e6`
- C210 branch: `security/c210-history-preserving-recovery`

The C210 branch was created from the refreshed PR #188 head. A two-parent merge commit
`6ff65a87cf448b5dfa5795a9aa6b6f5f7fea6193` uses the unchanged PR #188 tree and
has PR #188 and PR #176 as its parents. PR #186 is already an ancestor of PR #188.
This preserves both original branch histories without rewriting either original
branch. The original PR branches and PR #188 branch were not force-pushed.

## Shared-file semantic union

The refreshed PR #188 tree was inspected against both source branches:

| File | PR #176 behavior | PR #186 behavior | C208 integration evidence |
|---|---|---|---|
| internal/audit/log.go | pairing attempt IDs and validation | forwarding IDs, direction and destination audit fields | both sets present |
| internal/audit/log_test.go | pairing audit regression suite | forwarding audit regression suite | expanded combined suite |
| internal/session/server.go | generation-bound pairing admission | forwarding runtime, authenticated router identity and authorized sessions | both code paths present |
| internal/trust/store.go | pairing trust insertion and durable replacement | forwarding trust-store integration | pairing insertion, deletion and uncertain durability retained |

This is a source-level semantic check, not a claim that every regression test passes.
The ancestry merge uses the already integrated C208 tree, and retains the two original
histories as merge parents. No original PR branch was modified.

## Clock discontinuity mitigation

Pairing credential metadata now persists `last_observed_at`.

- New V2 credentials initialize the high-water mark at issuance.
- V1 migration initializes it at migration time.
- A validation rejects a wall clock more than 30 seconds behind the persisted
  high-water mark.
- A forward observation is durably written before the credential is accepted.
- Secret rotation also rejects a detected rollback and persists a newer observation.
- Existing V2 metadata without the new optional field is initialized from issuance
  time on first successful validation.

The new deterministic regression covers a substantial rollback, tolerated small
backward skew, forward progress and persistence after restart.

This is a bounded local clock-discontinuity defense, not a trusted time service.
It cannot detect a clock change that occurs before the process next observes time,
nor can it resist an attacker who restores the credential metadata together with
other same-account-writable state. Production expiry still assumes a reasonably
trusted system clock. Future-issued credentials remain rejected by the existing
30-second issuance-skew rule.

## Durable revocation fault coverage

The trust-store regression suite already injected pre-replacement and directory-sync
failures for both trusted-clients.json and trusted-devices.json. C210 adds an explicit
post-replacement failure injection. The API must report uncertain durability rather
than claim revocation success when the replacement is visible but the persistence
boundary cannot be established.

Unix directory fsync and Windows local fixed-NTFS/write-through implementations are
present. These injected tests are not physical power-loss tests and do not establish
hardware/controller cache behavior.

## Outstanding security blockers

### Recovery archive key custody

The current C208 implementation still stores the archive HMAC key as
`pairing-outcomes.archive.key` in the protected state directory. File permissions,
ownership and Windows ACL checks do not protect it from a compromised process
running as the same OS account. This does not meet the C210 key-custody requirement.

A production fix requires a non-exportable signing/MAC operation backed by a
platform-protected key store or an independently administered signing service.
The key boundary must expose signing and verification, not export raw key bytes.
It also needs explicit provisioning, key identity/pinning, access policy, rotation,
and recovery procedures. No TPM/TPM2, Windows CNG non-exportable key, macOS Keychain
access-control, Linux Secret Service/TPM, or independently administered signing
service is currently provisioned or available through the repository integration.
Silently replacing the current key file with another same-account-readable file
would not remediate this finding. The existing key-file design remains a release
blocker pending a real provider and migration authority.

Migration cannot automatically trust a legacy local HMAC key against a same-account
attacker: the attacker could have modified both the archive and its MAC. The
migration must authenticate a known archive checkpoint out of band or obtain a
signed checkpoint from the independently administered authority. If that proof is
unavailable, recovery must stop for operator-assisted reconciliation; it must not
silently bless the local archive.

### Snapshot rollback protection

The archive checkpoint and active ledger currently live in the same local state
directory. Their hash/HMAC checks detect tampering without the key, but cannot
prevent a same-account attacker from restoring an older valid archive and matching
older active ledger. A protected monotonic authority is still required.

A safe implementation must bind the latest recovery-state generation and digest to
a non-rollbackable TPM/secure-enclave/OS-protected monotonic counter or independent
authority. It must fail closed if the local archive or ledger is behind the protected
head. A local counter file or a second file in the same directory is not an adequate
solution. The authority must define interrupted-update reconciliation; counter
advancement followed by a failed local write must remain explicitly uncertain and
must not roll back the protected head.

No such hardware/remote authority is provisioned in the current environment. This
is a release blocker, not a test-only gap.

## Changed-file inventory

- `internal/trust/pairing.go` — persisted clock high-water mark, rollback rejection,
  rotation checks and durable observation.
- `internal/trust/pairing_credential_test.go` — migration high-water assertion and
  deterministic rollback/forward-clock tests.
- `internal/trust/store_test.go` — post-replacement revocation failure injection.
- `docs/C210_SECURITY_REMEDIATION.md` — this handoff and remaining security gates.

The ancestry merge commit changes the branch graph but retains the C208 source tree.

## Validation and release status

- Repository/PR state refreshed before work.
- Original PR #176 and PR #186 branch refs left untouched.
- C210 ancestry merge commit created and pushed to the new branch.
- Source-level four-file semantic review completed.
- New tests added but not executed locally.
- No Go toolchain execution, race test, native Windows/macOS test, physical power-loss
  test, or hardware-backed key test was available in this session.
- Exact-HEAD CI and Desktop runs must be obtained after the final C210 commit.
- No merge, approval, signing, deployment or publication performed.

## Required next steps

1. Provision a platform-backed non-exportable signing authority or independently
   administered signing service and its public verification identity.
2. Provision a monotonic recovery-state authority and define its crash/recovery
   transaction before enabling archive compaction.
3. Implement and test authenticated legacy-key migration against an out-of-band
   known checkpoint; otherwise require operator recovery.
4. Add clock injection tests for recovery-ledger timestamps and document the trusted
   wall-clock boundary for all expiry decisions.
5. Run focused trust/audit/session tests, full CI and Desktop workflows on the final
   exact C210 SHA; independently review the four shared files and native platform
   persistence semantics.
6. Keep PR #176, #186 and #188 unmerged until all security and validation gates pass.
