# C299 — Desktop usability, port forwarding, and managed control-plane assessment

Assessment date: 2026-11-26 (GitHub repository timestamps observed; timestamps are later than the operator's stated local date and should be reconciled).
Repository: ADRN-9/wedecent
Audited default-branch HEAD: `acbca90e10a4d51cb0ca0ec9f066089fbac97bb7`
Scope: source and GitHub metadata inspection only. No shell commands, local test execution, hardware testing, deployment, signing, or production activation were performed.

## Executive result

The default branch contains a meaningful renderer-only Tauri desktop implementation and a documented Local Core authority boundary. Secure forwarding is implemented on a separate, unmerged draft PR (#186), with further checkpoint-authority hardening on dependent draft PR #187. Managed-account foundations exist in the default branch, while tenant authorization and tenant audit hardening are on dependent, unmerged draft PRs #180 and #181. SSO (OIDC/SAML), mature device groups/RBAC, multi-region relay selection, production deployment, and real-hardware acceptance are not established by this review.

PR #205's malformed transport-override remediation is a 4-file patch at `d2efed65df7f8e02d44293d49606656725b2354d`. GitHub reports zero check runs and zero commit statuses for that exact SHA, and the commit-workflow query returns no runs. Its base is PR #203's branch, not `main`; it is open, draft, and unmerged. Do not treat it as integrated or CI-accepted.

## Repository / PR reconciliation

| Item | Observed state |
|---|---|
| Default branch | `main` |
| Default branch HEAD | `acbca90e10a4d51cb0ca0ec9f066089fbac97bb7` |
| PR #205 | Open, draft, unmerged; head `d2efed65df7f8e02d44293d49606656725b2354d`; base `security/c228-windows-service-e2e-hardening` |
| PR #203 | Open, draft, unmerged; head `e3051e38bea95c414711e71554ae32a75a305a3c`; base `security/c227-windows-preflight-service-recovery` |
| PR #176 | Open, draft, unmerged; head `eaba551d5d18e540dd96f752aa2b049248b95505`; base `main` |
| PR #186 | Open, draft, unmerged; head `7773660e0481427ebffb0c53a0ed7bcce1b1db03`; base `main` |
| PR #187 | Open, draft, unmerged; head `565b4460e0b8183694253173872af6aff1c0974e`; base `feat/secure-port-forwarding-foundation` |
| PR #180 | Open, draft, unmerged; head `078640e026ed055c9747870e14a89eefb5b20100`; base `security/active-terminal-revocation-wd-rev01` |
| PR #181 | Open, draft, unmerged; head `e3ccdf91d1128aedb1fbf841c92fa6356d519308`; base `security/tenant-authorization-wd-cp01` |

PR #205 modifies:
- `cmd/wd/transport_locator.go`
- `cmd/wd/transport_locator_test.go`
- `cmd/wd/pair_lan_discovery.go`
- `cmd/wd/pair_lan_discovery_test.go`

The diff rejects non-empty transport override values with surrounding whitespace rather than treating them as absent; it adds negative tests for whitespace-only overrides and discovery conflicts. This is a narrow fail-closed correction. It does not establish the broader transport acceptance criteria.

### Exact-commit workflow evidence

- PR #205 SHA `d2efed65df7f8e02d44293d49606656725b2354d`: GitHub check-runs endpoint returned `total_count=0`; commit status endpoint returned `state=pending,total_count=0`; commit-workflow query returned no runs. **No CI pass claimed.**
- PR #203 SHA `e3051e38bea95c414711e71554ae32a75a305a3c`: CI run 45770285073 and Desktop shell run 45770285111 both completed successfully. These runs validate that SHA, not PR #205's later head.
- PR #186 SHA `7773660e0481427ebffb0c53a0ed7bcce1b1db03`: CI run 45528326348 and Desktop shell run 45528326409 both completed successfully. This is branch CI evidence, not proof of production readiness or a merge.
- PR #180 SHA `078640e026ed055c9747870e14a89eefb5b20100`: CI run 44967451417 and Desktop shell run 44967451432 both completed successfully.
- PR #181 SHA `e3ccdf91d1128aedb1fbf841c92fa6356d519308`: CI run 44967476404 and Desktop shell run 44967476420 both completed successfully.
- PR #187 SHA `565b4460e0b8183694253173872af6aff1c0974e`: commit-workflow query returned no runs.

The repository's default branch tree was read at `acbca90e10a4d51cb0ca0ec9f066089fbac97bb7`. Its workflow files include `.github/workflows/ci.yml` and `.github/workflows/desktop.yml`. No run was returned for the default-branch SHA by the commit-workflow query.

## A. Desktop usability

Default-branch evidence includes `docs/DESKTOP_SHELL.md`, `docs/DESKTOP_UX.md`, `docs/DESKTOP_UX_V3.md`, Tauri bridge code in `desktop/src-tauri/src/main.rs`, renderer assets in `desktop/dist/`, file-transfer UI/native code, and deterministic UI behavior/boundary tests in `desktop/scripts/`.

The design explicitly keeps device inventory, terminal streams, session authority, trust, and transport decisions in Local Core / wd-agent. Renderer filtering, profiles, keyboard navigation, appearance, and tab selection are presentation-only. The renderer file-transfer command surface is allowlisted to status/upload-picker/download-picker operations; native/Core owns paths, bytes, validation, lifecycle and cancellation. Desktop CI scripts include JS syntax checks, deterministic behavior tests, renderer-boundary checks and UX contract checks. These scripts were inspected but not executed in this assessment.

| Requirement | Classification | Evidence / limitation |
|---|---|---|
| Device discovery and selection | PASS (implementation-level) | Tauri bridge exposes sanitized Core inventory and transport summaries; UX contract restricts inventory to Local Core. No live-device E2E was performed. |
| Secure terminal sessions | PASS (architecture/implementation-level) | Tauri uses a local bridge to Core-owned connections and terminal streams; no renderer networking/trust authority. No independent security penetration or production session test. |
| Multiple tabs/streams | PASS (implementation-level) | UX contract defines tab/tabpanel behavior and deterministic keyboard navigation; Core owns stream IDs. Renderer behavior tests exist. |
| Profiles | PASS (bounded UI implementation) | Profiles are documented as local labels plus canonical device IDs and resolve against current Core inventory. Persistence/runtime UX not independently exercised here. |
| File transfer | PASS (bounded UI/Core boundary implementation) | Native picker command surface and native/Core ownership documented and guarded by renderer-boundary checks. End-to-end transfer, platform picker and recovery behavior not executed. |
| Accessibility / keyboard | PASS (contract and regression-test implementation) | Tab semantics, focus behavior, labelled dialogs, live regions, high contrast, reduced motion, keyboard shortcuts and deterministic behavior tests are present. No assistive-technology/manual acceptance performed. |
| Connection/transport state | PASS (presentation contract) | UX contract distinguishes unavailable/busy/ready/success/failure; transport display is not identity or authority. No real transport-state E2E. |
| Recovery/error handling | NOT ESTABLISHED (product acceptance) | Fail-closed Core-unavailable behavior and explicit states are specified; this review did not exercise restart, disconnection, stale state, or OS recovery workflows. |

Desktop implementation-level PASS classifications are not a claim of release readiness. Canonical desktop workflows and manual cross-platform acceptance remain required on the release candidate.

## B. Secure port forwarding

Default branch does not contain the `internal/portforward` implementation tree. The implementation is on PR #186, which adds Local Core API/client/server integration, agent configuration, authorization, destination/session handling, replay/checkpoint fencing, audit adapters, and tests. PR #187 adds a separate checkpoint-authority principal, dedicated short-lived authority JWT boundary, PostgreSQL checkpoint trust registries, and recovery tests.

| Requirement | Classification | Evidence / limitation |
|---|---|---|
| Local forwarding authorization | BLOCKED | Implementation and tests are present on unmerged PR #186; not in audited `main`. |
| Remote forwarding authorization | BLOCKED | Same PR branch; dependent security hardening in PR #187 is also unmerged. |
| Bounded destinations/listeners | BLOCKED | Destination/session and agent configuration validation code/tests are on PR #186; cannot count as integrated default-branch behavior. |
| Lifecycle limits and cleanup | BLOCKED | Manager, session and persistent tests are on PR #186; no runtime acceptance performed. |
| Audit events | BLOCKED | Audit/checkpoint code and tests are on PR #186; centralized tenant audit foundation is separately on PR #181. |
| Replay protection | BLOCKED | Durable replay/checkpoint code/tests are on PR #186; dependent authority isolation and recovery work is on PR #187. |
| Negative tests / fail-closed behavior | BLOCKED | Relevant tests exist in PR #186/#187; CI evidence is successful for #186 SHA only, with no workflow run established for #187 SHA. |
| Local Core remains authority | PASS (architecture in candidate) | PR #186 routes operations through Core API/IPC and agent-owned configuration. Integration is blocked by the unmerged candidate chain. |

Security note: PR #187's source changes a privileged database authority model and replay-fence recovery. Its absence of exact-SHA workflow evidence is a material gate; do not merge or enable remote forwarding until its database, concurrency, failure-injection and authority-boundary gates are demonstrated.

## C. Managed control plane

Default-branch evidence includes account-authorization and enrollment migrations, device-enrollment Edge Function, connection-grant and route-authorization functions, and RLS-oriented tests. `docs/SUPABASE_CONTROL_PLANE.md` describes Supabase as metadata/account authorization only; raw terminal bytes remain on the endpoint/relay path. It explicitly separates endpoint Ed25519 proof from account-level authorization grants.

PR #180 adds tenant authorization hardening and an enrollment-race test. PR #181 adds tenant-scoped append-only audit storage and database tests. Both are open draft PRs in a dependency chain, not integrated into `main`.

| Requirement | Classification | Evidence / limitation |
|---|---|---|
| Organizations and users | PASS (foundation only) | Account authorization schema and Supabase Auth/organization/membership design exist in `main`; operational production tenant lifecycle not validated. |
| Device enrollment and management | PASS (foundation only) | Enrollment function/migrations and endpoint identity binding exist; hardened tenant authorization remains on unmerged PR #180. |
| OIDC / SAML SSO | NOT ESTABLISHED | No verified implementation or acceptance evidence identified in this inspection. |
| RBAC and device groups | NOT ESTABLISHED | Terminal access/role foundation exists, but complete managed RBAC, group lifecycle and enforcement matrix not established. |
| Audit/search/retention | BLOCKED | Local bounded JSONL audit exists; tenant-scoped append-only audit candidate is PR #181. Search, retention enforcement and operational audit controls are not proven. |
| Multi-region relay selection | NOT ESTABLISHED | No verified region-selection policy, failover implementation or acceptance evidence identified. |
| Separation from device identity / routing authority | PASS (architecture-level) | Account grants are distinct from endpoint Ed25519 proof and routing/relay proof-of-possession. Production enforcement requires integration tests and deployed control-plane validation. |

## Cross-cutting security / dependencies

1. **PR #205 workflow gap:** workflow PR-base filters observed in PR #203/205 context do not include the PR #203 base branch. The #205 head has no checks. Add an explicit supported base or otherwise ensure PR #205 receives CI before review/merge.
2. **Dependency chain:** PR #205 → #203 → #202 → #201 → #200 → #199, and PR #187 → #186. PR #181 → #180. Preserve ancestry; do not retarget or merge out of order without dependency review.
3. **Windows infrastructure:** persistent-VM acceptance and service-account/ACL validation require the supported Windows runner and infrastructure ownership. Passing CI on an earlier SHA is not a substitute for persistent-VM evidence.
4. **Physical transports:** Linux/Windows Bluetooth RFCOMM, USB CDC-ACM, Linux USB gadget CDC-ACM, and USB NCM/direct-TCP remain NOT ESTABLISHED until real hardware demonstrates cryptographically authorized terminal sessions.
5. **Release trust:** production update trust-root provisioning, external signing, immutable publication, Windows state ACL validation and rollback protection remain separate release gates. No signing/deployment was attempted.
6. **Managed provider inputs:** OIDC/SAML provider configuration, production tenant policy, regional relay deployment and customer-data retention/legal decisions need explicit provider/operator evidence.

## Execution log / honesty

- Direct GitHub repository, PR, file, commit-status, check-run, workflow-run, and branch metadata were inspected.
- No local repository checkout, shell command, test command, desktop build, database migration, hardware test, production operation, PR merge, or code change was executed.
- This commit adds only this assessment report. It does not implement or certify any product capability.
- The successful workflow results listed above are GitHub Actions results tied to their exact SHAs. They are not tests run in this ChatGPT session.

## Recommended next engineering gates

1. Correct PR #205 CI targeting and obtain fresh CI + Desktop shell runs on `d2efed65df7f8e02d44293d49606656725b2354d`; then review the patch against its full dependency ancestry.
2. Obtain exact-SHA CI and database/security acceptance for PR #187, then review PR #186 end-to-end with destination abuse, listener binding, lifecycle exhaustion, audit failure, replay and revocation negatives.
3. Validate desktop release candidate on Windows, Linux and macOS, including Core restart/recovery, screen-reader and keyboard-only operation, profile corruption, file transfer interruption and OS-native dialogs.
4. Complete tenant enforcement and audit chain (#180/#181), then add OIDC/SAML, device groups/RBAC, search/retention and region-aware relay policy with tests.
5. Keep production activation blocked until infrastructure, signing/trust-root and real-hardware gates have independently recorded evidence.
