# Production release trust and provenance

Production release builders fail closed unless the approved replay-authority configuration is supplied. No production hostname, SPKI pin, approval digest, signing identity, private key, or storage credential is committed to this repository.

## Protected GitHub configuration

Before creating or using a production release tag, provision all three GitHub Actions environments:

- `wedecent-production-release`
- `wedecent-production-signing`
- `wedecent-production-publication`

Each environment must:

- Require at least one independent reviewer; do not allow the initiating actor to approve their own release.
- Restrict deployments to the approved `v*` release-tag pattern.
- Keep production configuration at environment scope. Do not define repository- or organization-level fallback variables with the same names.
- Be administered separately from the code author where separation of duties is required.

The following values are required in each environment that runs a production build, signing, or publication boundary:

- `WEDECENT_PRODUCTION_RELEASE_APPROVED=true`
- `WEDECENT_REPLAY_AUTHORITY_HOSTNAME`
- `WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256`
- `WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256`

The explicit approval marker is a configuration guard, not proof that GitHub environment protection is configured. The environment's required-reviewer rule is the human approval boundary. A SHA-256 digest without an independently controlled signing key or provider approval is not independent authorization.

The hostname must be a canonical lowercase DNS name. SPKI pins must be one to four unique lowercase SHA-256 hex digests separated by commas. The approval digest is recomputed over these exact UTF-8 bytes, including the final newline:

    wedecent-replay-authority-approval-v1
    hostname=HOSTNAME
    spki_sha256=PIN1[,PIN2...]

The digest binds the exact hostname/pin tuple and detects substitution; it does not replace approval by the replay-authority owner. Do not provision these values until the owner has supplied and independently approved the real production hostname and SPKI pins. Test values are permitted only in regression fixtures.

Create a tag ruleset for `refs/tags/v*` that restricts tag creation to authorized release operators/automation and blocks tag updates and deletions. A protected branch ruleset for `main` does not protect release tags. Provider-side environment and tag-rule settings must be inspected independently; the workflow cannot prove that those settings exist merely because it references an environment name.

## Build modes and source provenance

All three release builders default to production:

- `scripts/build-windows-release.sh`
- `scripts/build-linux-release.sh`
- `scripts/build-macos-release.sh`

Production mode requires GitHub Actions context for `ADRN-9/wedecent`, the exact checked-out `GITHUB_SHA`, the matching `vVERSION` tag, a clean source tree, the canonical repository origin, and a commit-derived `SOURCE_DATE_EPOCH`. Caller-supplied commit overrides and dirty-tree overrides are rejected. The checked-out commit and Git tree are recorded in `VERSION.txt`.

At signing and publication boundaries, `wedecent_verify_release_metadata` resolves the Git tree object for immutable `GITHUB_SHA` from the checked-out repository and requires the artifact's `source_commit` and `source_tree` to match that exact commit/tree pair. A well-formed but substituted 40-character tree hash is rejected. The check does not trust a tree hash merely because it was copied into an artifact.

For local development and ordinary CI, explicitly use `WEDECENT_BUILD_MODE=diagnostic`. Diagnostic artifacts carry `build_mode=diagnostic`, embed no replay-authority anchors, and are rejected by signing, installer-preparation, and publication boundaries. A diagnostic build is not a production release.

The Linux builder supports amd64 and arm64. The macOS builder supports amd64 and arm64. The Windows builder currently targets amd64. Builders use `-trimpath`, `-buildvcs=false`, an empty Go build ID, commit-derived timestamps, and deterministic SHA-256 manifests.

## Artifact provenance attestations

Each platform build produces a provenance sidecar under `dist/provenance/`. The sidecar binds:

- Repository and immutable source commit.
- The Git tree object associated with that commit.
- Artifact name and target platform.
- A sorted SHA-256 digest for every regular file in the artifact directory.
- `artifact_tree_sha256`, computed as SHA-256 over the sorted ASCII records `path NUL sha256 LF`.

The sidecar is itself the subject and custom predicate of a GitHub artifact attestation created with the pinned `actions/attest@v4.2.2` action. Verification requires the exact repository, this production workflow's signer identity, the release tag ref, the expected `GITHUB_SHA`, the corresponding Git tree, and matching digests for every artifact file. The signed Windows outputs receive new sidecars and attestations after Authenticode signing, so the published digest evidence describes the signed bytes rather than the unsigned inputs.

The manifest's digest list is not a substitute for the attestation. The attestation cryptographically binds the provenance sidecar to the GitHub Actions workflow identity; the verifier then independently checks the sidecar's source commit/tree and every file digest.

## Live release-tag verification

`scripts/verify-live-release-tag.sh` checks the live remote Git ref at each protected release boundary. It uses an exact `refs/tags/TAG` query through `git ls-remote --refs origin`, requires exactly one matching ref, and compares the remote ref-object SHA with the checked-out ref-object SHA.

- Lightweight tags must point directly to immutable `GITHUB_SHA`.
- Annotated tags must be a tag object whose embedded tag name matches the requested ref and whose direct target type is `commit` with target SHA equal to `GITHUB_SHA`.
- Both forms must peel to the exact immutable commit.
- Missing refs, duplicate/ambiguous responses, stale local refs, moved tag objects, malformed objects, nested tag targets, and mismatched target commits fail closed.

The check runs during production build initialization and again before each Windows/Linux/macOS build, artifact provenance verification, signing preflight, each Authenticode signing operation, signed-output staging, publication preflight, each create-only immutable upload, stable-manifest signing, and stable-pair publication. The production workflow also checks the tag before starting each protected job. This reduces the tag-movement window but is not a substitute for provider-side immutable tag rules: a tag can still move between a successful check and the next external operation unless GitHub rejects the ref update.

`scripts/test-release-tags.sh` creates isolated bare remotes and exercises valid annotated and lightweight tags, retargeting after build, missing tags, ambiguous exact-ref responses, and annotated tag-object reuse under a different tag name.

## Stable-manifest retry and atomicity regressions

The stable publisher now retries transient HTTP 408/425/429/500/502/503/504 responses and transport failures up to three times when probing stable object state. Unknown HTTP states fail immediately; exhausted retries fail before the publisher is invoked.

`scripts/test-windows-stable-update-publication.sh` covers a one-time HTTP 503 followed by success, retry exhaustion, monotonic sequence rejection, malformed/missing manifest-signature pairs, dry-run non-mutation, an injected publisher failure after staging, and a compare-and-swap conflict caused by a concurrent writer. Its test adapter models the pair as immutable generation directories selected by one atomic pointer replacement, so a failure before pointer swap leaves both published files and the pointer unchanged.

This is a regression test of the required adapter contract, not proof that the production R2 adapter exists or is atomic. The repository currently defines the external `WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER` interface but does not contain a production implementation. Two independent mutable R2 object writes are not an atomic pair operation. The production adapter must use a real transactional/CAS mechanism or a single-object commit pointer/envelope with readers bound to the same generation; it must not claim pair atomicity based only on sequential uploads.

## Live GitHub configuration inspection (2026-11-23)

The connected GitHub ruleset listing returned one active ruleset: `Protect main`, target `branch`, include `~DEFAULT_BRANCH`. No ruleset targeting tags was present. The current visible tag refs were:

| Tag | Ref object | Target commit | Object form |
|---|---|---|---|
| `v0.2.2` | `3314c50acf5a798550dc7358b87fe8917272bd41` | `ef56bf87e910cbe4c1265d0bcb64d779e11baec8` | annotated |
| `v0.3.0` | `9f7653ef06911f3d491e4a4de189a773b30dab21` | `33e339932821b442525e0fc0b0e1cc5751e805f6` | annotated |
| `v0.3.0-rc.1` | `dbff9930734ac2885b08baa50ebab0b7363a9574` | `dd0f01a8262627cca82a1bf027f1153e8f0cea6b` | annotated |
| `v0.3.0-rc.2` | `e023455a41d21c6bfb0b5c09d05a98d09865fef0` | `5d9535f78372d893ef27132b33af21a321eb332c` | annotated |
| `v0.3.0-rc.3` | `c9173f9efdc3c1b7209153b776f4e7733ecdbcbe` | `61494ac8098991d9fa4d452251db4725488f5b41` | annotated |

The exact active ruleset configuration required before production tags are used is:

1. **Creation ruleset:** name `Restrict WeDecent release tag creation`; target `tag`; include `refs/tags/v*`; enforcement `active`; rule `creation`; bypass only a dedicated release-operator team and the narrowly scoped release-tag automation identity.
2. **Immutability ruleset:** name `Protect WeDecent release tag immutability`; target `tag`; include `refs/tags/v*`; enforcement `active`; rules `update` and `deletion`; no bypass actors. Keep this as a separate ruleset so a creation bypass cannot also bypass update/deletion protection.

The current `Protect main` ruleset requires these eight status contexts: `route-capability-client`, `route-e2e`, `linux`, `windows-agent`, `windows-release`, `relay-worker`, `control-plane`, and `supabase-db`. It does not require `macos-agent` or any Desktop shell job. The Desktop workflow contexts that should be required are `linux-tauri-check`, `windows-tauri-check`, and `macos-tauri-check`. Add `macos-agent` and all three Desktop contexts to the protected main-branch ruleset after confirming their stable check names.

The connected GitHub interface exposed ruleset reads but not ruleset writes, environment reviewer settings, or runner inventory. Therefore this inspection cannot verify the required-reviewer configuration for `wedecent-production-release`, `wedecent-production-signing`, or `wedecent-production-publication`, nor can it prove that the self-hosted signing/publisher runners are online. The workflow's `environment:` declarations and approval marker variables are not evidence of required reviewers.

No production replay-authority hostname, SPKI pins, independent owner approval, Authenticode key, stable-update signing key, or public key provisioning was visible or supplied. No production signing/publication workflow evidence is claimed. Keep the protected release jobs fail-closed until the actual owner-approved values, environment reviewers, runners, and external adapters are provisioned.

## Endpoint binary inspection

`wd-core` and `wd-agent` both import the same `internal/buildinfo` trust-anchor variables. The builders inject the same approved hostname and SPKI pin set into both binaries, then independently inspect each binary's bytes. Native Linux/macOS builds invoke each binary's `release-trust` command and compare the exact runtime output. The production Windows build runs on a native Windows runner and executes both release-trust commands. Ordinary PR CI cross-builds diagnostic Windows binaries on Linux and uses the byte-level verifier only.

For an installed binary, run:

    wd-core release-trust
    wd-agent release-trust

This command reports public trust configuration only; it does not expose private keys or credentials.

## Production release workflow

`.github/workflows/production-release-build.yml` is tag-triggered and is designed to run these gates in order:

1. Validate canonical stable `vMAJOR.MINOR.PATCH` tag syntax, require the repository `VERSION` to match, and prove both checked-out `HEAD` and the tag ref resolve to immutable `GITHUB_SHA`. Pre-release and malformed tags stop before any production build.
2. Build Windows, Linux, and macOS production artifacts from the exact tag commit.
3. Build the Windows installer package from the same unsigned Windows release.
4. Create per-artifact provenance sidecars and GitHub OIDC/Sigstore attestations.
5. Download and verify every platform artifact, attestation identity, source commit/tree, and file digest.
6. Run the Windows Authenticode finalizer on the protected `wedecent-signing` self-hosted Windows runner. It rejects forged source-tree metadata before invoking the signer, verifies signatures, and atomically stages the signed release and installer.
7. Attest the final signed Windows release and installer bytes.
8. Publish immutable Windows archives through a create-only uploader. Existing objects are accepted only when their bytes are identical; ambiguous remote states and concurrent create-only conflicts fail closed.
9. Only after immutable downloads are verified and published, prepare, sign, verify, and publish the stable update manifest/signature pair with monotonic sequence enforcement and an atomic compare-and-swap publisher.

The signing job expects these environment variables to point to preinstalled, absolute, non-symlink adapters on the protected runner:

- `WEDECENT_WINDOWS_AUTHENTICODE_SIGNER`
- `WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER`

The signing runner must be isolated from untrusted workloads, run a supported GitHub Actions runner, provide Git Bash, Python, GitHub CLI, and the required file/hash utilities, and access a hardware-backed/non-exportable Authenticode signing key through the signer adapter. The workflow performs an early preflight before invoking repository scripts or the signer and rejects missing approval markers, trust-anchor values, or signer/verifier adapters. The signing key itself must not be stored in the repository, workflow variables, or release artifacts.

The publication runner uses the `self-hosted, linux, wedecent-release-publisher` labels and must provide Bash, Python 3, GitHub CLI, Go 1.27, curl, SHA-256 utilities, and a platform-compatible Authenticode verifier. Publication and stable-update jobs perform early preflights that reject missing environment markers, trust anchors, adapter executables, public keys, sequence values, or timestamps before invoking release scripts. Signing and publication preflights also re-check that the checked-out HEAD and live tag ref still resolve to immutable GITHUB_SHA. It requires these environment-scoped adapter paths:

- `WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER`
- `WEDECENT_R2_CREATE_ONLY_UPLOADER`
- `WEDECENT_UPDATE_MANIFEST_SIGNER`
- `WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER`
- `WEDECENT_UPDATE_PUBLIC_KEY_PATH`

The immutable-object uploader must perform atomic create-only writes. The stable-pair publisher must compare both current object digests and atomically replace the manifest/signature pair or leave both objects unchanged. The stable update private key must remain in an HSM/KMS or equivalent protected signer; only the public key is supplied to the verifier. The stable sequence is the workflow run number; the publication timestamp is generated in UTC immediately before the stable-manifest publication step.

The workflow references GitHub environments but cannot inspect or enforce their reviewer configuration. A missing or unprotected environment, missing tag ruleset, missing self-hosted runner, missing adapter, missing trust anchor, or missing credential must block the corresponding gate; do not bypass it or replace it with a caller-supplied marker.

## Remaining production dependencies

The repository workflow and scripts do not provision these provider-side inputs:

- Independent GitHub environment reviewers and tag-creation/update/deletion rules.
- Approved production replay-authority hostname, SPKI pins, and owner authorization.
- Protected Windows signing runner and Authenticode signer/verifier adapters.
- Protected publication runner, immutable R2 create-only uploader, and stable-pair atomic publisher.
- Stable update signing key and independently provisioned public key.
- Linux/macOS external signing identities and signing pipeline, if required by the distribution policy.

Until those dependencies are provisioned and a real tag-triggered workflow completes, no production signing, publication, stable-manifest activation, or production release should be claimed. Repository CI and successful diagnostic tests are not production release evidence.


## C313 — live branch-ruleset verification

On 2026-11-26, the active repository ruleset `Protect main` (ID `21507567`, target `branch`, enforcement `active`) was read from the GitHub repository rulesets API. The returned rule configuration is concrete evidence of the current main-branch policy, not a statement about tag rules or Actions environment protection.

Observed configuration:
- Required status contexts: `route-capability-client`, `route-e2e`, `linux`, `windows-agent`, `windows-release`, `relay-worker`, `control-plane`, and `supabase-db`.
- `macos-agent` is not required.
- Desktop contexts `linux-tauri-check`, `windows-tauri-check`, and `macos-tauri-check` are not required.
- Pull-request rule has `required_approving_review_count: 0`, `required_reviewers: []`, and `require_code_owner_review: false`; it does require resolution of review threads.
- The ruleset targets the default branch only. It does not protect `refs/tags/v*`.
- Ruleset `updated_at`: 2026-09-22T12:36:01.399-04:00.

The ruleset is active and prevents deletion/non-fast-forward updates, but its current review/status policy is weaker than the production release evidence requirements. Before production release authorization is exercised, an authorized repository administrator must update the policy to require the stable macOS and all three Desktop contexts, require an appropriate independent approval (and code-owner review where ownership is configured), and create a separate immutable release-tag ruleset for `refs/tags/v*`. Confirm the resulting rule configuration by reading it back; do not infer success from workflow declarations.

The GitHub integration can read this repository ruleset but the branch-protection endpoint returned 403 and the available interface does not expose Actions environment reviewer settings, self-hosted runner inventory/administration, or secret provisioning. Required reviewers for `wedecent-production-release`, `wedecent-production-signing`, and `wedecent-production-publication`, plus actual signer/publisher runner readiness, remain **NOT ESTABLISHED**. Do not bypass these gates or treat an environment name/approval marker as evidence of provider-side protection.

This is a repository-policy evidence update only. It does not change the ruleset, provision credentials, change production trust anchors, or run a production release.


## C314 — update-signing trust hierarchy, rotation and emergency revocation

### Security boundary and key roles

The production update-signing design has three deliberately separate identities. They must not share private-key material or credentials:

1. **Offline update trust root** — Ed25519 public key pinned in the shipped client build. Its private key is generated and held offline (or in an independently administered offline HSM); it is used only to authorize update-keyset metadata and root transitions. It is never present in GitHub Actions, the release runner, the publisher, or the update service.
2. **Online stable-manifest signing key** — Ed25519 key held by an HSM/KMS-backed signing service. The release workflow sends canonical manifest bytes to a narrow signer adapter; it cannot read or export the private key. The signer authenticates the approved release workflow identity, environment, immutable source commit/tag, sequence and artifact digests before signing. The signer does not have publication credentials.
3. **Independent verifier** — a separate implementation/identity that verifies signatures, keyset authorization, key status, manifest canonicality, sequence monotonicity, release provenance and artifact digests. It has read-only access to public trust material and cannot request signatures or publish objects. The client verifier is part of the application trust boundary; server-side release verification must not call the signing adapter as its verifier.

The immutable-object publisher is a fourth isolated role. It receives already signed and verified bytes and has create-only publication permissions, but no signing permission or access to the signing key. The signer must not have R2 credentials; the publisher must not have signer credentials. GitHub OIDC identity should be audience- and repository/workflow-scoped, and the external signer must reject arbitrary workflow callers even if they can invoke the adapter.

### Key provisioning ceremony — no development-key promotion

Production key provisioning is a recorded, two-person ceremony performed outside the repository and ordinary CI:

1. An independently named security owner and release owner approve the key algorithm (Ed25519), root/key roles, key IDs, validity window, rotation overlap, revocation SLA, HSM/KMS provider and recovery plan.
2. Generate the offline root in its approved offline boundary and the online manifest key inside the HSM/KMS. Do not generate either in a developer checkout, test, hosted runner, or ordinary release job. The online private key must be non-exportable and its signer must expose only a constrained signing operation over canonical manifest bytes.
3. Export only the root public key and online public key. Record their SHA-256 fingerprints, key IDs, HSM key handles/attestation, generation ceremony record, custodians, quorum policy, creation time, algorithm and validity. Never record private key bytes, recovery shares, PINs or secret material in GitHub issues, PRs, logs or this repository.
4. The offline root signs a canonical keyset document containing a monotonically increasing keyset epoch, root key ID, each manifest key ID/public key/algorithm, not-before, not-after, status and optional revocation time. The keyset format is versioned and strict: canonical encoding, bounded size, no duplicate IDs, no unknown fields, no ambiguous key encodings, and explicit UTC times.
5. Provision the offline root public key through a separately reviewed source change and release pipeline. The change must not be accepted solely because the new keyset or manifest contains its own key. Verify the shipped client binary's embedded root fingerprint from the exact reproducible release artifact.
6. Publish the signed keyset before any manifest references a newly provisioned key. Verify the keyset signature with the independently pinned root and read it back from the fixed origin. Only then permit the manifest signer to use that key ID.

No production root or online key has been generated or provisioned by this work. Existing test keys and CI-generated Ed25519 keys are test-only and must never be promoted.

### Manifest key identification and verifier admission

The current updateinfo DiscoveryClient accepts one explicitly provisioned Ed25519 public key and the current manifest signature is a detached signature over canonical manifest bytes. The current production public key path is an operator-supplied WEDECENT_UPDATE_PUBLIC_KEY_PATH; it is not yet a versioned, root-authorized keyset protocol. Do not silently interpret the existing single-key file as a trust root.

Before production key activation, introduce a versioned manifest/keyset protocol (new schema, no in-place reinterpretation of v1):
- Each signed manifest carries an explicit signing_key_id and keyset_epoch; the detached signature covers the complete canonical bytes, including these fields.
- The client first verifies a separately fetched/cached keyset with the offline root pinned in the client. It then requires the manifest key ID to be present, currently authorized, within validity, and not revoked at the manifest publication time and the client's trusted current-time policy.
- Keyset epochs and manifest sequences are monotonic and persisted with integrity protection. Lower epochs, stale keysets, unknown key IDs, duplicate key IDs, expired keysets, revoked keys and rollback attempts fail closed.
- A manifest cannot introduce, replace, or reactivate a key. Key material from the manifest, TLS endpoint, DNS, artifact or unsigned config is never a trust anchor.
- The first rollout must explicitly decide whether to support a temporary dual-verification window for a previously shipped v1 trust key. If no production v1 key has shipped, do not add a legacy fallback.

The current v1 verifier must remain unchanged until a reviewed v2 implementation and migration tests are complete. No keyset is currently live, and this protocol is a design gate rather than an implemented feature.

### Rotation, compromise and revocation

**Planned rotation:** publish a root-signed keyset at epoch N+1 with the new manifest key marked active and the old key marked verify-only with a bounded not-after. Distribute the new keyset before signing manifests with the new key. Require clients to observe epoch N+1 before accepting new-key manifests. After the overlap, mark the old key revoked and stop signing with it. Retain the old public key and audit records for historical verification, but do not permit it to authorize new manifests.

**Manifest-key compromise:** immediately disable the key in the external signer/HSM, revoke it in a new root-signed keyset, increment keyset epoch, block new publication, and publish the revocation through the fixed origin and an independent incident channel. Release a clean client/update policy that refuses the compromised key ID. Rebuild/sign affected releases with a new key only after the independent root authority approves. Do not rely on mutable CDN cache invalidation as the only revocation mechanism.

**Root-key compromise:** stop update acceptance through the compromised root, invoke the offline recovery quorum, and ship a client trust-anchor update through an independently trusted application distribution channel. A root transition must be signed by the currently pinned root and independently cross-signed by the replacement root, with strictly increasing root epoch and explicit old-root retirement. A client that has no valid chain from its pinned root must fail closed; there is no trust-on-first-use or manifest-supplied replacement root.

**Availability policy:** keysets should have a bounded validity interval and be refreshed before expiry. A client with an expired keyset cannot silently fall back to an older epoch or a key embedded in a manifest. The exact maximum staleness and offline grace policy must be approved by the security owner before production activation; default is no acceptance of newly discovered updates when authorization metadata is stale.

Every rotation/revocation event must retain an auditable record: request/ticket, two approvers, key IDs and fingerprints (public only), old/new epochs, effective UTC time, signer disablement confirmation, keyset digest, release commit/tag, published object generation and independent read-back verification.

### External signer/verifier and publication separation

The production workflow's WEDECENT_UPDATE_MANIFEST_SIGNER and WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER are currently operator-supplied executable adapters. A path check is not proof of adapter provenance, identity, policy or key non-exportability. Before production use:
- Pin signer/verifier adapter versions by immutable digest and validate ownership/permissions at runner startup; reject symlinks, writable-by-untrusted principals and mutable downloads.
- Authenticate workload identity using GitHub OIDC with exact repository, workflow path/ref, environment and audience conditions. Do not accept long-lived GitHub secrets as the only caller authentication.
- Have the signer independently validate the canonical manifest, key ID, keyset epoch, sequence, version, artifact URLs/digests, immutable source commit/tag and provenance attestations. Enforce sequence monotonicity inside the signing service, not only in the workflow.
- Return signature bytes plus a public audit receipt (key ID, digest, signer policy version, UTC time, request ID); never return key handles with signing authority or private material.
- Keep signer, verifier and publisher identities separate. Verify the signer's output with a public-key-only verifier process that has no signer socket, HSM session, publication credential or writable trust store.
- The publisher performs immutable create-only writes or a real CAS/single-pointer generation commit, reads back the exact generation, and cannot alter existing immutable artifact objects. The stable manifest and signature must be one reader-visible generation; sequential independent mutable object writes are forbidden.
- Preserve signed manifest bytes, signature, keyset, provenance, verifier output, publisher read-back and signer receipt as immutable release evidence.

CI fake adapters are regression fixtures only. No production signer/verifier, public key, HSM handle, OIDC policy, immutable uploader or atomic stable-pair publisher has been established by this C314 work.

### Live provider-policy evidence — 2026-11-26

The current live Protect main ruleset (ID 21507567) is active and targets only the default branch. It currently requires eight contexts: route-capability-client, route-e2e, linux, windows-agent, windows-release, relay-worker, control-plane, and supabase-db. It omits macos-agent and the three Desktop contexts linux-tauri-check, windows-tauri-check, and macos-tauri-check. The pull-request rule requires zero approvals, no required reviewers and no code-owner review. No release-tag ruleset was returned by the live ruleset listing.

Required production changes are therefore:
1. Set independent approving review count to at least one (prefer two for trust-anchor/signing changes), require code-owner review, dismiss stale approvals on new commits, and require last-push approval for sensitive release changes.
2. Require all nine CI contexts plus all three Desktop platform contexts, with strict up-to-date branch policy; confirm exact stable check names before writing.
3. Create a tag-creation ruleset for refs/tags/v* with narrowly scoped release-operator bypass, and a separate update/deletion prohibition with no bypass actors.
4. Configure each production Actions environment with independent reviewers, self-approval disabled, and v* deployment restriction. Read back settings through provider administration; workflow YAML is not evidence.
5. Verify dedicated signing and publisher runner groups, ephemeral/isolated workload boundaries, runner labels, image provenance, patching and network egress restrictions.

The GitHub integration available to this task can read rulesets but cannot write them or inspect environment reviewers/runner inventory. No policy update is claimed. These settings require a named repository administrator/security owner and provider-side administration.



### C314 workflow wiring audit — signer/publisher co-location is not acceptable

The current workflow source at this PR head contains one publish-stable-update job that injects both WEDECENT_UPDATE_MANIFEST_SIGNER and WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER into the same job, environment and self-hosted publisher runner. The script publish-windows-stable-update.sh invokes the signer, verifies the candidate with the public key, then invokes the pair publisher and reads the result back. The signer and publisher are distinct executable paths, but they are not isolated credential or workload identities in this wiring.

This is an implementation gap against the required trust separation, not a completed security control. Before production activation, split the flow into independently protected jobs and runner groups:
1. Stable-manifest preparation/signing job: receives verified artifact digests and release provenance, uses the update-signing environment and signer identity only, and emits a bounded signed-pair bundle plus public signer receipt. It must not receive R2 credentials, uploader executable or publication permissions.
2. Independent verification gate: runs with public key/keyset only, no signer socket/session and no publication credentials; verifies exact canonical manifest bytes, detached signature, key ID/epoch, monotonic sequence, artifact digests, release provenance and signer receipt.
3. Stable-pair publication job: receives only the verified signed bundle and expected prior object generation/digests; it has the create-only/CAS publisher identity only, no signer adapter, HSM session or signing permission. It rechecks the immutable tag and release approval, performs one atomic generation/pointer commit, and reads back and verifies the exact published generation.
4. Retain the signed bundle, verifier report, publisher generation ID/read-back digests and workflow attestations as release evidence.

The current production workflow does not implement this split. The stable-manifest script also prepares, signs, verifies and publishes in one invocation. Both require a reviewed refactor and negative tests proving the signer cannot publish and the publisher cannot sign. A separate executable path or environment variable alone is not isolation.

### C314 repository ownership and provider administration evidence

The current source tree has no CODEOWNERS file, so requiring code-owner review in a ruleset would not by itself establish meaningful ownership until an approved CODEOWNERS map exists. The live ruleset API remains read-only through the connected integration. The ruleset listing shows only Protect main; no tag-targeted ruleset was returned. Direct branch-protection read returned HTTP 403. Repository Actions environment, runner inventory and runner-group endpoints were not available through this integration. Therefore environment required-reviewer state, self-approval restrictions, runner isolation and provider secret state remain NOT ESTABLISHED; absence of connector access is not proof those settings are absent.

Named human dependencies are not yet established: the repository owner/admin must designate a repository ruleset/CODEOWNERS owner, production security owner, update-signing key custodians, HSM/KMS operator, Windows signing operator, publisher operator and Windows privileged-VM infrastructure owner. Do not infer these people from repository ownership or runner labels.


### C314 workflow publication boundary

The production-release workflow file is present on the unmerged PR #205 branch, but a live recursive tree read of the current main branch did not contain .github/workflows/production-release-build.yml. PR #205 remains open and draft. Therefore the production workflow design is not yet part of main, and no tag-triggered production release workflow has been demonstrated from main. This repository/branch state is separate from the missing provider credentials and protected environments; all are independent release gates. Do not infer production release readiness from the workflow existing only in an unmerged branch.


## C315 — isolated update-signing pipeline and versioned keyset verifier

### Three-workload release graph

The production workflow now defines three separate stable-update jobs and no longer invokes the legacy combined signer/publisher script:

1. `sign-stable-update` runs on the `wedecent-update-signer` runner label and `wedecent-production-update-signing` environment. It receives `WEDECENT_UPDATE_MANIFEST_SIGNER`, the public verification key path, and approved release/replay/audit configuration. It creates the canonical manifest, signs it, verifies the signer output locally, and uploads only the manifest/signature candidate. It has no publisher variable or publisher adapter invocation. This is the only stable-update job granted GitHub `id-token: write` permission so an external signer can authenticate a narrowly scoped OIDC workload identity. The signer service must still validate exact repository, workflow, ref, environment and audience claims; the permission alone does not establish signer-side trust.
2. `verify-stable-update` runs on the `wedecent-update-verifier` runner label and `wedecent-production-update-verification` environment. It receives only the public key path. It verifies canonical bytes and Ed25519 signature, verifies the existing stable pair, enforces monotonic version/sequence, and writes a receipt binding manifest SHA-256, signature SHA-256, public-key SHA-256 and the exact expected prior pair digests. It receives neither signer nor publisher credentials.
3. `publish-stable-update` runs on the `wedecent-release-publisher` runner label and the existing publication environment. It receives the publisher adapter and public key path, but no signer adapter. It verifies receipt digests, independently re-verifies the candidate and current prior pair, rechecks the live release tag, invokes the CAS publisher, and reads back and verifies the exact manifest/signature bytes.

Each artifact name includes the immutable source commit and workflow run ID. The verified artifact carries the verifier receipt into the publisher job. The publisher rechecks the current pair against the verifier's expected digests before invoking the external CAS adapter, so a concurrent writer causes a fail-closed conflict rather than a stale overwrite.

New scripts:
- `scripts/sign-windows-stable-update.sh`
- `scripts/verify-windows-stable-update.sh`
- `scripts/publish-windows-stable-update-pair.sh`
- `scripts/test-production-signing-isolation.py`

The signer and publisher adapters must now each have an independently configured lowercase SHA-256 pin (`WEDECENT_UPDATE_MANIFEST_SIGNER_SHA256` and `WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER_SHA256`). Their scripts reject a digest mismatch and reject group/world-writable adapter files. The signer job alone receives GitHub `id-token: write`; verification and publication jobs do not receive that permission. Signer-side OIDC claim enforcement and provider-side adapter immutability remain external configuration requirements.

The production workflow calls each script through Bash (new repository scripts are created as non-executable text files through the repository contents API). The old `publish-windows-stable-update.sh` combined entrypoint remains for deterministic regression fixtures, but now explicitly rejects execution when `GITHUB_WORKFLOW=Production release`. The production workflow static regression rejects any call to that legacy entrypoint.

### Negative privilege-boundary regression

The new Python regression checks:
- signer job receives signer adapter and does not receive publisher adapter;
- verifier job receives neither privileged adapter;
- publisher job receives publisher adapter and does not receive signer adapter;
- each job uses its own runner label and required dependency edge;
- signing/verifier/publisher scripts reference only their respective adapter variables;
- signed candidate and verifier-approved artifacts are separate handoff stages;
- the legacy combined script is absent from the production workflow and refuses the production workflow context.

The regression is wired into the Linux CI job immediately after actionlint. This proves the repository's workflow/configuration boundary, not actual infrastructure isolation. The three runner labels must be backed by three separate, appropriately restricted runner groups/hosts; a label alone does not prove host or credential isolation. GitHub environment reviewer settings, runner-group membership, runner ephemerality and network egress restrictions remain provider-side NOT ESTABLISHED.

### Versioned Ed25519 keyset verification API

The updateinfo package now contains a strict versioned keyset and manifest-v2 verification path:
- Keyset schema v1: canonical JSON with root key ID, monotonically increasing epoch, issue/expiry timestamps and a bounded, sorted list of Ed25519 manifest keys.
- Key entries have unique key IDs and unique public-key material, canonical public-key encoding, validity windows and explicit active, verify-only or revoked status.
- Keysets are authenticated by the separately pinned Ed25519 root key. Unknown root IDs, invalid signatures, noncanonical bytes, unknown fields, duplicate/unsorted keys, invalid timestamps, expired keysets and oversized input fail closed.
- `VerifyKeyset` returns an opaque `VerifiedKeyset`. The caller supplies its persisted highest epoch and digest. Lower epochs and same-epoch different-digest equivocation are rejected; the exact already-accepted epoch/digest is idempotently accepted.
- Manifest schema v2 adds `signing_key_id` and `keyset_epoch`. `VerifyManifestV2` requires a currently valid verified keyset, exact epoch match, an active authorized key, Ed25519 signature over the complete canonical manifest, and existing monotonic version/sequence checks.
- Verify-only keys are not accepted for new stable discovery. Revoked keys are rejected explicitly. The legacy v1 `Verify` path refuses schema-v2 manifests, preventing a caller from bypassing root-authorized keyset validation with a single-key verifier.

New tests cover root signature/canonicality, keyset expiry, root ID mismatch, keyset rollback, same-epoch equivocation, duplicate/unsorted key IDs, active/verify-only/revoked/unknown manifest keys, v1 verifier rejection of v2, and manifest sequence/version rollback.

### Integration and release limitations

This is a verification library/API and CI-tested implementation advance, not a production trust activation. The current `DiscoveryClient` still uses the legacy single pinned key and v1 manifest. It does not yet fetch/cache keyset metadata, persist epoch/digest/sequence in integrity-protected state, or invoke `VerifyManifestV2`. The CLI and stable publication script remain v1. Do not publish a v2 manifest until client discovery/state integration and migration compatibility tests are complete.

No production root key, manifest signing key, keyset, signer, public-key pin or provider credential was generated or provisioned by C315. The offline root ceremony, production keyset publication, root rotation and root compromise recovery remain operational design gates. The v2 API implements manifest-key rotation/status and revocation policy, but does not implement root-key rotation.

### Atomic publication evidence boundary

The publisher-only script preserves the existing external atomic pair publisher contract: expected prior manifest/signature SHA-256 values are passed to one adapter invocation, which must perform a single logical CAS/generation-pointer commit and return nonzero without modifying either object on conflict. The script rechecks both prior digests before the call and performs exact byte read-back plus signature verification afterward.

The repository regression fixture models immutable generation directories and an atomic current-pointer replacement, and tests CAS conflict/failure preservation. This is a local test fixture, not proof that the configured production Cloudflare R2 adapter performs a real conditional transaction or atomic generation-pointer switch. No production adapter or live object-store CAS test has been established.

### C315 evidence and remaining gates

- Current source branch at C315 work start was PR #205 HEAD `59b46bb4c4a42f0687ce6896db1e96e62347a1a5`; C315 changes are being committed on the existing PR #205 head branch, preserving its ancestry and base.
- CI at that starting HEAD passed 9/9 in run `45815569577`.
- Desktop run `45815569775` had Linux passed and Windows/macOS still in progress at the initial C315 reconciliation. Fresh runs must be checked for the final C315 head.
- New static privilege regression is part of CI; actionlint validates the production workflow syntax.
- The repository integration can create/update source files and inspect Actions runs, but cannot administer environment reviewers, runner groups, repository rulesets, external signer services or R2 policy.

Human dependencies still require named owners: repository governance administrator, security owner/root custodians, HSM/KMS operator, signing runner administrator, verification runner administrator, publisher/R2 operator, and Windows infrastructure owner for Issue #204. No accountable individuals are established in the repository evidence currently available.
