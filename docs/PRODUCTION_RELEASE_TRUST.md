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
