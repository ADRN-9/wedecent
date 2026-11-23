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

## Endpoint binary inspection

`wd-core` and `wd-agent` both import the same `internal/buildinfo` trust-anchor variables. The builders inject the same approved hostname and SPKI pin set into both binaries, then independently inspect each binary's bytes. Native Linux/macOS builds invoke each binary's `release-trust` command and compare the exact runtime output. The production Windows build runs on a native Windows runner and executes both release-trust commands. Ordinary PR CI cross-builds diagnostic Windows binaries on Linux and uses the byte-level verifier only.

For an installed binary, run:

    wd-core release-trust
    wd-agent release-trust

This command reports public trust configuration only; it does not expose private keys or credentials.

## Production release workflow

`.github/workflows/production-release-build.yml` is tag-triggered and is designed to run these gates in order:

1. Build Windows, Linux, and macOS production artifacts from the exact tag commit.
2. Build the Windows installer package from the same unsigned Windows release.
3. Create per-artifact provenance sidecars and GitHub OIDC/Sigstore attestations.
4. Download and verify every platform artifact, attestation identity, source commit/tree, and file digest.
5. Run the Windows Authenticode finalizer on the protected `wedecent-signing` self-hosted Windows runner. It rejects forged source-tree metadata before invoking the signer, verifies signatures, and atomically stages the signed release and installer.
6. Attest the final signed Windows release and installer bytes.
7. Publish immutable Windows archives through a create-only uploader. Existing objects are accepted only when their bytes are identical; ambiguous remote states and concurrent create-only conflicts fail closed.
8. Only after immutable downloads are verified and published, prepare, sign, verify, and publish the stable update manifest/signature pair with monotonic sequence enforcement and an atomic compare-and-swap publisher.

The signing job expects these environment variables to point to preinstalled, absolute, non-symlink adapters on the protected runner:

- `WEDECENT_WINDOWS_AUTHENTICODE_SIGNER`
- `WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER`

The signing runner must be isolated from untrusted workloads, run a supported GitHub Actions runner, provide Git Bash, Python, GitHub CLI, and the required file/hash utilities, and access a hardware-backed/non-exportable Authenticode signing key through the signer adapter. The workflow performs an early preflight before invoking repository scripts or the signer and rejects missing approval markers, trust-anchor values, or signer/verifier adapters. The signing key itself must not be stored in the repository, workflow variables, or release artifacts.

The publication runner uses the `self-hosted, linux, wedecent-release-publisher` labels and must provide Bash, Python 3, GitHub CLI, Go 1.27, curl, SHA-256 utilities, and a platform-compatible Authenticode verifier. Publication and stable-update jobs perform early preflights that reject missing environment markers, trust anchors, adapter executables, public keys, sequence values, or timestamps before invoking release scripts. It requires these environment-scoped adapter paths:

- `WEDECENT_WINDOWS_AUTHENTICODE_VERIFIER`
- `WEDECENT_R2_CREATE_ONLY_UPLOADER`
- `WEDECENT_UPDATE_MANIFEST_SIGNER`
- `WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER`
- `WEDECENT_UPDATE_PUBLIC_KEY_PATH`

The immutable-object uploader must perform atomic create-only writes. The stable-pair publisher must compare both current object digests and atomically replace the manifest/signature pair or leave both objects unchanged. The stable update private key must remain in an HSM/KMS or equivalent protected signer; only the public key is supplied to the verifier. The stable sequence is the workflow run number and the timestamp is the workflow run start time.

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
