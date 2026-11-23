# Production release trust and provenance

Production release builders fail closed unless an independently approved replay-authority configuration is supplied. No production hostname, SPKI pin, approval digest, signing identity, or credential is committed to this repository.

## Human-approved configuration

Provision a protected GitHub Actions environment named wedecent-production-release before attempting a production build:

- Restrict deployment branches/tags to the protected v* release-tag pattern.
- Require at least one independent reviewer to approve access to the environment.
- Set WEDECENT_PRODUCTION_RELEASE_APPROVED to the exact value true in that protected environment.
- Store the following environment variables in that protected environment:
  - WEDECENT_REPLAY_AUTHORITY_HOSTNAME
  - WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256
  - WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256

The hostname must be a canonical lowercase DNS name. SPKI pins must be one to four unique lowercase SHA-256 hex digests separated by commas. The approval digest is independently computed and approved by the trust-anchor owner over these exact UTF-8 bytes, including the final newline:

    wedecent-replay-authority-approval-v1
    hostname=HOSTNAME
    spki_sha256=PIN1[,PIN2...]

The digest is SHA-256 of that byte sequence. The build scripts recompute it and reject missing, partial, malformed, duplicate, or unapproved values. Do not set these variables until the replay-authority operator has supplied and approved the real production hostname and SPKI pins. Test values are permitted only in regression fixtures.

The protected environment is the approval boundary; the build workflow references that environment for every platform job, and the explicit approval marker must be true. The digest binds the exact hostname/pin tuple and detects accidental or unauthorized substitution. The workflow is .github/workflows/production-release-build.yml and uploads immutable, exact-SHA build artifacts only; it does not sign or publish them. Environment reviewers and administrators must be independent from the code author where organizational policy requires separation of duties.

## Build modes and provenance

All three release builders default to production:

- scripts/build-windows-release.sh
- scripts/build-linux-release.sh
- scripts/build-macos-release.sh

Production mode requires the protected environment approval marker, GitHub Actions context for ADRN-9/wedecent, the exact checked-out GITHUB_SHA, the matching vVERSION tag, a clean source tree, the canonical repository origin, and a commit-derived SOURCE_DATE_EPOCH. Caller-supplied commit overrides and dirty-tree overrides are rejected. The checked-out commit and Git tree are recorded in VERSION.txt.

For local development and ordinary CI, explicitly use WEDECENT_BUILD_MODE=diagnostic. Diagnostic artifacts carry build_mode=diagnostic, embed no replay-authority anchors, and are rejected by signing, installer-preparation, and publication boundaries. A diagnostic build is not a production release.

The Linux builder supports amd64 and arm64. The macOS builder supports amd64 and arm64. The Windows builder currently targets amd64. All builders use -trimpath, -buildvcs=false, an empty Go build ID, commit-derived timestamps, and deterministic SHA-256 manifests.

## Endpoint binary inspection

wd-core and wd-agent both import the same internal/buildinfo trust-anchor variables. The builders inject the same approved hostname and SPKI pin set into both binaries, then independently inspect each binary's bytes. Native Linux/macOS builds also invoke each binary's release-trust command and compare the exact runtime output. Windows cross-builds use the byte-level verifier because a Windows executable cannot be run on the Linux release runner.

For an installed binary, run:

    wd-core release-trust
    wd-agent release-trust

This command reports public trust configuration only; it does not expose private keys or credentials.

## Signing and publication

Before signing, installer preparation, or public publication, the scripts require:

- WEDECENT_EXPECTED_SOURCE_SHA (or the trusted workflow's GITHUB_SHA);
- the approved hostname, SPKI pins, and approval digest;
- VERSION.txt with build_mode=production;
- an exact source commit matching the independently supplied expected SHA;
- valid source-tree provenance metadata;
- both wd-core and wd-agent containing the approved anchors.

The expected source SHA must come from the protected release workflow's immutable GitHub context, not from artifact metadata supplied by an untrusted caller. Do not accept a SHA copied from an untrusted archive as independent provenance.

This work does not provision production trust anchors, a Windows Authenticode signing identity, a Linux/macOS signing identity, or public-storage credentials. Those are human/provider dependencies. No signing, publication, merge, or deployment is performed by the repository build jobs.
