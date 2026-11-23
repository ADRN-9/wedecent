#!/usr/bin/env bash

WEDECENT_RELEASE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"

wedecent_release_fail() {
  printf 'release-trust: %s\n' "$*" >&2
  return 1
}

wedecent_sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    return 1
  fi
}

wedecent_replay_authority_approval_digest() {
  local hostname="$1"
  local pins="$2"
  printf 'wedecent-replay-authority-approval-v1\nhostname=%s\nspki_sha256=%s\n' \
    "$hostname" "$pins" | wedecent_sha256_stdin
}

wedecent_require_approved_replay_trust() {
  local hostname="${WEDECENT_REPLAY_AUTHORITY_HOSTNAME:-}"
  local pins="${WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256:-}"
  local approval="${WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256:-}"
  local actual pin seen=""

  [[ -n "$hostname" && -n "$pins" && -n "$approval" ]] ||
    wedecent_release_fail "production replay-authority hostname, SPKI pins and approval digest are all required" || return 1
  [[ "$hostname" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]] ||
    wedecent_release_fail "replay-authority hostname must be a canonical lowercase DNS hostname" || return 1
  [[ ! "$hostname" =~ ^[0-9.]+$ ]] ||
    wedecent_release_fail "replay-authority must be a DNS hostname, not an IP address" || return 1
  [[ "$pins" =~ ^[0-9a-f]{64}(,[0-9a-f]{64}){0,3}$ ]] ||
    wedecent_release_fail "SPKI pins must be one to four unique lowercase SHA-256 hex digests" || return 1
  [[ "$approval" =~ ^[0-9a-f]{64}$ ]] ||
    wedecent_release_fail "replay-authority approval digest must be 64 lowercase hex characters" || return 1

  local -a pin_array=()
  IFS=',' read -r -a pin_array <<< "$pins"
  for pin in "${pin_array[@]}"; do
    case ",$seen," in
      *",$pin,"*) wedecent_release_fail "duplicate replay-authority SPKI pin" || return 1 ;;
    esac
    seen="${seen:+$seen,}$pin"
  done

  actual="$(wedecent_replay_authority_approval_digest "$hostname" "$pins")" ||
    wedecent_release_fail "cannot calculate replay-authority approval digest" || return 1
  [[ "$actual" == "$approval" ]] ||
    wedecent_release_fail "replay-authority configuration does not match its independently approved digest" || return 1

  REPLAY_AUTHORITY_HOSTNAME="$hostname"
  REPLAY_AUTHORITY_SPKI_SHA256="$pins"
  REPLAY_AUTHORITY_APPROVAL_SHA256="$approval"
}

wedecent_require_production_provenance() {
  local root="$1"
  local version="$2"
  local head tree status origin tag_commit commit_epoch

  [[ "${GITHUB_ACTIONS:-}" == "true" ]] ||
    wedecent_release_fail "production builds must run in GitHub Actions" || return 1
  [[ "${WEDECENT_PRODUCTION_RELEASE_APPROVED:-}" == "true" ]] ||
    wedecent_release_fail "protected production-release environment approval marker is missing" || return 1
  [[ "${GITHUB_REPOSITORY:-}" == "ADRN-9/wedecent" ]] ||
    wedecent_release_fail "production build repository context is not ADRN-9/wedecent" || return 1
  [[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] ||
    wedecent_release_fail "GitHub Actions must provide an exact 40-character GITHUB_SHA" || return 1
  [[ "${GITHUB_REF_TYPE:-}" == "tag" && "${GITHUB_REF_NAME:-}" == "v$version" ]] ||
    wedecent_release_fail "production builds must target the exact v$version tag" || return 1
  [[ -z "${WEDECENT_BUILD_COMMIT:-}" ]] ||
    wedecent_release_fail "WEDECENT_BUILD_COMMIT overrides are forbidden" || return 1
  [[ "${WEDECENT_ALLOW_DIRTY:-0}" == "0" ]] ||
    wedecent_release_fail "dirty-tree overrides are forbidden for production builds" || return 1

  head="$(git -C "$root" rev-parse --verify 'HEAD^{commit}')" ||
    wedecent_release_fail "cannot resolve checked-out source commit" || return 1
  tree="$(git -C "$root" rev-parse --verify 'HEAD^{tree}')" ||
    wedecent_release_fail "cannot resolve checked-out source tree" || return 1
  [[ "$head" == "$GITHUB_SHA" ]] ||
    wedecent_release_fail "checked-out HEAD does not match GitHub's immutable GITHUB_SHA" || return 1
  tag_commit="$(git -C "$root" rev-parse --verify "refs/tags/$GITHUB_REF_NAME^{commit}")" ||
    wedecent_release_fail "the production tag is not present in the checked-out repository" || return 1
  [[ "$tag_commit" == "$head" ]] ||
    wedecent_release_fail "production tag does not resolve to the checked-out source commit" || return 1

  status="$(git -C "$root" status --porcelain --untracked-files=all)" ||
    wedecent_release_fail "cannot inspect source-tree cleanliness" || return 1
  [[ -z "$status" ]] ||
    wedecent_release_fail "production source tree is dirty or contains untracked files" || return 1

  origin="$(git -C "$root" remote get-url origin 2>/dev/null || true)"
  case "$origin" in
    https://github.com/ADRN-9/wedecent|https://github.com/ADRN-9/wedecent.git|git@github.com:ADRN-9/wedecent|git@github.com:ADRN-9/wedecent.git) ;;
    *) wedecent_release_fail "Git origin is not the canonical WeDecent repository" || return 1 ;;
  esac

  commit_epoch="$(git -C "$root" show -s --format=%ct "$head")" ||
    wedecent_release_fail "cannot read source commit timestamp" || return 1
  [[ "$commit_epoch" =~ ^[0-9]+$ ]] ||
    wedecent_release_fail "source commit timestamp is malformed" || return 1
  if [[ -n "${SOURCE_DATE_EPOCH:-}" && "$SOURCE_DATE_EPOCH" != "$commit_epoch" ]]; then
    wedecent_release_fail "SOURCE_DATE_EPOCH must equal the checked-out commit timestamp" || return 1
  fi

  RELEASE_COMMIT="$head"
  RELEASE_SOURCE_COMMIT="$head"
  RELEASE_SOURCE_TREE="$tree"
  SOURCE_DATE_EPOCH="$commit_epoch"
}

wedecent_metadata_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" '
    $1 == key {
      count++
      value = substr($0, index($0, "=") + 1)
    }
    END {
      if (count != 1) exit 1
      print value
    }
  ' "$file"
}

wedecent_verify_binary_trust() {
  local binary="$1"
  local hostname="$2"
  local pins="$3"
  python3 "$WEDECENT_RELEASE_ROOT/scripts/verify-release-binary-trust.py" "$binary" "$hostname" "$pins"
}

wedecent_verify_release_metadata() {
  local directory="$1"
  local metadata expected version commit source_commit source_tree mode hostname pins approval platform core agent

  [[ -d "$directory" && ! -L "$directory" ]] ||
    wedecent_release_fail "release directory must be a regular non-symlink directory" || return 1
  metadata="$directory/VERSION.txt"
  [[ -f "$metadata" && ! -L "$metadata" ]] ||
    wedecent_release_fail "release VERSION.txt must be a regular non-symlink file" || return 1
  wedecent_require_approved_replay_trust || return 1

  expected="${WEDECENT_EXPECTED_SOURCE_SHA:-${GITHUB_SHA:-}}"
  [[ "$expected" =~ ^[0-9a-f]{40}$ ]] ||
    wedecent_release_fail "WEDECENT_EXPECTED_SOURCE_SHA or GITHUB_SHA must identify the expected source commit" || return 1

  version="$(wedecent_metadata_value "$metadata" version)" || return 1
  commit="$(wedecent_metadata_value "$metadata" commit)" || return 1
  source_commit="$(wedecent_metadata_value "$metadata" source_commit)" || return 1
  source_tree="$(wedecent_metadata_value "$metadata" source_tree)" || return 1
  mode="$(wedecent_metadata_value "$metadata" build_mode)" || return 1
  hostname="$(wedecent_metadata_value "$metadata" replay_authority_hostname)" || return 1
  pins="$(wedecent_metadata_value "$metadata" replay_authority_spki_sha256)" || return 1
  approval="$(wedecent_metadata_value "$metadata" replay_authority_approval_sha256)" || return 1
  platform="$(wedecent_metadata_value "$metadata" platform)" || return 1

  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] ||
    wedecent_release_fail "release version metadata is malformed" || return 1
  [[ "$mode" == "production" ]] ||
    wedecent_release_fail "diagnostic or unknown build modes cannot be signed or published" || return 1
  [[ "$commit" == "$expected" && "$source_commit" == "$expected" ]] ||
    wedecent_release_fail "release source commit does not match the independently expected source SHA" || return 1
  [[ "$source_tree" =~ ^[0-9a-f]{40}$ ]] ||
    wedecent_release_fail "release source tree provenance is malformed" || return 1
  [[ "$hostname" == "$REPLAY_AUTHORITY_HOSTNAME" &&
     "$pins" == "$REPLAY_AUTHORITY_SPKI_SHA256" &&
     "$approval" == "$REPLAY_AUTHORITY_APPROVAL_SHA256" ]] ||
    wedecent_release_fail "release metadata does not match the approved replay-authority configuration" || return 1

  case "$platform" in
    windows/amd64) core="$directory/wd-core.exe"; agent="$directory/wd-agent.exe" ;;
    linux/amd64|linux/arm64|darwin/amd64|darwin/arm64) core="$directory/wd-core"; agent="$directory/wd-agent" ;;
    *) wedecent_release_fail "unsupported production release platform metadata: $platform" || return 1 ;;
  esac
  [[ -f "$core" && ! -L "$core" && -f "$agent" && ! -L "$agent" ]] ||
    wedecent_release_fail "wd-core and wd-agent must be regular non-symlink release binaries" || return 1
  wedecent_verify_binary_trust "$core" "$hostname" "$pins" ||
    wedecent_release_fail "wd-core does not contain the approved replay-authority anchors" || return 1
  wedecent_verify_binary_trust "$agent" "$hostname" "$pins" ||
    wedecent_release_fail "wd-agent does not contain the approved replay-authority anchors" || return 1
}

wedecent_release_init() {
  local root="$1"
  local platform="$2"
  local arch="$3"
  local requested_out="$4"
  local mode status head commit_epoch raw_parent canonical_parent output_name

  ROOT="$(cd "$root" && pwd -P)"
  RELEASE_PLATFORM="$platform"
  RELEASE_ARCH="$arch"
  BUILD_MODE="${WEDECENT_BUILD_MODE:-production}"
  GO_BIN="${GO:-go}"
  VERSION_FILE="$ROOT/VERSION"
  [[ -f "$VERSION_FILE" && ! -L "$VERSION_FILE" ]] ||
    wedecent_release_fail "VERSION file is missing or is a symlink" || return 1
  VERSION="$(tr -d '\r\n' < "$VERSION_FILE")"
  [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] ||
    wedecent_release_fail "VERSION is not release-like: $VERSION" || return 1

  [[ -z "${WEDECENT_BUILD_COMMIT:-}" ]] ||
    wedecent_release_fail "WEDECENT_BUILD_COMMIT overrides are forbidden" || return 1
  head="$(git -C "$ROOT" rev-parse --verify 'HEAD^{commit}')" ||
    wedecent_release_fail "cannot resolve checked-out source commit" || return 1
  status="$(git -C "$ROOT" status --porcelain --untracked-files=all)" ||
    wedecent_release_fail "cannot inspect source-tree cleanliness" || return 1
  RELEASE_SOURCE_COMMIT="$head"
  RELEASE_SOURCE_TREE="$(git -C "$ROOT" rev-parse --verify 'HEAD^{tree}')" ||
    wedecent_release_fail "cannot resolve checked-out source tree" || return 1
  TRUST_HOSTNAME=""
  TRUST_PINS=""
  TRUST_APPROVAL=""

  case "$BUILD_MODE" in
    production)
      [[ -z "$status" ]] ||
        wedecent_release_fail "production source tree is dirty or contains untracked files" || return 1
      wedecent_require_approved_replay_trust || return 1
      wedecent_require_production_provenance "$ROOT" "$VERSION" || return 1
      TRUST_HOSTNAME="$REPLAY_AUTHORITY_HOSTNAME"
      TRUST_PINS="$REPLAY_AUTHORITY_SPKI_SHA256"
      TRUST_APPROVAL="$REPLAY_AUTHORITY_APPROVAL_SHA256"
      ;;
    diagnostic)
      [[ "${WEDECENT_ALLOW_DIRTY:-0}" == "0" || "${WEDECENT_ALLOW_DIRTY:-0}" == "1" ]] ||
        wedecent_release_fail "WEDECENT_ALLOW_DIRTY must be 0 or 1" || return 1
      if [[ -n "$status" ]]; then
        [[ "${WEDECENT_ALLOW_DIRTY:-0}" == "1" ]] ||
          wedecent_release_fail "working tree is dirty; set WEDECENT_ALLOW_DIRTY=1 for an explicit diagnostic build" || return 1
        RELEASE_COMMIT="${head}-dirty"
      else
        RELEASE_COMMIT="$head"
      fi
      [[ -z "${WEDECENT_REPLAY_AUTHORITY_HOSTNAME:-}${WEDECENT_REPLAY_AUTHORITY_SPKI_SHA256:-}${WEDECENT_REPLAY_AUTHORITY_APPROVAL_SHA256:-}" ]] ||
        wedecent_release_fail "diagnostic builds must not accept production replay-authority configuration" || return 1
      ;;
    *)
      wedecent_release_fail "WEDECENT_BUILD_MODE must be production or diagnostic" || return 1
      ;;
  esac

  if [[ "$BUILD_MODE" == "diagnostic" ]]; then
    commit_epoch="$(git -C "$ROOT" show -s --format=%ct "$head")" ||
      wedecent_release_fail "cannot read source commit timestamp" || return 1
    if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
      SOURCE_DATE_EPOCH="$commit_epoch"
    fi
  fi
  [[ "${SOURCE_DATE_EPOCH:-}" =~ ^[0-9]+$ ]] ||
    wedecent_release_fail "SOURCE_DATE_EPOCH must be an integer Unix timestamp" || return 1

  if date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ' >/dev/null 2>&1; then
    BUILT_AT="$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"
  else
    BUILT_AT="$(date -u -r "$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')" ||
      wedecent_release_fail "cannot format SOURCE_DATE_EPOCH" || return 1
  fi

  GO_VERSION="$("$GO_BIN" env GOVERSION)" ||
    wedecent_release_fail "cannot determine Go toolchain version" || return 1
  [[ -n "$GO_VERSION" ]] ||
    wedecent_release_fail "Go toolchain version is empty" || return 1

  if [[ -L "$ROOT/dist" ]]; then
    wedecent_release_fail "dist must not be a symlink" || return 1
  fi
  mkdir -p -- "$ROOT/dist"
  DIST_ROOT="$ROOT/dist"
  [[ "$(cd "$DIST_ROOT" && pwd -P)" == "$DIST_ROOT" ]] ||
    wedecent_release_fail "dist path is not canonical" || return 1

  if [[ "$requested_out" != /* ]]; then
    requested_out="$ROOT/$requested_out"
  fi
  raw_parent="$(dirname -- "$requested_out")"
  output_name="$(basename -- "$requested_out")"
  [[ -n "$output_name" && "$output_name" != "." && "$output_name" != ".." ]] ||
    wedecent_release_fail "unsafe release output path" || return 1
  [[ -d "$raw_parent" && ! -L "$raw_parent" ]] ||
    wedecent_release_fail "release output parent must already exist and must not be a symlink" || return 1
  case "$raw_parent" in
    *"/../"*|*/..|*"/./"*|*/.) wedecent_release_fail "release output path contains a non-canonical component" || return 1 ;;
  esac
  canonical_parent="$(cd "$raw_parent" && pwd -P)" ||
    wedecent_release_fail "cannot resolve release output parent" || return 1
  [[ "$canonical_parent" == "$raw_parent" ]] ||
    wedecent_release_fail "release output path contains a symlink component" || return 1
  case "$canonical_parent" in
    "$DIST_ROOT"|"$DIST_ROOT"/*) ;;
    *) wedecent_release_fail "release output must remain inside canonical $DIST_ROOT" || return 1 ;;
  esac
  OUT_DIR="$canonical_parent/$output_name"
  [[ ! -e "$OUT_DIR" && ! -L "$OUT_DIR" ]] ||
    wedecent_release_fail "release output already exists; refusing to overwrite: $OUT_DIR" || return 1

  WEDECENT_RELEASE_PARENT="$canonical_parent"
  WEDECENT_RELEASE_STAGE="$(mktemp -d "$canonical_parent/.wedecent-release.XXXXXX")" ||
    wedecent_release_fail "cannot create isolated release staging directory" || return 1
  [[ -d "$WEDECENT_RELEASE_STAGE" && ! -L "$WEDECENT_RELEASE_STAGE" ]] ||
    wedecent_release_fail "release staging directory is not a regular directory" || return 1
  trap 'wedecent_release_cleanup' EXIT

  RELEASE_LDFLAGS="-buildid= -X=wedecent.com/wedecent/internal/buildinfo.Version=$VERSION -X=wedecent.com/wedecent/internal/buildinfo.Commit=$RELEASE_COMMIT -X=wedecent.com/wedecent/internal/buildinfo.BuiltAt=$BUILT_AT -X=wedecent.com/wedecent/internal/buildinfo.ReplayAuthorityHostname=$TRUST_HOSTNAME -X=wedecent.com/wedecent/internal/buildinfo.ReplayAuthoritySPKISHA256=$TRUST_PINS"
}

wedecent_release_cleanup() {
  if [[ -n "${WEDECENT_RELEASE_STAGE:-}" ]]; then
    case "$WEDECENT_RELEASE_STAGE" in
      "$WEDECENT_RELEASE_PARENT"/.wedecent-release.*)
        [[ ! -L "$WEDECENT_RELEASE_STAGE" ]] && rm -rf -- "$WEDECENT_RELEASE_STAGE"
        ;;
      *)
        printf 'release-trust: refusing to clean an unrecognized staging path: %s\n' "$WEDECENT_RELEASE_STAGE" >&2
        ;;
    esac
  fi
}

wedecent_release_finish() {
  local name expected actual host_os host_arch
  cat > "$WEDECENT_RELEASE_STAGE/VERSION.txt" <<EOF_RELEASE
version=$VERSION
commit=$RELEASE_COMMIT
source_commit=$RELEASE_SOURCE_COMMIT
source_tree=$RELEASE_SOURCE_TREE
built_at=$BUILT_AT
go=$GO_VERSION
platform=$RELEASE_PLATFORM/$RELEASE_ARCH
build_mode=$BUILD_MODE
replay_authority_hostname=$TRUST_HOSTNAME
replay_authority_spki_sha256=$TRUST_PINS
replay_authority_approval_sha256=$TRUST_APPROVAL
EOF_RELEASE

  for name in "${RELEASE_BINARIES[@]}"; do
    [[ -f "$WEDECENT_RELEASE_STAGE/$name" && ! -L "$WEDECENT_RELEASE_STAGE/$name" ]] ||
      wedecent_release_fail "builder did not produce a regular binary: $name" || return 1
  done

  if [[ "$BUILD_MODE" == "production" ]]; then
    case "$RELEASE_PLATFORM" in
      windows)
        wedecent_verify_binary_trust "$WEDECENT_RELEASE_STAGE/wd-core.exe" "$TRUST_HOSTNAME" "$TRUST_PINS" || return 1
        wedecent_verify_binary_trust "$WEDECENT_RELEASE_STAGE/wd-agent.exe" "$TRUST_HOSTNAME" "$TRUST_PINS" || return 1
        ;;
      *)
        wedecent_verify_binary_trust "$WEDECENT_RELEASE_STAGE/wd-core" "$TRUST_HOSTNAME" "$TRUST_PINS" || return 1
        wedecent_verify_binary_trust "$WEDECENT_RELEASE_STAGE/wd-agent" "$TRUST_HOSTNAME" "$TRUST_PINS" || return 1
        ;;
    esac

    case "$(uname -s)" in
      Linux) host_os=linux ;;
      Darwin) host_os=darwin ;;
      MINGW*|MSYS*) host_os=windows ;;
      *) host_os=unknown ;;
    esac
    case "$(uname -m)" in
      x86_64|amd64) host_arch=amd64 ;;
      arm64|aarch64) host_arch=arm64 ;;
      *) host_arch=unknown ;;
    esac
    if [[ "$host_os" == "$RELEASE_PLATFORM" && "$host_arch" == "$RELEASE_ARCH" ]]; then
      expected="$(printf 'hostname=%s\nspki_sha256=%s\n' "$TRUST_HOSTNAME" "$TRUST_PINS")"
      case "$RELEASE_PLATFORM" in
        windows)
          actual="$("$WEDECENT_RELEASE_STAGE/wd-core.exe" release-trust)" || return 1
          [[ "$actual" == "$expected" ]] || wedecent_release_fail "wd-core runtime trust inspection mismatch" || return 1
          actual="$("$WEDECENT_RELEASE_STAGE/wd-agent.exe" release-trust)" || return 1
          ;;
        *)
          actual="$("$WEDECENT_RELEASE_STAGE/wd-core" release-trust)" || return 1
          [[ "$actual" == "$expected" ]] || wedecent_release_fail "wd-core runtime trust inspection mismatch" || return 1
          actual="$("$WEDECENT_RELEASE_STAGE/wd-agent" release-trust)" || return 1
          ;;
      esac
      [[ "$actual" == "$expected" ]] ||
        wedecent_release_fail "wd-agent runtime trust inspection mismatch" || return 1
    fi
  fi

  (
    cd "$WEDECENT_RELEASE_STAGE"
    for name in "${RELEASE_BINARIES[@]}"; do
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$name"
      else
        shasum -a 256 "$name"
      fi
    done | LC_ALL=C sort -k2 > SHA256SUMS.txt
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum -c SHA256SUMS.txt
    else
      shasum -a 256 -c SHA256SUMS.txt
    fi
  ) || wedecent_release_fail "release checksum verification failed" || return 1

  [[ ! -e "$OUT_DIR" && ! -L "$OUT_DIR" ]] ||
    wedecent_release_fail "release output appeared during build; refusing publication" || return 1
  mv -- "$WEDECENT_RELEASE_STAGE" "$OUT_DIR" ||
    wedecent_release_fail "atomic release staging publication failed" || return 1
  WEDECENT_RELEASE_STAGE=""
  trap - EXIT
  printf 'Built WeDecent %s %s/%s %s release bundle:\n  %s\n' \
    "$VERSION" "$RELEASE_PLATFORM" "$RELEASE_ARCH" "$BUILD_MODE" "$OUT_DIR"
}
