#!/usr/bin/env bash
set -euo pipefail

WEDECENT_TEST_TAG_ROOT=''
WEDECENT_TEST_TAG_REMOTE=''
WEDECENT_TEST_TAGS=()

wedecent_test_release_tags_init() {
  WEDECENT_TEST_TAG_ROOT="$1"
  WEDECENT_TEST_TAG_REMOTE="$2/release-tags.git"
  WEDECENT_TEST_TAGS=()
  git init --bare -q "$WEDECENT_TEST_TAG_REMOTE"
  export GIT_CONFIG_COUNT=1
  export GIT_CONFIG_KEY_0='remote.origin.url'
  export GIT_CONFIG_VALUE_0="$WEDECENT_TEST_TAG_REMOTE"
}

wedecent_test_release_tag_add() {
  local tag="$1"
  local source_sha="${2:-${GITHUB_SHA:-}}"
  local ref="refs/tags/$tag"
  [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)([.-][0-9A-Za-z.-]+)?$ ]] || {
    printf 'release-tag-fixture: invalid tag name: %s\n' "$tag" >&2
    return 1
  }
  [[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || {
    printf 'release-tag-fixture: invalid source commit: %s\n' "$source_sha" >&2
    return 1
  }
  if git -C "$WEDECENT_TEST_TAG_ROOT" show-ref --verify --quiet "$ref"; then
    local existing
    existing="$(git -C "$WEDECENT_TEST_TAG_ROOT" rev-parse --verify "$ref^{commit}")" || return 1
    [[ "$existing" == "$source_sha" ]] || {
      printf 'release-tag-fixture: existing tag points to a different commit: %s\n' "$tag" >&2
      return 1
    }
  else
    git -C "$WEDECENT_TEST_TAG_ROOT" tag -a "$tag" -m 'WeDecent test release tag' "$source_sha"
    WEDECENT_TEST_TAGS+=("$tag")
  fi
  git -C "$WEDECENT_TEST_TAG_ROOT" push -q --force "$WEDECENT_TEST_TAG_REMOTE" "$ref:$ref"
}

wedecent_test_release_tags_cleanup() {
  local tag
  for tag in "${WEDECENT_TEST_TAGS[@]}"; do
    git -C "$WEDECENT_TEST_TAG_ROOT" update-ref -d "refs/tags/$tag" >/dev/null 2>&1 || true
  done
  unset GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0
}
