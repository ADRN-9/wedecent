#!/usr/bin/env bash
set -euo pipefail

WEDECENT_TEST_TAG_ROOT=''
WEDECENT_TEST_TAG_REMOTE=''
WEDECENT_TEST_TAG_ORIGINAL_REMOTE=''
WEDECENT_TEST_TAG_ORIGIN_EXISTED=0
WEDECENT_TEST_TAGS=()

wedecent_test_release_tags_init() {
  WEDECENT_TEST_TAG_ROOT="$1"
  WEDECENT_TEST_TAG_REMOTE="$2/release-tags.git"
  WEDECENT_TEST_TAGS=()
  WEDECENT_TEST_TAG_ORIGINAL_REMOTE="$(git -C "$WEDECENT_TEST_TAG_ROOT" remote get-url origin 2>/dev/null || true)"
  if [[ -n "$WEDECENT_TEST_TAG_ORIGINAL_REMOTE" ]]; then
    WEDECENT_TEST_TAG_ORIGIN_EXISTED=1
  else
    WEDECENT_TEST_TAG_ORIGIN_EXISTED=0
  fi
  git init --bare -q "$WEDECENT_TEST_TAG_REMOTE"
  git --git-dir="$WEDECENT_TEST_TAG_REMOTE" config receive.shallowUpdate true
  if ((WEDECENT_TEST_TAG_ORIGIN_EXISTED == 1)); then
    git -C "$WEDECENT_TEST_TAG_ROOT" remote set-url origin "$WEDECENT_TEST_TAG_REMOTE"
  else
    git -C "$WEDECENT_TEST_TAG_ROOT" remote add origin "$WEDECENT_TEST_TAG_REMOTE"
  fi
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
    git -C "$WEDECENT_TEST_TAG_ROOT" \
      -c user.name='WeDecent test tag fixture' \
      -c user.email='release-tags@example.invalid' \
      tag -a "$tag" -m 'WeDecent test release tag' "$source_sha"
    WEDECENT_TEST_TAGS+=("$tag")
  fi
  git -C "$WEDECENT_TEST_TAG_ROOT" push -q --force "$WEDECENT_TEST_TAG_REMOTE" "$ref:$ref"
}

wedecent_test_release_tags_cleanup() {
  local tag
  for tag in "${WEDECENT_TEST_TAGS[@]}"; do
    git -C "$WEDECENT_TEST_TAG_ROOT" update-ref -d "refs/tags/$tag" >/dev/null 2>&1 || true
  done
  if ((WEDECENT_TEST_TAG_ORIGIN_EXISTED == 1)); then
    git -C "$WEDECENT_TEST_TAG_ROOT" remote set-url origin "$WEDECENT_TEST_TAG_ORIGINAL_REMOTE"
  else
    git -C "$WEDECENT_TEST_TAG_ROOT" remote remove origin >/dev/null 2>&1 || true
  fi
}
