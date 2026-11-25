#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'test-release-tags: %s\n' "$*" >&2
  exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERIFY="$ROOT/scripts/verify-live-release-tag.sh"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
REPO="$WORK/repo"
REMOTE="$WORK/remote.git"
BIN="$WORK/bin"
mkdir -p "$BIN"
git init -q "$REPO"
git -C "$REPO" config user.name 'WeDecent release tag tests'
git -C "$REPO" config user.email 'release-tags@example.invalid'
git init --bare -q "$REMOTE"
git -C "$REPO" remote add origin "$REMOTE"

printf 'source one\n' > "$REPO/source.txt"
git -C "$REPO" add source.txt
git -C "$REPO" commit -qm 'source one'
FIRST="$(git -C "$REPO" rev-parse HEAD)"

printf 'source two\n' > "$REPO/source.txt"
git -C "$REPO" add source.txt
git -C "$REPO" commit -qm 'source two'
SECOND="$(git -C "$REPO" rev-parse HEAD)"

git -C "$REPO" tag -a v1.2.3 -m 'annotated release' "$FIRST"
git -C "$REPO" push -q origin refs/tags/v1.2.3
"$VERIFY" "$REPO" v1.2.3 "$FIRST" "$REMOTE" >/dev/null ||
  fail 'valid annotated tag was rejected'

git -C "$REPO" tag v1.2.4 "$FIRST"
git -C "$REPO" push -q origin refs/tags/v1.2.4
"$VERIFY" "$REPO" v1.2.4 "$FIRST" "$REMOTE" >/dev/null ||
  fail 'valid lightweight tag was rejected'

# Simulate an annotated tag being retargeted after build completion.
OLD_ANNOTATED="$(git -C "$REPO" rev-parse refs/tags/v1.2.3)"
git -C "$REPO" tag -fa v1.2.3 -m 'moved after build' "$SECOND" >/dev/null
git -C "$REPO" push -q --force origin refs/tags/v1.2.3
git -C "$REPO" update-ref refs/tags/v1.2.3 "$OLD_ANNOTATED"
if "$VERIFY" "$REPO" v1.2.3 "$FIRST" "$REMOTE" >/dev/null 2>&1; then
  fail 'annotated tag movement between build and publication was accepted'
fi

git --git-dir="$REMOTE" update-ref refs/tags/v1.2.4 "$SECOND"
if "$VERIFY" "$REPO" v1.2.4 "$FIRST" "$REMOTE" >/dev/null 2>&1; then
  fail 'lightweight tag movement between build and publication was accepted'
fi

git --git-dir="$REMOTE" update-ref -d refs/tags/v1.2.4
if "$VERIFY" "$REPO" v1.2.4 "$FIRST" "$REMOTE" >/dev/null 2>&1; then
  fail 'missing live release tag was accepted'
fi

git -C "$REPO" tag -a v1.2.6 -m 'original tag name' "$FIRST"
git -C "$REPO" push -q origin refs/tags/v1.2.6
ORIGINAL_TAG_OBJECT="$(git -C "$REPO" rev-parse refs/tags/v1.2.6)"
git -C "$REPO" update-ref refs/tags/v1.2.7 "$ORIGINAL_TAG_OBJECT"
git --git-dir="$REMOTE" update-ref refs/tags/v1.2.7 "$ORIGINAL_TAG_OBJECT"
if "$VERIFY" "$REPO" v1.2.7 "$FIRST" "$REMOTE" >/dev/null 2>&1; then
  fail 'annotated tag object reused under a different tag name was accepted'
fi

REAL_GIT="$(command -v git)"
cat > "$BIN/git" <<EOF_GIT
#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == '-C' && "\${3:-}" == 'ls-remote' && "\${5:-}" == '$REMOTE' && "\${6:-}" == 'refs/tags/v1.2.6' ]]; then
  sha="\$("$REAL_GIT" -C "$REPO" rev-parse --verify refs/tags/v1.2.6)"
  printf '%s\\t%s\\n%s\\t%s\\n' "\$sha" 'refs/tags/v1.2.6' "\$sha" 'refs/tags/v1.2.6'
  exit 0
fi
exec "$REAL_GIT" "\$@"
EOF_GIT
chmod 0700 "$BIN/git"
if PATH="$BIN:$PATH" "$VERIFY" "$REPO" v1.2.6 "$FIRST" "$REMOTE" >/dev/null 2>&1; then
  fail 'ambiguous live release tag response was accepted'
fi

printf 'Live annotated/lightweight release tag checks and movement regressions passed.\n'
