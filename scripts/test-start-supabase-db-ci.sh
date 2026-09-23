#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'test-start-supabase-db-ci: %s\n' "$*" >&2
  exit 1
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$ROOT/scripts/start-supabase-db-ci.sh"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
BIN="$WORK/bin"
mkdir -p -- "$BIN"
COUNTER="$WORK/counter"
MODE="$WORK/mode"
printf '0\n' > "$COUNTER"

cat > "$BIN/supabase" <<'EOF_SUPABASE'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'db start' ]] || exit 64
if [[ -n "${SUPABASE_INTERNAL_IMAGE_REGISTRY+x}" ]]; then
  printf 'registry override leaked into supabase invocation\n' >&2
  exit 67
fi
count="$(cat "$WEDECENT_FAKE_COUNTER")"
count=$((count + 1))
printf '%d\n' "$count" > "$WEDECENT_FAKE_COUNTER"
mode="$(cat "$WEDECENT_FAKE_MODE")"
case "$mode" in
  transient)
    if ((count < 3)); then
      printf 'toomanyrequests: ghcr.io/supabase/postgres\n' >&2
      exit 23
    fi
    printf 'Started supabase.\n'
    ;;
  nonregistry)
    printf 'invalid project configuration\n' >&2
    exit 31
    ;;
  permanent)
    printf '429 Too Many Requests while pulling image\n' >&2
    exit 41
    ;;
  *)
    exit 65
    ;;
esac
EOF_SUPABASE
chmod 0700 "$BIN/supabase"

run_target() {
  PATH="$BIN:$PATH" \
  SUPABASE_INTERNAL_IMAGE_REGISTRY=ghcr.io \
  WEDECENT_FAKE_COUNTER="$COUNTER" \
  WEDECENT_FAKE_MODE="$MODE" \
  WEDECENT_SUPABASE_START_ATTEMPTS=3 \
  WEDECENT_SUPABASE_RETRY_BASE_SECONDS=0 \
    "$TARGET"
}

printf 'transient\n' > "$MODE"
printf '0\n' > "$COUNTER"
run_target >/dev/null
[[ "$(cat "$COUNTER")" == '3' ]] || fail 'transient registry throttle did not retry to success'

printf 'nonregistry\n' > "$MODE"
printf '0\n' > "$COUNTER"
if run_target >/dev/null 2>&1; then
  fail 'non-registry startup failure unexpectedly succeeded'
fi
[[ "$(cat "$COUNTER")" == '1' ]] || fail 'non-registry failure was retried'

printf 'permanent\n' > "$MODE"
printf '0\n' > "$COUNTER"
if run_target >/dev/null 2>&1; then
  fail 'permanent registry throttle unexpectedly succeeded'
fi
[[ "$(cat "$COUNTER")" == '3' ]] || fail 'registry throttle did not stop at configured attempt limit'

if PATH="$BIN:$PATH" SUPABASE_INTERNAL_IMAGE_REGISTRY=ghcr.io \
   WEDECENT_FAKE_COUNTER="$COUNTER" WEDECENT_FAKE_MODE="$MODE" \
   WEDECENT_SUPABASE_START_ATTEMPTS=0 WEDECENT_SUPABASE_RETRY_BASE_SECONDS=0 \
   "$TARGET" >/dev/null 2>&1; then
  fail 'invalid attempt count unexpectedly succeeded'
fi

printf 'Supabase registry retry and fallback policy verified.\n'
