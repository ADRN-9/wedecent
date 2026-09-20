#!/usr/bin/env bash
set -u -o pipefail

EXPECTED_BRANCH="${WEDECENT_EXPECTED_BRANCH:-feature/v0.4-route-capability-client}"
MODE="${1:-fast}"

fail() {
  printf 'WEDECENT_ROUTE_CLIENT_TESTS_FAILED: %s\n' "$*" >&2
  exit 1
}

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
[[ -n "$repo_root" ]] || fail "not inside a git repository"
cd "$repo_root"

origin="$(git remote get-url origin 2>/dev/null || true)"
case "$origin" in
  *github.com/ADRN-9/wedecent.git|*github.com/ADRN-9/wedecent|git@github.com:ADRN-9/wedecent.git)
    ;;
  *)
    fail "wrong repository origin: ${origin:-<missing>}"
    ;;
esac

branch="$(git branch --show-current)"
[[ "$branch" == "$EXPECTED_BRANCH" ]] || fail "wrong branch: $branch (expected $EXPECTED_BRANCH)"

head="$(git rev-parse --short=12 HEAD)"
dirty="$(git status --porcelain --untracked-files=all | wc -l | tr -d ' ')"
printf 'WEDECENT_REPO=%s\n' "$repo_root"
printf 'WEDECENT_BRANCH=%s\n' "$branch"
printf 'WEDECENT_HEAD=%s\n' "$head"
printf 'WEDECENT_DIRTY_ENTRIES=%s\n' "$dirty"

focused_regex='Test(AutomaticRouteAuthorization|BuildRoutedConnectRequest|OpenRoutedSourceRouterTrust|BuildRoutedDialer|PrepareRoutedDialer|RunConnectRejects|RunConnectRouted)'

run_fast() {
  printf '\n== Focused route-capability-client tests ==\n'
  if ! go test ./cmd/wd -run "$focused_regex" -count=1; then
    printf 'WEDECENT_ROUTE_CLIENT_FOCUSED_FAIL\n' >&2
    return 1
  fi
  printf 'WEDECENT_ROUTE_CLIENT_FOCUSED_OK\n'

  printf '\n== cmd/wd regression suite ==\n'
  if ! go test ./cmd/wd -count=1; then
    printf 'WEDECENT_ROUTE_CLIENT_CMD_WD_FAIL\n' >&2
    return 1
  fi
  printf 'WEDECENT_ROUTE_CLIENT_CMD_WD_OK\n'
}

run_full() {
  run_fast || return 1

  printf '\n== Relevant package suite ==\n'
  if ! go test ./internal/account ./internal/mesh ./internal/meshnet ./cmd/wd -count=1; then
    printf 'WEDECENT_ROUTE_CLIENT_PACKAGES_FAIL\n' >&2
    return 1
  fi
  printf 'WEDECENT_ROUTE_CLIENT_PACKAGES_OK\n'

  printf '\n== Diff hygiene ==\n'
  if ! git diff --check; then
    printf 'WEDECENT_ROUTE_CLIENT_DIFF_CHECK_FAIL\n' >&2
    return 1
  fi
  printf 'WEDECENT_ROUTE_CLIENT_DIFF_CHECK_OK\n'

  printf '\n== Race suite ==\n'
  if ! command -v gcc >/dev/null 2>&1; then
    printf 'WEDECENT_ROUTE_CLIENT_RACE_ENV_FAIL: gcc not found\n' >&2
    return 1
  fi
  if ! CGO_ENABLED=1 go test -race ./internal/account ./internal/mesh ./internal/meshnet ./cmd/wd -count=1; then
    printf 'WEDECENT_ROUTE_CLIENT_RACE_FAIL\n' >&2
    return 1
  fi
  printf 'WEDECENT_ROUTE_CLIENT_RACE_OK\n'
}

snapshot() {
  find cmd/wd internal/account internal/mesh internal/meshnet \
    -type f -name '*.go' -printf '%T@ %p\n' 2>/dev/null \
    | sort \
    | sha256sum \
    | awk '{print $1}'
}

watch_loop() {
  printf 'WEDECENT_ROUTE_CLIENT_WATCHING\n'
  last="$(snapshot)"
  while true; do
    sleep 1
    current="$(snapshot)"
    if [[ "$current" != "$last" ]]; then
      last="$current"
      printf '\n== Go change detected ==\n'
      if run_fast; then
        printf 'WEDECENT_ROUTE_CLIENT_WATCH_PASS\n'
      else
        printf 'WEDECENT_ROUTE_CLIENT_WATCH_FAIL\n' >&2
      fi
    fi
  done
}

case "$MODE" in
  fast)
    if run_fast; then
      printf '\nWEDECENT_ROUTE_CLIENT_ALL_OK\n'
      exit 0
    fi
    exit 1
    ;;
  full)
    if run_full; then
      printf '\nWEDECENT_ROUTE_CLIENT_ALL_OK\n'
      exit 0
    fi
    exit 1
    ;;
  watch)
    if run_fast; then
      printf 'WEDECENT_ROUTE_CLIENT_INITIAL_PASS\n'
    else
      printf 'WEDECENT_ROUTE_CLIENT_INITIAL_FAIL\n' >&2
    fi
    watch_loop
    ;;
  *)
    fail "usage: $0 [fast|full|watch]"
    ;;
esac
