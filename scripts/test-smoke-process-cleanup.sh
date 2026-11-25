#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT/scripts/lib/smoke-processes.sh"

sleep 30 &
COOPERATIVE_PID=$!
sh -c 'trap "" TERM; exec sleep 30' &
STUBBORN_PID=$!

cleanup() {
  status=$?
  trap - EXIT INT TERM
  stop_child "$COOPERATIVE_PID"
  stop_child "$STUBBORN_PID"
  for pid in "$COOPERATIVE_PID" "$STUBBORN_PID"; do
    if kill -0 "$pid" 2>/dev/null; then
      printf 'child process %s remains alive after cleanup\n' "$pid" >&2
      status=1
    fi
  done
  if [ "$status" -eq 0 ]; then
    printf 'Interrupted smoke child cleanup passed.\n'
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

kill -TERM $$
