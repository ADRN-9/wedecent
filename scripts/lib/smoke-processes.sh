stop_child() {
  pid=$1
  [ -n "$pid" ] || return 0
  kill "$pid" 2>/dev/null || true
  attempts=0
  while kill -0 "$pid" 2>/dev/null; do
    state=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d ' ' || true)
    case "$state" in
      Z*|"") break ;;
    esac
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 20 ]; then
      kill -KILL "$pid" 2>/dev/null || true
      break
    fi
    sleep 0.1
  done
  wait "$pid" 2>/dev/null || true
}
