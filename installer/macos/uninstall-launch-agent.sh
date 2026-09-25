#!/bin/sh
set -eu

[ "$#" -eq 0 ] || { echo "usage: $0" >&2; exit 2; }
uid=$(id -u)
[ "$uid" -ne 0 ] || { echo "refusing root uninstallation; run as the user who owns the LaunchAgent" >&2; exit 1; }
case "${HOME:-}" in
  /*) ;;
  *) echo "HOME must be an absolute path" >&2; exit 1 ;;
esac

support_dir=$HOME/Library/Application\ Support/WeDecent
plist=$HOME/Library/LaunchAgents/com.wedecent.agent.plist
domain=gui/$uid

/bin/launchctl bootout "$domain/com.wedecent.agent" >/dev/null 2>&1 || true
rm -f "$plist" "$support_dir/bin/wd-agent"
rmdir "$support_dir/bin" 2>/dev/null || true

echo "removed com.wedecent.agent LaunchAgent files"
echo "preserved $support_dir/agent.json, $support_dir/agent, and logs; remove them manually only if identity/config/state should be destroyed"
