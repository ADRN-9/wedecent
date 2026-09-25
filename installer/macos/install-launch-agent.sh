#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <wd-agent-binary> <agent-config-json>" >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
uid=$(id -u)
[ "$uid" -ne 0 ] || { echo "refusing root installation; install the LaunchAgent as the user whose shell will be exposed" >&2; exit 1; }

agent_src=$1
config_src=$2

validate_regular_file() {
  path=$1
  label=$2
  [ -f "$path" ] || { echo "$label must be a regular file: $path" >&2; exit 1; }
  [ ! -L "$path" ] || { echo "$label must not be a symbolic link: $path" >&2; exit 1; }
}

reject_symlink() {
  path=$1
  label=$2
  [ ! -L "$path" ] || { echo "$label must not be a symbolic link: $path" >&2; exit 1; }
}

validate_regular_file "$agent_src" "wd-agent binary"
[ -x "$agent_src" ] || { echo "wd-agent binary is not executable: $agent_src" >&2; exit 1; }
validate_regular_file "$config_src" "agent config"

case "${HOME:-}" in
  /*) ;;
  *) echo "HOME must be an absolute path" >&2; exit 1 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
renderer=$script_dir/render-launch-agent.sh
validate_regular_file "$renderer" "launch agent renderer"

support_dir=$HOME/Library/Application\ Support/WeDecent
bin_dir=$support_dir/bin
state_dir=$support_dir/agent
log_dir=$support_dir/logs
launch_agents=$HOME/Library/LaunchAgents
plist=$launch_agents/com.wedecent.agent.plist
agent_dst=$bin_dir/wd-agent
config_dst=$support_dir/agent.json
stdout_log=$log_dir/agent.stdout.log
stderr_log=$log_dir/agent.stderr.log

reject_symlink "$support_dir" "support directory"
reject_symlink "$bin_dir" "binary directory"
reject_symlink "$state_dir" "agent state directory"
reject_symlink "$log_dir" "log directory"
reject_symlink "$agent_dst" "installed wd-agent"
reject_symlink "$config_dst" "installed agent config"
reject_symlink "$plist" "LaunchAgent plist"

umask 077
mkdir -p "$bin_dir" "$state_dir" "$log_dir" "$launch_agents"
chmod 700 "$support_dir" "$bin_dir" "$state_dir" "$log_dir"

/usr/bin/install -m 0700 "$agent_src" "$agent_dst"
/usr/bin/install -m 0600 "$config_src" "$config_dst"

plist_tmp=$(/usr/bin/mktemp "$launch_agents/.com.wedecent.agent.plist.XXXXXX")
cleanup() { rm -f "$plist_tmp"; }
trap cleanup EXIT HUP INT TERM
"$renderer" "$agent_dst" "$config_dst" "$state_dir" "$stdout_log" "$stderr_log" >"$plist_tmp"
/usr/bin/plutil -lint "$plist_tmp" >/dev/null
chmod 0600 "$plist_tmp"
mv -f "$plist_tmp" "$plist"
trap - EXIT HUP INT TERM

domain=gui/$uid
if /bin/launchctl print "$domain" >/dev/null 2>&1; then
  /bin/launchctl bootout "$domain/com.wedecent.agent" >/dev/null 2>&1 || true
  /bin/launchctl bootstrap "$domain" "$plist"
  /bin/launchctl enable "$domain/com.wedecent.agent"
  echo "installed and loaded com.wedecent.agent"
else
  echo "installed com.wedecent.agent; it will load at the next graphical login"
fi
