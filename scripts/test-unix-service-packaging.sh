#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
linux_dir=$root/installer/linux
macos_dir=$root/installer/macos
unit=$linux_dir/wedecent-agent.service
linux_installer=$linux_dir/install-service.sh
macos_installer=$macos_dir/install-launch-agent.sh

for script in \
  "$linux_installer" \
  "$linux_dir/uninstall-service.sh" \
  "$macos_dir/render-launch-agent.sh" \
  "$macos_installer" \
  "$macos_dir/uninstall-launch-agent.sh"; do
  sh -n "$script"
done

grep -Fx 'User=wedecent' "$unit" >/dev/null
grep -Fx 'Group=wedecent' "$unit" >/dev/null
grep -Fx 'ExecStart=/usr/local/libexec/wedecent/wd-agent serve --config=/etc/wedecent/agent.json --state=/var/lib/wedecent/agent' "$unit" >/dev/null
grep -Fx 'NoNewPrivileges=true' "$unit" >/dev/null
grep -Fx 'ProtectSystem=strict' "$unit" >/dev/null
grep -Fx 'ProtectHome=true' "$unit" >/dev/null
grep -Fx 'ReadWritePaths=/var/lib/wedecent' "$unit" >/dev/null
grep -Fx 'CapabilityBoundingSet=' "$unit" >/dev/null
grep -Fx 'AmbientCapabilities=' "$unit" >/dev/null
if grep -Eq '^(User|Group)=root$' "$unit"; then
  echo "systemd unit must not run as root" >&2
  exit 1
fi

for required in \
  '/usr/local/libexec/wedecent/wd-agent' \
  '/etc/wedecent/agent.json' \
  '/var/lib/wedecent/agent' \
  '/etc/systemd/system/wedecent-agent.service'; do
  grep -F "reject_symlink $required" "$linux_installer" >/dev/null || {
    echo "Linux installer does not reject symlinked destination: $required" >&2
    exit 1
  }
done

work=${TMPDIR:-/tmp}/wedecent-service-test.$$
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir -p "$work"
plist=$work/agent.plist
agent='/Applications/WeDecent & Tools/wd-agent'
config='/Users/test/Library/Application Support/WeDecent/a&b<config>.json'
state='/Users/test/Library/Application Support/WeDecent/agent'
stdout_log='/Users/test/Library/Application Support/WeDecent/logs/stdout.log'
stderr_log='/Users/test/Library/Application Support/WeDecent/logs/stderr.log'

sh "$macos_dir/render-launch-agent.sh" "$agent" "$config" "$state" "$stdout_log" "$stderr_log" >"$plist"
grep -F '<string>/Applications/WeDecent &amp; Tools/wd-agent</string>' "$plist" >/dev/null
grep -F '<string>--config=/Users/test/Library/Application Support/WeDecent/a&amp;b&lt;config&gt;.json</string>' "$plist" >/dev/null
grep -F '<string>--state=/Users/test/Library/Application Support/WeDecent/agent</string>' "$plist" >/dev/null
grep -F '<integer>63</integer>' "$plist" >/dev/null
grep -F '<key>RunAtLoad</key>' "$plist" >/dev/null
grep -F '<key>KeepAlive</key>' "$plist" >/dev/null

if command -v plutil >/dev/null 2>&1; then
  plutil -lint "$plist" >/dev/null
fi

if sh "$macos_dir/render-launch-agent.sh" relative/path "$config" "$state" "$stdout_log" "$stderr_log" >/dev/null 2>&1; then
  echo "renderer accepted a relative binary path" >&2
  exit 1
fi

if ! grep -F 'refusing root installation' "$macos_installer" >/dev/null; then
  echo "macOS installer must explicitly refuse root" >&2
  exit 1
fi
if ! grep -F '/usr/bin/mktemp "$launch_agents/.com.wedecent.agent.plist.XXXXXX"' "$macos_installer" >/dev/null; then
  echo "macOS installer must create plist staging with mktemp" >&2
  exit 1
fi
if grep -F 'chmod 700 "$support_dir" "$bin_dir" "$state_dir" "$log_dir" "$launch_agents"' "$macos_installer" >/dev/null; then
  echo "macOS installer must not change permissions on the user LaunchAgents directory" >&2
  exit 1
fi
for required in \
  'reject_symlink "$state_dir"' \
  'reject_symlink "$agent_dst"' \
  'reject_symlink "$config_dst"' \
  'reject_symlink "$plist"'; do
  grep -F "$required" "$macos_installer" >/dev/null || {
    echo "macOS installer is missing destination symlink rejection: $required" >&2
    exit 1
  }
done

if ! grep -F 'preserved /etc/wedecent and /var/lib/wedecent' "$linux_dir/uninstall-service.sh" >/dev/null; then
  echo "Linux uninstaller must preserve identity/config/state by default" >&2
  exit 1
fi

echo "unix service packaging checks passed"
