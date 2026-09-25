#!/bin/sh
set -eu

usage() {
  echo "usage: $0 <wd-agent-binary> <agent-config-json>" >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
[ "$(id -u)" -eq 0 ] || { echo "installer must run as root" >&2; exit 1; }

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

for tool in install id systemctl getent; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required tool not found: $tool" >&2; exit 1; }
done

if ! getent passwd wedecent >/dev/null 2>&1; then
  command -v useradd >/dev/null 2>&1 || { echo "required tool not found: useradd" >&2; exit 1; }
  nologin=$(command -v nologin || true)
  [ -n "$nologin" ] || nologin=/usr/sbin/nologin
  useradd --system --home-dir /var/lib/wedecent --shell "$nologin" --user-group wedecent
fi
getent group wedecent >/dev/null 2>&1 || { echo "wedecent group is missing" >&2; exit 1; }

reject_symlink /usr/local/libexec/wedecent "binary directory"
reject_symlink /usr/local/libexec/wedecent/wd-agent "installed wd-agent"
reject_symlink /etc/wedecent "configuration directory"
reject_symlink /etc/wedecent/agent.json "installed agent config"
reject_symlink /var/lib/wedecent "state root"
reject_symlink /var/lib/wedecent/agent "agent state directory"
reject_symlink /etc/systemd/system/wedecent-agent.service "systemd unit destination"

install -d -o root -g root -m 0755 /usr/local/libexec/wedecent
install -o root -g root -m 0755 "$agent_src" /usr/local/libexec/wedecent/wd-agent

install -d -o root -g wedecent -m 0750 /etc/wedecent
install -o root -g wedecent -m 0640 "$config_src" /etc/wedecent/agent.json

install -d -o wedecent -g wedecent -m 0700 /var/lib/wedecent
install -d -o wedecent -g wedecent -m 0700 /var/lib/wedecent/agent

unit_src=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/wedecent-agent.service
validate_regular_file "$unit_src" "systemd unit"
install -o root -g root -m 0644 "$unit_src" /etc/systemd/system/wedecent-agent.service

systemctl daemon-reload
systemctl enable --now wedecent-agent.service

echo "installed and started wedecent-agent.service"
