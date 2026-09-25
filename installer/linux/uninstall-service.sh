#!/bin/sh
set -eu

[ "$#" -eq 0 ] || { echo "usage: $0" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "uninstaller must run as root" >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "required tool not found: systemctl" >&2; exit 1; }

systemctl disable --now wedecent-agent.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/wedecent-agent.service
rm -f /usr/local/libexec/wedecent/wd-agent
rmdir /usr/local/libexec/wedecent 2>/dev/null || true
systemctl daemon-reload

echo "removed wedecent-agent service files"
echo "preserved /etc/wedecent and /var/lib/wedecent; remove them manually only if identity/config/state should be destroyed"
