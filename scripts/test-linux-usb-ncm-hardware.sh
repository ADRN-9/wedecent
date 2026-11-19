#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "wedecent-usb-ncm-hardware: $*" >&2
  exit 1
}

[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"

for command in dirname go grep ip mktemp readlink sed tee timeout tr; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

: "\${WEDECENT_USB_NCM_INTERFACE:?set the host-side USB NCM interface name}"
: "\${WEDECENT_USB_NCM_ENDPOINT:?set the numeric peer endpoint as IPv4:port or [IPv6]:port}"
: "\${WEDECENT_USB_NCM_FINGERPRINT:?set the expected WeDecent SHA256 fingerprint}"
: "\${WEDECENT_USB_NCM_PAIRING_SECRET:?set a fresh single-use WeDecent pairing secret}"

if [[ ! "$WEDECENT_USB_NCM_INTERFACE" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]]; then
  fail "interface name is invalid"
fi
sys_interface="/sys/class/net/$WEDECENT_USB_NCM_INTERFACE"
[[ -e "$sys_interface" ]] || fail "interface does not exist in sysfs"
[[ -e "$sys_interface/device" ]] || fail "interface has no physical device ancestry"

sys_device="$(readlink -f -- "$sys_interface/device")"
[[ "$sys_device" == /sys/devices/* ]] || fail "interface device does not resolve under /sys/devices"
driver_path="$(readlink -f -- "$sys_interface/device/driver" 2>/dev/null || true)"
[[ "\${driver_path##*/}" == "cdc_ncm" ]] || fail "interface is not bound to the Linux cdc_ncm driver"

usb_node=""
probe="$sys_device"
while [[ "$probe" == /sys/devices/* && "$probe" != /sys/devices ]]; do
  if [[ -r "$probe/idVendor" && -r "$probe/idProduct" ]]; then
    usb_node="$probe"
    break
  fi
  probe="$(dirname "$probe")"
done
[[ -n "$usb_node" ]] || fail "interface has no USB idVendor/idProduct ancestor"

vendor="$(tr -d '[:space:]' < "$usb_node/idVendor")"
product="$(tr -d '[:space:]' < "$usb_node/idProduct")"
[[ "$vendor" =~ ^[0-9A-Fa-f]{4}$ && "$product" =~ ^[0-9A-Fa-f]{4}$ ]] || fail "USB descriptor identifiers are malformed"

if [[ "$WEDECENT_USB_NCM_ENDPOINT" =~ ^\[([0-9A-Fa-f:.]+)\]:([0-9]{1,5})$ ]]; then
  peer_host="\${BASH_REMATCH[1]}"
  peer_port="\${BASH_REMATCH[2]}"
elif [[ "$WEDECENT_USB_NCM_ENDPOINT" =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]{1,5})$ ]]; then
  peer_host="\${BASH_REMATCH[1]}"
  peer_port="\${BASH_REMATCH[3]}"
else
  fail "endpoint must be a numeric IPv4:port or bracketed [IPv6]:port; DNS is not accepted"
fi
(( 10#$peer_port >= 1 && 10#$peer_port <= 65535 )) || fail "endpoint port must be 1-65535"
[[ "$peer_port" == "$((10#$peer_port))" ]] || fail "endpoint port must use canonical decimal notation"

link_info="$(ip link show dev "$WEDECENT_USB_NCM_INTERFACE" 2>/dev/null)" || fail "cannot inspect NCM interface"
grep -Eq '<[^>]*UP[^>]*>' <<<"$link_info" || fail "NCM interface is not administratively UP"
route_info="$(ip route get "$peer_host" 2>/dev/null)" || fail "no route exists to the numeric peer endpoint"
if [[ " $route_info " != *" dev $WEDECENT_USB_NCM_INTERFACE "* ]]; then
  fail "peer endpoint route does not use the selected USB NCM interface"
fi

printf 'USB NCM interface: %s driver=cdc_ncm vendor=%s product=%s\n' "$WEDECENT_USB_NCM_INTERFACE" "$vendor" "$product"
printf 'Peer endpoint: %s (route verified through selected USB NCM interface)\n' "$WEDECENT_USB_NCM_ENDPOINT"

work="$(mktemp -d)"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT
chmod 700 "$work"
mkdir -m 700 "$work/bin" "$work/state" "$work/wrong-fingerprint" "$work/replay"

go build -trimpath -buildvcs=false -o "$work/bin/wd" ./cmd/wd
chmod 700 "$work/bin/wd"
export WEDECENT_PAIRING_SECRET="$WEDECENT_USB_NCM_PAIRING_SECRET"

# A wrong pin must fail before the single-use secret is consumed.
if "$work/bin/wd" pair --state "$work/wrong-fingerprint" --name wedecent-ncm-wrong-pin \
  --endpoint "$WEDECENT_USB_NCM_ENDPOINT" \
  --fingerprint "SHA256:0000000000000000000000000000000000000000000000000000000000000000" >/dev/null 2>&1; then
  fail "pairing unexpectedly accepted an incorrect server fingerprint"
fi
echo "WEDECENT_USB_NCM_WRONG_FINGERPRINT_REJECTED"

pair_output="$("$work/bin/wd" pair \
  --state "$work/state" \
  --name wedecent-usb-ncm-hardware-gate \
  --endpoint "$WEDECENT_USB_NCM_ENDPOINT" \
  --fingerprint "$WEDECENT_USB_NCM_FINGERPRINT")"
printf '%s\n' "$pair_output"
grep -Fq ' via tcp://' <<<"$pair_output" || fail "pairing did not persist a direct TCP locator"

paired_device_id="$(sed -nE 's/^Paired .* \((wd_[a-z2-7]{16})\) via tcp:\/\/.*$/\1/p' <<<"$pair_output")"
[[ "$paired_device_id" =~ ^wd_[a-z2-7]{16}$ ]] || fail "could not extract paired WeDecent device ID"
if [[ -n "\${WEDECENT_USB_NCM_EXPECT_DEVICE_ID:-}" && "$paired_device_id" != "$WEDECENT_USB_NCM_EXPECT_DEVICE_ID" ]]; then
  fail "paired device ID does not match WEDECENT_USB_NCM_EXPECT_DEVICE_ID"
fi
echo "WEDECENT_USB_NCM_PAIR_HARDWARE_OK"

# A different client identity must not be able to reuse the consumed secret.
if "$work/bin/wd" pair --state "$work/replay" --name wedecent-ncm-replay-probe \
  --endpoint "$WEDECENT_USB_NCM_ENDPOINT" \
  --fingerprint "$WEDECENT_USB_NCM_FINGERPRINT" >/dev/null 2>&1; then
  fail "server accepted a replayed single-use pairing secret"
fi
echo "WEDECENT_USB_NCM_REPLAY_REJECTED"

if [[ -z "\${WEDECENT_USB_NCM_CONNECTION_GRANT_FILE:-}" ]]; then
  echo "Pairing and negative hardware gates passed. Set WEDECENT_USB_NCM_CONNECTION_GRANT_FILE, WEDECENT_USB_NCM_TERMINAL_INPUT_FILE, and WEDECENT_USB_NCM_TERMINAL_MARKER for the authorized terminal gate."
  exit 0
fi
[[ -f "$WEDECENT_USB_NCM_CONNECTION_GRANT_FILE" && ! -L "$WEDECENT_USB_NCM_CONNECTION_GRANT_FILE" ]] || fail "connection grant must be a regular non-symlink file"
: "\${WEDECENT_USB_NCM_TERMINAL_INPUT_FILE:?set terminal input file}"
: "\${WEDECENT_USB_NCM_TERMINAL_MARKER:?set expected remote terminal marker}"
[[ -f "$WEDECENT_USB_NCM_TERMINAL_INPUT_FILE" && ! -L "$WEDECENT_USB_NCM_TERMINAL_INPUT_FILE" ]] || fail "terminal input must be a regular non-symlink file"
if grep -Fq "$WEDECENT_USB_NCM_TERMINAL_MARKER" "$WEDECENT_USB_NCM_TERMINAL_INPUT_FILE"; then
  fail "terminal input contains the expected marker contiguously; PTY echo could satisfy the assertion"
fi

timeout_seconds="\${WEDECENT_USB_NCM_TERMINAL_TIMEOUT_SECONDS:-60}"
[[ "$timeout_seconds" =~ ^[0-9]{1,3}$ ]] && (( 10#$timeout_seconds >= 1 && 10#$timeout_seconds <= 300 )) || fail "terminal timeout must be canonical decimal 1-300"
[[ "$timeout_seconds" == "$((10#$timeout_seconds))" ]] || fail "terminal timeout must use canonical decimal notation"

timeout "$timeout_seconds" "$work/bin/wd" connect \
  --state "$work/state" \
  --endpoint "$WEDECENT_USB_NCM_ENDPOINT" \
  --lan-timeout 0 \
  --connection-grant-file "$WEDECENT_USB_NCM_CONNECTION_GRANT_FILE" \
  "$paired_device_id" < "$WEDECENT_USB_NCM_TERMINAL_INPUT_FILE" | tee "$work/terminal.out"
grep -Fq "$WEDECENT_USB_NCM_TERMINAL_MARKER" "$work/terminal.out" || fail "remote PTY did not emit the expected marker"
echo "WEDECENT_USB_NCM_TERMINAL_SESSION_HARDWARE_OK"

# A second fresh grant proves the transport can reconnect after the first
# session has closed. It is intentionally separate from the first grant.
if [[ -n "\${WEDECENT_USB_NCM_RECONNECT_CONNECTION_GRANT_FILE:-}" ]]; then
  [[ -f "$WEDECENT_USB_NCM_RECONNECT_CONNECTION_GRANT_FILE" && ! -L "$WEDECENT_USB_NCM_RECONNECT_CONNECTION_GRANT_FILE" ]] || fail "reconnect grant must be a regular non-symlink file"
  : "\${WEDECENT_USB_NCM_RECONNECT_INPUT_FILE:?set reconnect terminal input file}"
  : "\${WEDECENT_USB_NCM_RECONNECT_MARKER:?set reconnect marker}"
  [[ -f "$WEDECENT_USB_NCM_RECONNECT_INPUT_FILE" && ! -L "$WEDECENT_USB_NCM_RECONNECT_INPUT_FILE" ]] || fail "reconnect input must be a regular non-symlink file"
  grep -Fq "$WEDECENT_USB_NCM_RECONNECT_MARKER" "$WEDECENT_USB_NCM_RECONNECT_INPUT_FILE" && fail "reconnect input contains the expected marker contiguously"
  timeout "$timeout_seconds" "$work/bin/wd" connect \
    --state "$work/state" \
    --endpoint "$WEDECENT_USB_NCM_ENDPOINT" \
    --lan-timeout 0 \
    --connection-grant-file "$WEDECENT_USB_NCM_RECONNECT_CONNECTION_GRANT_FILE" \
    "$paired_device_id" < "$WEDECENT_USB_NCM_RECONNECT_INPUT_FILE" | tee "$work/reconnect.out"
  grep -Fq "$WEDECENT_USB_NCM_RECONNECT_MARKER" "$work/reconnect.out" || fail "reconnected remote PTY did not emit the expected marker"
  echo "WEDECENT_USB_NCM_RECONNECT_HARDWARE_OK"
else
  echo "Reconnection not run. Set WEDECENT_USB_NCM_RECONNECT_CONNECTION_GRANT_FILE, WEDECENT_USB_NCM_RECONNECT_INPUT_FILE, and WEDECENT_USB_NCM_RECONNECT_MARKER to prove a second authorized session."
fi
