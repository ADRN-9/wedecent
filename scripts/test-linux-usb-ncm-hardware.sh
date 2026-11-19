#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "wedecent-usb-ncm-hardware: $*" >&2
  exit 1
}

[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"

for command in awk cmp dirname go grep id ip mktemp readlink sed stat timeout tr; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

: "${WEDECENT_USB_NCM_INTERFACE:?set the host-side USB NCM interface name}"
: "${WEDECENT_USB_NCM_ENDPOINT:?set the numeric peer endpoint as IPv4:port or [IPv6]:port}"
: "${WEDECENT_USB_NCM_FINGERPRINT:?set the expected WeDecent SHA256 fingerprint}"
: "${WEDECENT_USB_NCM_PAIRING_SECRET_FILE:?set a private file containing the fresh single-use WeDecent pairing secret}"
: "${WEDECENT_USB_NCM_CONNECTION_GRANT_FILE:?set the first short-lived connection grant file}"
: "${WEDECENT_USB_NCM_TERMINAL_INPUT_FILE:?set the first remote terminal input file}"
: "${WEDECENT_USB_NCM_TERMINAL_MARKER:?set the expected first remote terminal marker}"
: "${WEDECENT_USB_NCM_RECONNECT_CONNECTION_GRANT_FILE:?set a separate fresh reconnect grant file}"
: "${WEDECENT_USB_NCM_RECONNECT_INPUT_FILE:?set the reconnect terminal input file}"
: "${WEDECENT_USB_NCM_RECONNECT_MARKER:?set the expected reconnect terminal marker}"

validate_private_file() {
  local path="$1" label="$2" owner mode mode_value
  [[ -f "$path" && ! -L "$path" ]] || fail "$label must be a regular non-symlink file"
  owner="$(stat -c '%u' -- "$path")" || fail "cannot inspect $label owner"
  [[ "$owner" == "$(id -u)" ]] || fail "$label must be owned by the current user"
  mode="$(stat -c '%a' -- "$path")" || fail "cannot inspect $label permissions"
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || fail "$label permissions are malformed"
  mode_value=$((8#$mode))
  (( (mode_value & 0400) != 0 && (mode_value & 0077) == 0 && (mode_value & 07000) == 0 )) || fail "$label must be readable by the current user and inaccessible to group/other users"
}

validate_private_file "$WEDECENT_USB_NCM_PAIRING_SECRET_FILE" "pairing secret"

validate_connection_grant_file() {
  local path="$1" label="$2" size
  validate_private_file "$path" "$label"
  size="$(stat -c '%s' -- "$path")" || fail "cannot inspect $label size"
  [[ "$size" =~ ^[0-9]+$ ]] && (( size >= 1 && size <= 16384 )) || fail "$label must contain 1-16384 bytes"
  awk 'NR == 1 { count = split($0, parts, /\./); if (count == 3 && parts[1] != "" && parts[2] != "" && parts[3] != "" && $0 !~ /[[:space:]]/) valid = 1; next } NR == 2 && $0 == "" { next } { invalid = 1 } END { exit !(valid && !invalid) }' "$path" || fail "$label must contain exactly one JWT"
}
validate_connection_grant_file "$WEDECENT_USB_NCM_CONNECTION_GRANT_FILE" "first connection grant"
validate_connection_grant_file "$WEDECENT_USB_NCM_RECONNECT_CONNECTION_GRANT_FILE" "reconnect connection grant"
[[ ! "$WEDECENT_USB_NCM_CONNECTION_GRANT_FILE" -ef "$WEDECENT_USB_NCM_RECONNECT_CONNECTION_GRANT_FILE" ]] || fail "first and reconnect grants must be separate files"
if cmp -s -- "$WEDECENT_USB_NCM_CONNECTION_GRANT_FILE" "$WEDECENT_USB_NCM_RECONNECT_CONNECTION_GRANT_FILE"; then
  fail "reconnect must use a separate fresh connection grant, not a copy of the first grant"
fi
[[ -f "$WEDECENT_USB_NCM_TERMINAL_INPUT_FILE" && ! -L "$WEDECENT_USB_NCM_TERMINAL_INPUT_FILE" ]] || fail "terminal input must be a regular non-symlink file"
[[ -f "$WEDECENT_USB_NCM_RECONNECT_INPUT_FILE" && ! -L "$WEDECENT_USB_NCM_RECONNECT_INPUT_FILE" ]] || fail "reconnect input must be a regular non-symlink file"
[[ ! "$WEDECENT_USB_NCM_TERMINAL_INPUT_FILE" -ef "$WEDECENT_USB_NCM_RECONNECT_INPUT_FILE" ]] || fail "terminal and reconnect inputs must be separate files"

if [[ ! "$WEDECENT_USB_NCM_INTERFACE" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]]; then
  fail "interface name is invalid"
fi
sys_interface="/sys/class/net/$WEDECENT_USB_NCM_INTERFACE"
[[ -e "$sys_interface" ]] || fail "interface does not exist in sysfs"
[[ -e "$sys_interface/device" ]] || fail "interface has no physical device ancestry"

sys_device="$(readlink -f -- "$sys_interface/device")"
[[ "$sys_device" == /sys/devices/* ]] || fail "interface device does not resolve under /sys/devices"
driver_path="$(readlink -f -- "$sys_interface/device/driver" 2>/dev/null || true)"
[[ "${driver_path##*/}" == "cdc_ncm" ]] || fail "interface is not bound to the Linux cdc_ncm driver"

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
  peer_host="${BASH_REMATCH[1]}"
  peer_port="${BASH_REMATCH[2]}"
elif [[ "$WEDECENT_USB_NCM_ENDPOINT" =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3}):([0-9]{1,5})$ ]]; then
  peer_host="${BASH_REMATCH[1]}"
  peer_port="${BASH_REMATCH[3]}"
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

manufacturer="$(cat "$usb_node/manufacturer" 2>/dev/null || true)"
product_name="$(cat "$usb_node/product" 2>/dev/null || true)"
commit="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"
printf 'Host OS/kernel: %s\n' "$(uname -srmo)"
printf 'WeDecent commit: %s\n' "$commit"
printf 'USB NCM interface: %s driver=cdc_ncm manufacturer=%s product=%s VID:PID=%s:%s\n' "$WEDECENT_USB_NCM_INTERFACE" "$manufacturer" "$product_name" "$vendor" "$product"
printf 'Peer endpoint: %s (selected transport=direct_tcp+usb_ncm; route verified through selected USB NCM interface)\n' "$WEDECENT_USB_NCM_ENDPOINT"
printf 'Expected WeDecent fingerprint: %s\n' "$WEDECENT_USB_NCM_FINGERPRINT"

work="$(mktemp -d)"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT
chmod 700 "$work"
mkdir -m 700 "$work/bin" "$work/state" "$work/wrong-fingerprint" "$work/replay"
printf '%s' 'not-the-real-pairing-secret-for-fingerprint-probe' > "$work/wrong-fingerprint.secret"
chmod 600 "$work/wrong-fingerprint.secret"

go build -trimpath -buildvcs=false -o "$work/bin/wd" ./cmd/wd
chmod 700 "$work/bin/wd"
# Derive a valid, guaranteed-different pin from the independently supplied pin.
fingerprint_body="$WEDECENT_USB_NCM_FINGERPRINT"
if [[ "$fingerprint_body" == *:* ]]; then
  fingerprint_prefix="${fingerprint_body%%:*}"
  [[ "${fingerprint_prefix^^}" == "SHA256" ]] || fail "fingerprint prefix must be SHA256"
  fingerprint_body="${fingerprint_body#*:}"
fi
[[ "$fingerprint_body" =~ ^[[:xdigit:]]{64}$ ]] || fail "fingerprint must contain exactly 64 hexadecimal characters"
fingerprint_body="${fingerprint_body^^}"
if [[ "${fingerprint_body:0:1}" == "0" ]]; then
  wrong_first_nibble="1"
else
  wrong_first_nibble="0"
fi
wrong_fingerprint="SHA256:${wrong_first_nibble}${fingerprint_body:1}"

# A wrong pin must fail with the exact TLS fingerprint rejection, before pairing.
if env -u WEDECENT_PAIRING_SECRET "$work/bin/wd" pair --state "$work/wrong-fingerprint" --name wedecent-ncm-wrong-pin \
  --endpoint "$WEDECENT_USB_NCM_ENDPOINT" \
  --fingerprint "$wrong_fingerprint" \
  --pairing-secret-file "$work/wrong-fingerprint.secret" >/dev/null 2>"$work/wrong-fingerprint.err"; then
  fail "pairing unexpectedly accepted an incorrect server fingerprint"
fi
grep -Fq "device fingerprint mismatch" "$work/wrong-fingerprint.err" || fail "wrong fingerprint probe failed for a reason other than the precise device fingerprint mismatch"
echo "WEDECENT_USB_NCM_WRONG_FINGERPRINT_REJECTED"

pair_output="$(env -u WEDECENT_PAIRING_SECRET "$work/bin/wd" pair \
  --state "$work/state" \
  --name wedecent-usb-ncm-hardware-gate \
  --endpoint "$WEDECENT_USB_NCM_ENDPOINT" \
  --fingerprint "$WEDECENT_USB_NCM_FINGERPRINT" \
  --pairing-secret-file "$WEDECENT_USB_NCM_PAIRING_SECRET_FILE")"
printf '%s\n' "$pair_output"
grep -Fq ' via tcp://' <<<"$pair_output" || fail "pairing did not persist a direct TCP locator"

paired_device_id="$(sed -nE 's/^Paired .* \((wd_[a-z2-7]{16})\) via tcp:\/\/.*$/\1/p' <<<"$pair_output")"
[[ "$paired_device_id" =~ ^wd_[a-z2-7]{16}$ ]] || fail "could not extract paired WeDecent device ID"
if [[ -n "${WEDECENT_USB_NCM_EXPECT_DEVICE_ID:-}" && "$paired_device_id" != "$WEDECENT_USB_NCM_EXPECT_DEVICE_ID" ]]; then
  fail "paired device ID does not match WEDECENT_USB_NCM_EXPECT_DEVICE_ID"
fi
echo "WEDECENT_USB_NCM_PAIR_HARDWARE_OK"

# A different client identity must not be able to reuse the consumed secret.
if env -u WEDECENT_PAIRING_SECRET "$work/bin/wd" pair --state "$work/replay" --name wedecent-ncm-replay-probe \
  --endpoint "$WEDECENT_USB_NCM_ENDPOINT" \
  --fingerprint "$WEDECENT_USB_NCM_FINGERPRINT" \
  --pairing-secret-file "$WEDECENT_USB_NCM_PAIRING_SECRET_FILE" >/dev/null 2>"$work/replay.err"; then
  fail "server accepted a replayed single-use pairing secret"
fi
grep -Fq "invalid or already consumed pairing secret" "$work/replay.err" || fail "replay probe failed for a reason other than the precise consumed-secret rejection"
echo "WEDECENT_USB_NCM_REPLAY_REJECTED"

[[ -f "$WEDECENT_USB_NCM_TERMINAL_INPUT_FILE" && ! -L "$WEDECENT_USB_NCM_TERMINAL_INPUT_FILE" ]] || fail "terminal input must be a regular non-symlink file"
if grep -Fq "$WEDECENT_USB_NCM_TERMINAL_MARKER" "$WEDECENT_USB_NCM_TERMINAL_INPUT_FILE"; then
  fail "terminal input contains the expected marker contiguously; PTY echo could satisfy the assertion"
fi
if [[ "$WEDECENT_USB_NCM_TERMINAL_MARKER" == "$WEDECENT_USB_NCM_RECONNECT_MARKER" ]]; then
  fail "first-session and reconnect markers must be distinct"
fi
if grep -Fq "$WEDECENT_USB_NCM_RECONNECT_MARKER" "$WEDECENT_USB_NCM_RECONNECT_INPUT_FILE"; then
  fail "reconnect input contains the expected marker contiguously; PTY echo could satisfy the assertion"
fi

timeout_seconds="${WEDECENT_USB_NCM_TERMINAL_TIMEOUT_SECONDS:-60}"
[[ "$timeout_seconds" =~ ^[0-9]{1,3}$ ]] && (( 10#$timeout_seconds >= 1 && 10#$timeout_seconds <= 300 )) || fail "terminal timeout must be canonical decimal 1-300"
[[ "$timeout_seconds" == "$((10#$timeout_seconds))" ]] || fail "terminal timeout must use canonical decimal notation"

if timeout "$timeout_seconds" "$work/bin/wd" connect \
  --state "$work/state" \
  --endpoint "$WEDECENT_USB_NCM_ENDPOINT" \
  --lan-timeout 0 \
  --connection-grant-file "$WEDECENT_USB_NCM_CONNECTION_GRANT_FILE" \
  "$paired_device_id" < "$WEDECENT_USB_NCM_TERMINAL_INPUT_FILE" > "$work/terminal.out"; then
  :
else
  fail "authorized first terminal session did not complete successfully"
fi
grep -Fq "$WEDECENT_USB_NCM_TERMINAL_MARKER" "$work/terminal.out" || fail "remote PTY did not emit the expected first-session marker"
echo "WEDECENT_USB_NCM_TERMINAL_SESSION_HARDWARE_OK"

# The first command has closed its session before this second authorized
# connection is attempted with a different, fresh grant.
if timeout "$timeout_seconds" "$work/bin/wd" connect \
  --state "$work/state" \
  --endpoint "$WEDECENT_USB_NCM_ENDPOINT" \
  --lan-timeout 0 \
  --connection-grant-file "$WEDECENT_USB_NCM_RECONNECT_CONNECTION_GRANT_FILE" \
  "$paired_device_id" < "$WEDECENT_USB_NCM_RECONNECT_INPUT_FILE" > "$work/reconnect.out"; then
  :
else
  fail "authorized reconnect session did not complete successfully"
fi
grep -Fq "$WEDECENT_USB_NCM_RECONNECT_MARKER" "$work/reconnect.out" || fail "reconnected remote PTY did not emit the expected marker"
echo "WEDECENT_USB_NCM_RECONNECT_HARDWARE_OK"
echo "WEDECENT_USB_NCM_ACCEPTANCE_COMPLETE"
