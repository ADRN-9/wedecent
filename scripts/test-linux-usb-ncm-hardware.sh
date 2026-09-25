#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Linux is required" >&2
  exit 1
fi

for command in go grep ip mktemp readlink sed tee tr; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 1
  fi
done

: "${WEDECENT_USB_NCM_INTERFACE:?set WEDECENT_USB_NCM_INTERFACE to the already configured USB NCM host interface}"
: "${WEDECENT_USB_NCM_PEER_IP:?set WEDECENT_USB_NCM_PEER_IP to the gadget-side point-to-point IPv4 address}"
: "${WEDECENT_USB_NCM_FINGERPRINT:?set WEDECENT_USB_NCM_FINGERPRINT to the peer WeDecent fingerprint}"
: "${WEDECENT_USB_NCM_PAIRING_SECRET:?set WEDECENT_USB_NCM_PAIRING_SECRET to a live single-use pairing secret}"

validate_ipv4() {
  local address="$1" octet
  [[ "$address" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  local old_ifs="$IFS"
  IFS='.' read -r -a octets <<<"$address"
  IFS="$old_ifs"
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]+$ ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
}

if ! validate_ipv4 "$WEDECENT_USB_NCM_PEER_IP"; then
  echo "WEDECENT_USB_NCM_PEER_IP must be an explicit IPv4 address" >&2
  exit 1
fi

peer_port="${WEDECENT_USB_NCM_PEER_PORT:-7443}"
if [[ ! "$peer_port" =~ ^[0-9]+$ ]] || (( peer_port < 1 || peer_port > 65535 )); then
  echo "WEDECENT_USB_NCM_PEER_PORT must be between 1 and 65535" >&2
  exit 1
fi

iface="$WEDECENT_USB_NCM_INTERFACE"
if [[ ! "$iface" =~ ^[A-Za-z0-9_.:-]+$ || ! -d "/sys/class/net/$iface" ]]; then
  echo "WEDECENT_USB_NCM_INTERFACE must name an existing simple network interface" >&2
  exit 1
fi
if [[ ! -e "/sys/class/net/$iface/device" ]]; then
  echo "$iface does not expose a device-backed sysfs entry" >&2
  exit 1
fi

sys_device="$(readlink -f "/sys/class/net/$iface/device")"
if [[ "$sys_device" != /sys/devices/* ]]; then
  echo "$iface does not resolve to a kernel device" >&2
  exit 1
fi

usb_node=""
probe="$sys_device"
while [[ "$probe" == /sys/devices/* && "$probe" != /sys/devices ]]; do
  if [[ -r "$probe/idVendor" && -r "$probe/idProduct" ]]; then
    usb_node="$probe"
    break
  fi
  probe="${probe%/*}"
done
if [[ -z "$usb_node" ]]; then
  echo "$iface is not backed by a detectable USB device" >&2
  exit 1
fi

vendor="$(tr -d '[:space:]' < "$usb_node/idVendor")"
product="$(tr -d '[:space:]' < "$usb_node/idProduct")"
if [[ ! "$vendor" =~ ^[0-9A-Fa-f]{4}$ || ! "$product" =~ ^[0-9A-Fa-f]{4}$ ]]; then
  echo "USB vendor/product identifiers are malformed" >&2
  exit 1
fi

operstate="$(<"/sys/class/net/$iface/operstate")"
if [[ "$operstate" != "up" && "$operstate" != "unknown" ]]; then
  echo "$iface is not operational (state: $operstate)" >&2
  exit 1
fi

route_output="$(ip route get "$WEDECENT_USB_NCM_PEER_IP")"
if ! grep -Fq " dev $iface " <<<" $route_output "; then
  echo "route to $WEDECENT_USB_NCM_PEER_IP does not use $iface" >&2
  echo "$route_output" >&2
  exit 1
fi

printf 'USB network interface: %s vendor=%s product=%s\n' "$iface" "$vendor" "$product"
printf 'Route to peer: %s\n' "$route_output"

work="$(mktemp -d)"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT
chmod 700 "$work"
mkdir -p "$work/bin" "$work/state"
chmod 700 "$work/bin" "$work/state"

go build -o "$work/bin/wd" ./cmd/wd
chmod 700 "$work/bin/wd"

endpoint="$WEDECENT_USB_NCM_PEER_IP:$peer_port"
export WEDECENT_PAIRING_SECRET="$WEDECENT_USB_NCM_PAIRING_SECRET"
pair_output="$($work/bin/wd pair \
  --state "$work/state" \
  --name wedecent-usb-ncm-hardware-gate \
  --endpoint "$endpoint" \
  --fingerprint "$WEDECENT_USB_NCM_FINGERPRINT")"
printf '%s\n' "$pair_output"

if ! grep -Fq " via tcp://$endpoint" <<<"$pair_output"; then
  echo "pairing did not persist the expected direct TCP locator" >&2
  exit 1
fi

paired_device_id="$(sed -n 's/^Paired .* (\(wd_[a-z2-7]*\)) via tcp:\/\/.*$/\1/p' <<<"$pair_output")"
if [[ ! "$paired_device_id" =~ ^wd_[a-z2-7]{16}$ ]]; then
  echo "could not extract paired WeDecent device ID" >&2
  exit 1
fi
if [[ -n "${WEDECENT_USB_NCM_EXPECT_DEVICE_ID:-}" && "$paired_device_id" != "$WEDECENT_USB_NCM_EXPECT_DEVICE_ID" ]]; then
  echo "paired device ID does not match WEDECENT_USB_NCM_EXPECT_DEVICE_ID" >&2
  exit 1
fi

echo "WEDECENT_USB_NCM_PAIR_HARDWARE_OK"

if [[ -z "${WEDECENT_USB_NCM_CONNECTION_GRANT_FILE:-}" ]]; then
  echo "Pairing hardware gate passed. Set WEDECENT_USB_NCM_CONNECTION_GRANT_FILE to also run the authorized terminal gate."
  exit 0
fi
if [[ ! -f "$WEDECENT_USB_NCM_CONNECTION_GRANT_FILE" ]]; then
  echo "WEDECENT_USB_NCM_CONNECTION_GRANT_FILE is not a regular file" >&2
  exit 1
fi

marker="WEDECENT_USB_NCM_TERMINAL_HARDWARE_OK"
printf 'printf "WEDECENT_USB_NCM_""TERMINAL_HARDWARE_OK\\n"\nexit\n' | \
  "$work/bin/wd" connect \
    --state "$work/state" \
    --endpoint "$endpoint" \
    --lan-timeout 0 \
    --connection-grant-file "$WEDECENT_USB_NCM_CONNECTION_GRANT_FILE" \
    "$paired_device_id" | tee "$work/terminal.out"

grep -Fq "$marker" "$work/terminal.out"
echo "WEDECENT_USB_NCM_TERMINAL_SESSION_HARDWARE_OK"
