#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Linux is required" >&2
  exit 1
fi

for command in dirname go grep mktemp readlink sed tee tr; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 1
  fi
done

: "${WEDECENT_SERIAL_DEVICE:?set WEDECENT_SERIAL_DEVICE to the real CDC-ACM device, e.g. /dev/ttyACM0}"
: "${WEDECENT_SERIAL_FINGERPRINT:?set WEDECENT_SERIAL_FINGERPRINT to the peer WeDecent fingerprint}"
: "${WEDECENT_SERIAL_PAIRING_SECRET:?set WEDECENT_SERIAL_PAIRING_SECRET to a live single-use pairing secret}"

if [[ "$WEDECENT_SERIAL_DEVICE" != /dev/ttyACM* ]]; then
  echo "WEDECENT_SERIAL_DEVICE must be an explicit /dev/ttyACM* device" >&2
  exit 1
fi
if [[ -L "$WEDECENT_SERIAL_DEVICE" || ! -c "$WEDECENT_SERIAL_DEVICE" ]]; then
  echo "WEDECENT_SERIAL_DEVICE must be a non-symlink character device" >&2
  exit 1
fi

tty_name="${WEDECENT_SERIAL_DEVICE#/dev/}"
sys_tty="/sys/class/tty/$tty_name/device"
if [[ ! -e "$sys_tty" ]]; then
  echo "no sysfs device exists for $WEDECENT_SERIAL_DEVICE" >&2
  exit 1
fi
sys_device="$(readlink -f "$sys_tty")"
if [[ "$sys_device" != /sys/devices/* ]]; then
  echo "serial endpoint does not resolve to a kernel device" >&2
  exit 1
fi

# Require evidence that this tty is backed by a USB device rather than a PTY or
# an arbitrary local character device. Walk ancestors until the sysfs root and
# require a USB idVendor/idProduct pair.
usb_node=""
probe="$sys_device"
while [[ "$probe" == /sys/devices/* && "$probe" != /sys/devices ]]; do
  if [[ -r "$probe/idVendor" && -r "$probe/idProduct" ]]; then
    usb_node="$probe"
    break
  fi
  probe="$(dirname "$probe")"
done
if [[ -z "$usb_node" ]]; then
  echo "$WEDECENT_SERIAL_DEVICE is not backed by a detectable USB device" >&2
  exit 1
fi

vendor="$(tr -d '[:space:]' < "$usb_node/idVendor")"
product="$(tr -d '[:space:]' < "$usb_node/idProduct")"
if [[ ! "$vendor" =~ ^[0-9A-Fa-f]{4}$ || ! "$product" =~ ^[0-9A-Fa-f]{4}$ ]]; then
  echo "USB vendor/product identifiers are malformed" >&2
  exit 1
fi
printf 'CDC-ACM USB device: %s vendor=%s product=%s\n' "$WEDECENT_SERIAL_DEVICE" "$vendor" "$product"

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

export WEDECENT_PAIRING_SECRET="$WEDECENT_SERIAL_PAIRING_SECRET"
pair_output="$($work/bin/wd pair \
  --state "$work/state" \
  --name wedecent-cdc-acm-hardware-gate \
  --serial "$WEDECENT_SERIAL_DEVICE" \
  --fingerprint "$WEDECENT_SERIAL_FINGERPRINT")"
printf '%s\n' "$pair_output"

if ! grep -Fq ' via serial://' <<<"$pair_output"; then
  echo "pairing did not persist a serial locator" >&2
  exit 1
fi

paired_device_id="$(sed -n 's/^Paired .* (\(wd_[a-z2-7]*\)) via serial:\/\/\/dev\/.*$/\1/p' <<<"$pair_output")"
if [[ ! "$paired_device_id" =~ ^wd_[a-z2-7]{16}$ ]]; then
  echo "could not extract paired WeDecent device ID" >&2
  exit 1
fi
if [[ -n "${WEDECENT_SERIAL_EXPECT_DEVICE_ID:-}" && "$paired_device_id" != "$WEDECENT_SERIAL_EXPECT_DEVICE_ID" ]]; then
  echo "paired device ID does not match WEDECENT_SERIAL_EXPECT_DEVICE_ID" >&2
  exit 1
fi

echo "WEDECENT_CDC_ACM_PAIR_HARDWARE_OK"

if [[ -z "${WEDECENT_SERIAL_CONNECTION_GRANT_FILE:-}" ]]; then
  echo "Pairing hardware gate passed. Set WEDECENT_SERIAL_CONNECTION_GRANT_FILE to also run the authorized terminal gate."
  exit 0
fi
if [[ ! -f "$WEDECENT_SERIAL_CONNECTION_GRANT_FILE" ]]; then
  echo "WEDECENT_SERIAL_CONNECTION_GRANT_FILE is not a regular file" >&2
  exit 1
fi

# Split the marker in the input command so local/remote TTY echo cannot satisfy
# the assertion. Only command execution on the remote PTY emits it contiguously.
marker="WEDECENT_CDC_ACM_TERMINAL_HARDWARE_OK"
printf 'printf "WEDECENT_CDC_ACM_""TERMINAL_HARDWARE_OK\\n"\nexit\n' | \
  "$work/bin/wd" connect \
    --state "$work/state" \
    --serial "$WEDECENT_SERIAL_DEVICE" \
    --lan-timeout 0 \
    --connection-grant-file "$WEDECENT_SERIAL_CONNECTION_GRANT_FILE" \
    "$paired_device_id" | tee "$work/terminal.out"

grep -Fq "$marker" "$work/terminal.out"
echo "WEDECENT_CDC_ACM_TERMINAL_SESSION_HARDWARE_OK"
