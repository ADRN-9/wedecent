#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Linux is required" >&2
  exit 1
fi

for command in go bluetoothctl grep mktemp; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 1
  fi
done

: "${WEDECENT_RFCOMM_PEER_MAC:?set WEDECENT_RFCOMM_PEER_MAC to the paired peer MAC}"
: "${WEDECENT_RFCOMM_CHANNEL:?set WEDECENT_RFCOMM_CHANNEL to the peer RFCOMM channel}"
: "${WEDECENT_RFCOMM_FINGERPRINT:?set WEDECENT_RFCOMM_FINGERPRINT to the peer WeDecent fingerprint}"
: "${WEDECENT_RFCOMM_PAIRING_SECRET:?set WEDECENT_RFCOMM_PAIRING_SECRET to a live single-use pairing secret}"

case "$WEDECENT_RFCOMM_CHANNEL" in
  ''|*[!0-9]*) echo "WEDECENT_RFCOMM_CHANNEL must be decimal 1-30" >&2; exit 1 ;;
esac
if (( WEDECENT_RFCOMM_CHANNEL < 1 || WEDECENT_RFCOMM_CHANNEL > 30 )); then
  echo "WEDECENT_RFCOMM_CHANNEL must be decimal 1-30" >&2
  exit 1
fi

peer_info="$(bluetoothctl info "$WEDECENT_RFCOMM_PEER_MAC" 2>/dev/null || true)"
if ! grep -Eq '^[[:space:]]*Paired:[[:space:]]+yes[[:space:]]*$' <<<"$peer_info"; then
  echo "Bluetooth peer is not paired according to BlueZ" >&2
  exit 1
fi

if ! bluetoothctl show 2>/dev/null | grep -Eq '^[[:space:]]*Powered:[[:space:]]+yes[[:space:]]*$'; then
  echo "no powered BlueZ controller is available" >&2
  exit 1
fi

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

export WEDECENT_PAIRING_SECRET="$WEDECENT_RFCOMM_PAIRING_SECRET"

pair_output="$($work/bin/wd pair \
  --state "$work/state" \
  --name wedecent-rfcomm-hardware-gate \
  --rfcomm "${WEDECENT_RFCOMM_PEER_MAC}/${WEDECENT_RFCOMM_CHANNEL}" \
  --fingerprint "$WEDECENT_RFCOMM_FINGERPRINT")"
printf '%s\n' "$pair_output"

if ! grep -Fq ' via rfcomm://' <<<"$pair_output"; then
  echo "pairing did not persist an RFCOMM locator" >&2
  exit 1
fi

paired_device_id="$(sed -n 's/^Paired .* (\(wd_[a-z2-7]*\)) via rfcomm:\/\/.*$/\1/p' <<<"$pair_output")"
if [[ ! "$paired_device_id" =~ ^wd_[a-z2-7]{16}$ ]]; then
  echo "could not extract paired WeDecent device ID" >&2
  exit 1
fi

if [[ -n "${WEDECENT_RFCOMM_EXPECT_DEVICE_ID:-}" && "$paired_device_id" != "$WEDECENT_RFCOMM_EXPECT_DEVICE_ID" ]]; then
  echo "paired device ID does not match WEDECENT_RFCOMM_EXPECT_DEVICE_ID" >&2
  exit 1
fi

echo "WEDECENT_RFCOMM_PAIR_HARDWARE_OK"

if [[ -z "${WEDECENT_RFCOMM_CONNECTION_GRANT_FILE:-}" ]]; then
  echo "Pairing hardware gate passed. Set WEDECENT_RFCOMM_CONNECTION_GRANT_FILE to also run the authorized terminal gate."
  exit 0
fi
if [[ ! -f "$WEDECENT_RFCOMM_CONNECTION_GRANT_FILE" ]]; then
  echo "WEDECENT_RFCOMM_CONNECTION_GRANT_FILE is not a regular file" >&2
  exit 1
fi

marker="WEDECENT_RFCOMM_TERMINAL_HARDWARE_OK"
printf 'printf "%s\\n"\nexit\n' "$marker" | \
  "$work/bin/wd" connect \
    --state "$work/state" \
    --rfcomm "${WEDECENT_RFCOMM_PEER_MAC}/${WEDECENT_RFCOMM_CHANNEL}" \
    --lan-timeout 0 \
    --connection-grant-file "$WEDECENT_RFCOMM_CONNECTION_GRANT_FILE" \
    "$paired_device_id" | tee "$work/terminal.out"

grep -Fq "$marker" "$work/terminal.out"
echo "WEDECENT_RFCOMM_TERMINAL_SESSION_HARDWARE_OK"
