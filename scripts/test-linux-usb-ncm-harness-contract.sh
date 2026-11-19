#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
harness="$root/scripts/test-linux-usb-ncm-hardware.sh"
if grep -Eq '^[[:space:]]*exit[[:space:]]+0([[:space:]]|$)' "$harness"; then
  echo "NCM harness contains an unconditional success exit" >&2
  exit 1
fi
grep -Fq 'WEDECENT_USB_NCM_ACCEPTANCE_COMPLETE' "$harness" || {
  echo "NCM harness has no complete-acceptance marker" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
chmod 700 "$work"

pairing="$work/pairing.secret"
grant="$work/first.jwt"
reconnect="$work/reconnect.jwt"
terminal="$work/terminal.in"
reconnect_input="$work/reconnect.in"
printf '%s' 'dummy-single-use-secret-for-contract-test' > "$pairing"
printf '%s' 'header.payload.signature' > "$grant"
printf '%s' 'header2.payload.signature' > "$reconnect"
printf '%s\n' 'exit' > "$terminal"
printf '%s\n' 'exit' > "$reconnect_input"
chmod 600 "$pairing" "$grant" "$reconnect"

names=(
  WEDECENT_USB_NCM_INTERFACE
  WEDECENT_USB_NCM_ENDPOINT
  WEDECENT_USB_NCM_FINGERPRINT
  WEDECENT_USB_NCM_PAIRING_SECRET_FILE
  WEDECENT_USB_NCM_CONNECTION_GRANT_FILE
  WEDECENT_USB_NCM_TERMINAL_INPUT_FILE
  WEDECENT_USB_NCM_TERMINAL_MARKER
  WEDECENT_USB_NCM_RECONNECT_CONNECTION_GRANT_FILE
  WEDECENT_USB_NCM_RECONNECT_INPUT_FILE
  WEDECENT_USB_NCM_RECONNECT_MARKER
)
values=(
  usb0
  192.0.2.1:7443
  SHA256:0000000000000000000000000000000000000000000000000000000000000000
  "$pairing"
  "$grant"
  "$terminal"
  WEDECENT_USB_NCM_REMOTE_OK
  "$reconnect"
  "$reconnect_input"
  WEDECENT_USB_NCM_RECONNECT_OK
)

for missing_index in "${!names[@]}"; do
  env_args=()
  for index in "${!names[@]}"; do
    if [[ "$index" != "$missing_index" ]]; then
      env_args+=("${names[$index]}=${values[$index]}")
    fi
  done
  log="$work/missing-${names[$missing_index]}.log"
  if env -i "PATH=$PATH" "${env_args[@]}" bash "$harness" >"$log" 2>&1; then
    echo "NCM harness unexpectedly accepted missing ${names[$missing_index]}" >&2
    exit 1
  fi
  if ! grep -Fq "${names[$missing_index]}" "$log"; then
    echo "NCM harness did not identify missing ${names[$missing_index]}" >&2
    exit 1
  fi
done

# Separate paths containing identical JWT bytes are not a fresh grant.
printf '%s' 'header.payload.signature' > "$reconnect"
chmod 600 "$reconnect"
env_args=()
for index in "${!names[@]}"; do
  env_args+=("${names[$index]}=${values[$index]}")
done
log="$work/reused-grant.log"
if env -i "PATH=$PATH" "${env_args[@]}" bash "$harness" >"$log" 2>&1; then
  echo "NCM harness unexpectedly accepted a reused connection grant" >&2
  exit 1
fi
if ! grep -Fq "separate fresh connection grant" "$log"; then
  echo "NCM harness did not identify the reused reconnect grant" >&2
  exit 1
fi

echo "NCM hardware harness fail-closed contract passed"
