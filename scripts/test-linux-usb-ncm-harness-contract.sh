#!/usr/bin/env bash
set -euo pipefail
unset WEDECENT_PAIRING_SECRET || true

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
harness="$root/scripts/test-linux-usb-ncm-hardware.sh"
grep -Fq 'WEDECENT_USB_NCM_ACCEPTANCE_COMPLETE' "$harness" || {
  echo "NCM harness has no complete-acceptance marker" >&2
  exit 1
}

work="$(mktemp -d)"
dirty_file=""
cleanup() {
  [[ -z "$dirty_file" ]] || rm -f -- "$dirty_file"
  rm -rf -- "$work"
}
trap cleanup EXIT
chmod 700 "$work"

pairing="$work/pairing.secret"
grant="$work/first.jwt"
reconnect="$work/reconnect.jwt"
terminal="$work/terminal.in"
reconnect_input="$work/reconnect.in"
printf '%s' 'dummy-single-use-secret-for-contract-test' > "$pairing"
printf '%s' 'header.first.payload' > "$grant"
printf '%s' 'header.second.payload' > "$reconnect"
printf '%s\n' 'exit' > "$terminal"
printf '%s\n' 'exit' > "$reconnect_input"
chmod 600 "$pairing" "$grant" "$reconnect"

commit="$(git -C "$root" rev-parse --verify HEAD)"
source_sha256="$(git -C "$root" archive --format=tar "$commit" | sha256sum | awk '{print $1}')"

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
  WEDECENT_USB_NCM_EXPECT_COMMIT
  WEDECENT_USB_NCM_EXPECT_SOURCE_SHA256
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
  "$commit"
  "$source_sha256"
)

for missing_index in "${!names[@]}"; do
  env_args=()
  for index in "${!names[@]}"; do
    [[ "$index" == "$missing_index" ]] || env_args+=("${names[$index]}=${values[$index]}")
  done
  log="$work/missing-${names[$missing_index]}.log"
  if env -i "PATH=$PATH" "${env_args[@]}" bash "$harness" >"$log" 2>&1; then
    echo "NCM harness unexpectedly accepted missing ${names[$missing_index]}" >&2
    exit 1
  fi
  grep -Fq "${names[$missing_index]}" "$log" || {
    cat "$log" >&2
    echo "NCM harness did not identify missing ${names[$missing_index]}" >&2
    exit 1
  }
done

env_args=()
for index in "${!names[@]}"; do env_args+=("${names[$index]}=${values[$index]}"); done
printf '%s' 'header.first.payload' > "$reconnect"
chmod 600 "$reconnect"
log="$work/reused-grant.log"
if env -i "PATH=$PATH" "${env_args[@]}" bash "$harness" >"$log" 2>&1; then
  echo "NCM harness unexpectedly accepted a reused connection grant" >&2
  exit 1
fi
grep -Fq "separate fresh connection grant" "$log" || {
  cat "$log" >&2
  echo "NCM harness did not identify the reused reconnect grant" >&2
  exit 1
}

fakebin="$work/fakebin"
mkdir -m 700 "$fakebin"
mkdir -p "$work/sys/class/net/usb0" "$work/sys/bus/usb/drivers/cdc_ncm"
usb_device="$work/sys/devices/platform/fake-usb/1-1"
usb_interface="$usb_device/1-1:1.0"
mkdir -p "$usb_interface/net"
printf '1d6b\n' > "$usb_device/idVendor"
printf '0104\n' > "$usb_device/idProduct"
printf 'WeDecent test fixture\n' > "$usb_device/manufacturer"
printf 'USB NCM contract fixture\n' > "$usb_device/product"
ln -s "$usb_interface" "$work/sys/class/net/usb0/device"
ln -s "$work/sys/bus/usb/drivers/cdc_ncm" "$usb_interface/driver"

cat > "$fakebin/ip" <<'IP'
#!/usr/bin/env bash
set -euo pipefail
[[ "${WEDECENT_PAIRING_SECRET+x}" != x ]] || { echo "pairing secret leaked to ip child" >&2; exit 97; }
case "$1 $2" in
  "link show") printf '2: usb0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n' ;;
  "route get") printf '192.0.2.1 dev usb0 src 192.0.2.2\n' ;;
  *) echo "unexpected fake ip invocation" >&2; exit 2 ;;
esac
IP
chmod 700 "$fakebin/ip"

cat > "$fakebin/go" <<'GO'
#!/usr/bin/env bash
set -euo pipefail
[[ "${WEDECENT_PAIRING_SECRET+x}" != x ]] || { echo "pairing secret leaked to go child" >&2; exit 97; }
if [[ "$1" == "env" && "$2" == "GOVERSION" ]]; then
  echo "go1.27.0"
  exit 0
fi
[[ "$1" == "build" ]] || { echo "unexpected fake go command" >&2; exit 2; }
output=""
package=""
while (($#)); do
  case "$1" in
    -o) output="$2"; shift 2 ;;
    -ldflags) shift 2 ;;
    *) package="$1"; shift ;;
  esac
done
[[ -n "$output" && -n "$package" ]] || { echo "fake go build arguments malformed" >&2; exit 2; }
case "$package" in
  ./cmd/wd)
    cat > "$output" <<'WD'
#!/usr/bin/env bash
set -euo pipefail
[[ "${WEDECENT_PAIRING_SECRET+x}" != x ]] || { echo "pairing secret leaked to wd child" >&2; exit 97; }
command="$1"
shift
case "$command" in
  pair)
    state=""
    while (($#)); do
      case "$1" in
        --state) state="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    if [[ "$state" == *wrong-fingerprint* ]]; then
      if [[ "${NCM_TEST_REJECTION_MODE:-}" == "wrong-fingerprint-generic" ]]; then
        echo "connection refused" >&2
      else
        echo "device fingerprint mismatch" >&2
      fi
      exit 1
    fi
    if [[ "$state" == *replay* ]]; then
      if [[ "${NCM_TEST_REJECTION_MODE:-}" == "replay-generic" ]]; then
        echo "connection refused" >&2
      else
        echo "invalid or already consumed pairing secret" >&2
      fi
      exit 1
    fi
    echo "Paired contract fixture (wd_aaaaaaaaaaaaaaaa) via tcp://192.0.2.1:7443"
    ;;
  connect)
    grant_file=""
    expected_commit=""
    expected_source=""
    while (($#)); do
      case "$1" in
        --connection-grant-file) grant_file="$2"; shift 2 ;;
        --expected-agent-commit) expected_commit="$2"; shift 2 ;;
        --expected-agent-source-sha256) expected_source="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    [[ "$expected_commit" == "$WEDECENT_USB_NCM_EXPECT_COMMIT" && "$expected_source" == "$WEDECENT_USB_NCM_EXPECT_SOURCE_SHA256" ]] || {
      echo "target agent build identity mismatch" >&2
      exit 255
    }
    case "${NCM_TEST_CONNECT_MODE:-success}" in
      timeout) sleep 10; exit 0 ;;
      reject) echo "authorization_denied: grant evidence unavailable" >&2; exit 255 ;;
      fail) echo "synthetic terminal failure" >&2; exit 42 ;;
    esac
    if [[ "$grant_file" == "$WEDECENT_USB_NCM_RECONNECT_CONNECTION_GRANT_FILE" ]]; then
      printf '%s\n' "$WEDECENT_USB_NCM_RECONNECT_MARKER"
    else
      printf '%s\n' "$WEDECENT_USB_NCM_TERMINAL_MARKER"
    fi
    ;;
  *) echo "unexpected fake wd command" >&2; exit 2 ;;
esac
WD
    ;;
  ./cmd/wd-agent)
    cat > "$output" <<'AGENT'
#!/usr/bin/env bash
set -euo pipefail
[[ "${WEDECENT_PAIRING_SECRET+x}" != x ]] || { echo "pairing secret leaked to wd-agent child" >&2; exit 97; }
if [[ "$1" == "version" ]]; then
  printf 'commit: %s\nsource_sha256: %s\n' "$WEDECENT_USB_NCM_EXPECT_COMMIT" "$WEDECENT_USB_NCM_EXPECT_SOURCE_SHA256"
fi
AGENT
    ;;
  *) echo "unexpected package: $package" >&2; exit 2 ;;
esac
if [[ "${NCM_TEST_NONREPRODUCIBLE:-0}" == "1" ]]; then
  count_file="$NCM_TEST_COUNTER_FILE"
  count=0
  [[ ! -f "$count_file" ]] || count="$(cat "$count_file")"
  count=$((count + 1))
  printf '%s' "$count" > "$count_file"
  printf '# build %s\n' "$count" >> "$output"
fi
chmod 700 "$output"
GO
chmod 700 "$fakebin/go"

test_harness="$work/harness-test.sh"
sed -e "s|^ROOT=.*|ROOT=\"$root\"|" \
  -e "s|^SYSFS_ROOT=\"/sys\"$|SYSFS_ROOT=\"$work/sys\"|" \
  -e 's/echo "WEDECENT_USB_NCM_/echo "WEDECENT_USB_NCM_CONTRACT_FIXTURE_/g' \
  "$harness" > "$test_harness"
chmod 700 "$test_harness"

base_args=()
for index in "${!names[@]}"; do base_args+=("${names[$index]}=${values[$index]}"); done
base_args+=("WEDECENT_USB_NCM_TERMINAL_TIMEOUT_SECONDS=1")

run_success() {
  local log="$work/success.log"
  env -i "PATH=$fakebin:$PATH" "WEDECENT_PAIRING_SECRET=canary-pairing-secret" "${base_args[@]}" "$@" bash "$test_harness" >"$log" 2>&1 || {
    cat "$log" >&2
    echo "NCM harness success-path contract failed" >&2
    exit 1
  }
  local markers=(
    WEDECENT_USB_NCM_CONTRACT_FIXTURE_SOURCE_PROVENANCE_VERIFIED
    WEDECENT_USB_NCM_CONTRACT_FIXTURE_WRONG_FINGERPRINT_REJECTED
    WEDECENT_USB_NCM_CONTRACT_FIXTURE_PAIR_HARDWARE_OK
    WEDECENT_USB_NCM_CONTRACT_FIXTURE_REPLAY_REJECTED
    WEDECENT_USB_NCM_CONTRACT_FIXTURE_AGENT_BUILD_IDENTITY_VERIFIED
    WEDECENT_USB_NCM_CONTRACT_FIXTURE_GRANT_EVIDENCE_VERIFIED
    WEDECENT_USB_NCM_CONTRACT_FIXTURE_TERMINAL_SESSION_HARDWARE_OK
    WEDECENT_USB_NCM_CONTRACT_FIXTURE_RECONNECT_AGENT_BUILD_IDENTITY_VERIFIED
    WEDECENT_USB_NCM_CONTRACT_FIXTURE_RECONNECT_GRANT_EVIDENCE_VERIFIED
    WEDECENT_USB_NCM_CONTRACT_FIXTURE_RECONNECT_HARDWARE_OK
    WEDECENT_USB_NCM_CONTRACT_FIXTURE_ACCEPTANCE_COMPLETE
  )
  local previous=0 line marker
  for marker in "${markers[@]}"; do
    [[ "$(grep -Fc "$marker" "$log")" == "1" ]] || { cat "$log" >&2; echo "missing or duplicate acceptance marker: $marker" >&2; exit 1; }
    line="$(awk -v marker="$marker" 'index($0, marker) { print NR; exit }' "$log")"
    (( line > previous )) || { echo "acceptance marker ordering failed at $marker" >&2; exit 1; }
    previous="$line"
  done
  [[ "$(awk 'END { print }' "$log")" == "WEDECENT_USB_NCM_CONTRACT_FIXTURE_ACCEPTANCE_COMPLETE" ]] || {
    echo "complete-acceptance marker was not the final output line" >&2
    exit 1
  }
}

run_failure() {
  local name="$1" expected="$2"
  shift 2
  local log="$work/$name.log"
  if env -i "PATH=$fakebin:$PATH" "WEDECENT_PAIRING_SECRET=canary-pairing-secret" "${base_args[@]}" "$@" bash "$test_harness" >"$log" 2>&1; then
    echo "NCM harness unexpectedly passed failure case $name" >&2
    exit 1
  fi
  grep -Fq "$expected" "$log" || {
    cat "$log" >&2
    echo "NCM harness failure case $name was misclassified" >&2
    exit 1
  }
  if grep -Fq "WEDECENT_USB_NCM_CONTRACT_FIXTURE_ACCEPTANCE_COMPLETE" "$log"; then
    echo "NCM harness emitted acceptance after failure case $name" >&2
    exit 1
  fi
}

run_success
run_failure timeout "authorized first terminal session timed out after 1s" "NCM_TEST_CONNECT_MODE=timeout"
run_failure authorization-rejection "authorized first terminal session was rejected by server authorization or authenticated build policy" "NCM_TEST_CONNECT_MODE=reject"
run_failure generic-session-failure "authorized first terminal session failed with exit status 42" "NCM_TEST_CONNECT_MODE=fail"
run_failure wrong-fingerprint-classification "wrong fingerprint probe failed for a reason other than the precise device fingerprint mismatch" "NCM_TEST_REJECTION_MODE=wrong-fingerprint-generic"
run_failure replay-classification "replay probe failed for a reason other than the precise consumed-secret rejection" "NCM_TEST_REJECTION_MODE=replay-generic"
run_failure nonreproducible-build "wd is not reproducible from the exact clean source commit" "NCM_TEST_NONREPRODUCIBLE=1" "NCM_TEST_COUNTER_FILE=$work/build-count"
run_failure mismatched-commit "checked-out commit does not match WEDECENT_USB_NCM_EXPECT_COMMIT" "WEDECENT_USB_NCM_EXPECT_COMMIT=0000000000000000000000000000000000000000"
run_failure mismatched-source "source archive SHA-256 does not match WEDECENT_USB_NCM_EXPECT_SOURCE_SHA256" "WEDECENT_USB_NCM_EXPECT_SOURCE_SHA256=0000000000000000000000000000000000000000000000000000000000000000"

dirty_file="$root/.ncm-contract-dirty-$$"
printf 'dirty\n' > "$dirty_file"
run_failure dirty-source "source working tree is not clean"
rm -f -- "$dirty_file"
dirty_file=""

echo "NCM hardware harness executable success/failure contract passed"
