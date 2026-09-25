#!/usr/bin/env bash
set -euo pipefail

readonly GADGET_ROOT="/sys/kernel/config/usb_gadget"
readonly GADGET_NAME="wedecent-ncm"
readonly GADGET_DIR="$GADGET_ROOT/$GADGET_NAME"
readonly CONFIG_NAME="c.1"
readonly FUNCTION_NAME="ncm.usb0"
readonly LANG_ID="0x409"

usage() {
  cat >&2 <<'EOF'
Usage:
  wedecent-linux-usb-ncm.sh setup --udc NAME --vendor-id HEX4 --product-id HEX4 --device-mac MAC --host-mac MAC [--serial TEXT]
  wedecent-linux-usb-ncm.sh teardown
  wedecent-linux-usb-ncm.sh status

This helper configures only /sys/kernel/config/usb_gadget/wedecent-ncm.
It creates the USB NCM link only; it never assigns IP addresses, routes, DHCP,
DNS, firewall rules, or WeDecent trust.
EOF
}

fail() {
  echo "wedecent-usb-ncm: $*" >&2
  exit 1
}

require_linux() {
  [[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
}

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "setup/teardown requires root"
}

validate_hex4() {
  [[ "$1" =~ ^[0-9A-Fa-f]{4}$ ]] || fail "$2 must contain exactly four hexadecimal digits"
}

validate_mac() {
  local mac="$1" name="$2"
  [[ "$mac" =~ ^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$ ]] || fail "$name must be a canonical six-octet MAC address"
  local first=$((16#${mac:0:2}))
  (( (first & 1) == 0 )) || fail "$name must be a unicast MAC address"
}

validate_string() {
  local value="$1" name="$2"
  [[ ${#value} -le 126 ]] || fail "$name is too long"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || fail "$name contains invalid control characters"
}

require_configfs() {
  [[ -d "$GADGET_ROOT" ]] || fail "$GADGET_ROOT is unavailable; mount configfs and enable USB gadget support first"
}

require_udc() {
  local udc="$1"
  [[ -n "$udc" && "$udc" != */* ]] || fail "invalid UDC name"
  [[ -d "/sys/class/udc/$udc" ]] || fail "UDC $udc does not exist under /sys/class/udc"
}

write_value() {
  printf '%s' "$1" > "$2"
}

assert_owned_layout() {
  local entry function_count=0 config_count=0
  [[ -d "$GADGET_DIR/functions/$FUNCTION_NAME" ]] || fail "refusing teardown: expected $FUNCTION_NAME is missing"
  [[ -d "$GADGET_DIR/configs/$CONFIG_NAME" ]] || fail "refusing teardown: expected $CONFIG_NAME is missing"
  [[ -L "$GADGET_DIR/configs/$CONFIG_NAME/$FUNCTION_NAME" ]] || fail "refusing teardown: expected NCM function link is missing"

  for entry in "$GADGET_DIR/functions/"*; do
    [[ -e "$entry" ]] || continue
    ((function_count += 1))
    [[ "${entry##*/}" == "$FUNCTION_NAME" ]] || fail "refusing teardown: unexpected gadget function ${entry##*/}"
  done
  for entry in "$GADGET_DIR/configs/"*; do
    [[ -e "$entry" ]] || continue
    ((config_count += 1))
    [[ "${entry##*/}" == "$CONFIG_NAME" ]] || fail "refusing teardown: unexpected gadget configuration ${entry##*/}"
  done
  [[ $function_count -eq 1 && $config_count -eq 1 ]] || fail "refusing teardown: gadget layout is not the helper-managed single-function layout"
}

setup_gadget() {
  require_root
  require_configfs

  local udc="" vendor="" product_id="" device_mac="" host_mac="" serial="wedecent-ncm"
  while (( $# > 0 )); do
    case "$1" in
      --udc) [[ $# -ge 2 ]] || fail "--udc requires a value"; udc="$2"; shift 2 ;;
      --vendor-id) [[ $# -ge 2 ]] || fail "--vendor-id requires a value"; vendor="$2"; shift 2 ;;
      --product-id) [[ $# -ge 2 ]] || fail "--product-id requires a value"; product_id="$2"; shift 2 ;;
      --device-mac) [[ $# -ge 2 ]] || fail "--device-mac requires a value"; device_mac="$2"; shift 2 ;;
      --host-mac) [[ $# -ge 2 ]] || fail "--host-mac requires a value"; host_mac="$2"; shift 2 ;;
      --serial) [[ $# -ge 2 ]] || fail "--serial requires a value"; serial="$2"; shift 2 ;;
      *) fail "unknown setup argument: $1" ;;
    esac
  done

  [[ -n "$udc" ]] || fail "--udc is required"
  [[ -n "$vendor" ]] || fail "--vendor-id is required; use an identifier you are authorized to use"
  [[ -n "$product_id" ]] || fail "--product-id is required; use an identifier you are authorized to use"
  [[ -n "$device_mac" ]] || fail "--device-mac is required"
  [[ -n "$host_mac" ]] || fail "--host-mac is required"
  validate_hex4 "$vendor" "vendor ID"
  validate_hex4 "$product_id" "product ID"
  validate_mac "$device_mac" "device MAC"
  validate_mac "$host_mac" "host MAC"
  [[ "${device_mac,,}" != "${host_mac,,}" ]] || fail "device and host MAC addresses must differ"
  validate_string "$serial" "serial"
  require_udc "$udc"

  [[ ! -e "$GADGET_DIR" ]] || fail "$GADGET_DIR already exists; inspect it manually or run teardown only if it was created by this helper"

  mkdir "$GADGET_DIR"
  local committed=0
  cleanup_partial() {
    if (( committed == 0 )); then
      [[ -e "$GADGET_DIR/UDC" ]] && printf '' > "$GADGET_DIR/UDC" 2>/dev/null || true
      rm -f "$GADGET_DIR/configs/$CONFIG_NAME/$FUNCTION_NAME" 2>/dev/null || true
      rmdir "$GADGET_DIR/configs/$CONFIG_NAME/strings/$LANG_ID" 2>/dev/null || true
      rmdir "$GADGET_DIR/configs/$CONFIG_NAME" 2>/dev/null || true
      rmdir "$GADGET_DIR/functions/$FUNCTION_NAME" 2>/dev/null || true
      rmdir "$GADGET_DIR/strings/$LANG_ID" 2>/dev/null || true
      rmdir "$GADGET_DIR" 2>/dev/null || true
    fi
  }
  trap cleanup_partial EXIT

  write_value "0x$vendor" "$GADGET_DIR/idVendor"
  write_value "0x$product_id" "$GADGET_DIR/idProduct"
  mkdir "$GADGET_DIR/strings/$LANG_ID"
  write_value "$serial" "$GADGET_DIR/strings/$LANG_ID/serialnumber"
  write_value "WeDecent" "$GADGET_DIR/strings/$LANG_ID/manufacturer"
  write_value "WeDecent USB NCM" "$GADGET_DIR/strings/$LANG_ID/product"

  mkdir "$GADGET_DIR/configs/$CONFIG_NAME"
  mkdir "$GADGET_DIR/configs/$CONFIG_NAME/strings/$LANG_ID"
  write_value "WeDecent USB network" "$GADGET_DIR/configs/$CONFIG_NAME/strings/$LANG_ID/configuration"

  mkdir "$GADGET_DIR/functions/$FUNCTION_NAME"
  write_value "$device_mac" "$GADGET_DIR/functions/$FUNCTION_NAME/dev_addr"
  write_value "$host_mac" "$GADGET_DIR/functions/$FUNCTION_NAME/host_addr"
  ln -s "$GADGET_DIR/functions/$FUNCTION_NAME" "$GADGET_DIR/configs/$CONFIG_NAME/$FUNCTION_NAME"

  write_value "$udc" "$GADGET_DIR/UDC"
  committed=1
  trap - EXIT

  local ifname=""
  [[ -r "$GADGET_DIR/functions/$FUNCTION_NAME/ifname" ]] && ifname="$(cat "$GADGET_DIR/functions/$FUNCTION_NAME/ifname")"
  echo "Configured $GADGET_NAME on UDC $udc"
  [[ -n "$ifname" ]] && echo "Gadget network interface: $ifname"
  echo "No IP address, route, DHCP, DNS, or firewall state was changed."
}

teardown_gadget() {
  require_root
  require_configfs
  [[ -d "$GADGET_DIR" ]] || fail "$GADGET_DIR does not exist"
  assert_owned_layout

  write_value "" "$GADGET_DIR/UDC"
  rm "$GADGET_DIR/configs/$CONFIG_NAME/$FUNCTION_NAME"
  rmdir "$GADGET_DIR/configs/$CONFIG_NAME/strings/$LANG_ID" 2>/dev/null || true
  rmdir "$GADGET_DIR/configs/$CONFIG_NAME"
  rmdir "$GADGET_DIR/functions/$FUNCTION_NAME"
  rmdir "$GADGET_DIR/strings/$LANG_ID" 2>/dev/null || true
  rmdir "$GADGET_DIR"
  echo "Removed $GADGET_NAME"
}

status_gadget() {
  require_configfs
  if [[ ! -d "$GADGET_DIR" ]]; then
    echo "not configured"
    return 1
  fi
  local udc="" ifname=""
  [[ -r "$GADGET_DIR/UDC" ]] && udc="$(cat "$GADGET_DIR/UDC")"
  [[ -r "$GADGET_DIR/functions/$FUNCTION_NAME/ifname" ]] && ifname="$(cat "$GADGET_DIR/functions/$FUNCTION_NAME/ifname")"
  printf 'configured%s%s\n' "${udc:+ and bound to $udc}" "${ifname:+; interface $ifname}"
}

main() {
  require_linux
  [[ $# -ge 1 ]] || { usage; exit 2; }
  local command="$1"
  shift
  case "$command" in
    setup) setup_gadget "$@" ;;
    teardown) [[ $# -eq 0 ]] || fail "teardown takes no arguments"; teardown_gadget ;;
    status) [[ $# -eq 0 ]] || fail "status takes no arguments"; status_gadget ;;
    -h|--help|help) usage ;;
    *) usage; fail "unknown command: $command" ;;
  esac
}

main "$@"
