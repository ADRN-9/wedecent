#!/usr/bin/env bash
set -euo pipefail

readonly GADGET_ROOT="/sys/kernel/config/usb_gadget"
readonly GADGET_NAME="wedecent-cdc-acm"
readonly GADGET_DIR="$GADGET_ROOT/$GADGET_NAME"
readonly CONFIG_NAME="c.1"
readonly FUNCTION_NAME="acm.usb0"
readonly LANG_ID="0x409"

usage() {
  cat >&2 <<'EOF'
Usage:
  wedecent-linux-usb-gadget.sh setup --udc NAME --vendor-id HEX4 --product-id HEX4 [--serial TEXT] [--manufacturer TEXT] [--product TEXT]
  wedecent-linux-usb-gadget.sh teardown
  wedecent-linux-usb-gadget.sh status

This helper configures only /sys/kernel/config/usb_gadget/wedecent-cdc-acm.
It never selects a UDC automatically and never assigns USB identifiers by default.
EOF
}

fail() {
  echo "wedecent-usb-gadget: $*" >&2
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

validate_string() {
  local value="$1" name="$2"
  [[ ${#value} -le 126 ]] || fail "$name is too long"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\0'* ]] || fail "$name contains invalid control characters"
}

require_configfs() {
  [[ -d "$GADGET_ROOT" ]] || fail "$GADGET_ROOT is unavailable; mount configfs and load USB gadget support first"
}

require_udc() {
  local udc="$1"
  [[ "$udc" != */* && -n "$udc" ]] || fail "invalid UDC name"
  [[ -d "/sys/class/udc/$udc" ]] || fail "UDC $udc does not exist under /sys/class/udc"
}

write_value() {
  local value="$1" path="$2"
  printf '%s' "$value" > "$path"
}

setup_gadget() {
  require_root
  require_configfs

  local udc="" vendor="" product_id="" serial="wedecent" manufacturer="WeDecent" product="WeDecent CDC-ACM"
  while (( $# > 0 )); do
    case "$1" in
      --udc) [[ $# -ge 2 ]] || fail "--udc requires a value"; udc="$2"; shift 2 ;;
      --vendor-id) [[ $# -ge 2 ]] || fail "--vendor-id requires a value"; vendor="$2"; shift 2 ;;
      --product-id) [[ $# -ge 2 ]] || fail "--product-id requires a value"; product_id="$2"; shift 2 ;;
      --serial) [[ $# -ge 2 ]] || fail "--serial requires a value"; serial="$2"; shift 2 ;;
      --manufacturer) [[ $# -ge 2 ]] || fail "--manufacturer requires a value"; manufacturer="$2"; shift 2 ;;
      --product) [[ $# -ge 2 ]] || fail "--product requires a value"; product="$2"; shift 2 ;;
      *) fail "unknown setup argument: $1" ;;
    esac
  done

  [[ -n "$udc" ]] || fail "--udc is required"
  [[ -n "$vendor" ]] || fail "--vendor-id is required; use an identifier you are authorized to use"
  [[ -n "$product_id" ]] || fail "--product-id is required; use an identifier you are authorized to use"
  validate_hex4 "$vendor" "vendor ID"
  validate_hex4 "$product_id" "product ID"
  validate_string "$serial" "serial"
  validate_string "$manufacturer" "manufacturer"
  validate_string "$product" "product"
  require_udc "$udc"

  [[ ! -e "$GADGET_DIR" ]] || fail "$GADGET_DIR already exists; inspect it manually or run teardown if it was created by this helper"

  mkdir "$GADGET_DIR"
  local committed=0
  cleanup_partial() {
    if (( committed == 0 )); then
      if [[ -e "$GADGET_DIR/UDC" ]]; then
        printf '' > "$GADGET_DIR/UDC" 2>/dev/null || true
      fi
      rm -f "$GADGET_DIR/configs/$CONFIG_NAME/$FUNCTION_NAME" 2>/dev/null || true
      rmdir "$GADGET_DIR/configs/$CONFIG_NAME/strings/$LANG_ID" 2>/dev/null || true
      rmdir "$GADGET_DIR/configs/$CONFIG_NAME" 2>/dev/null || true
      rmdir "$GADGET_DIR/functions/$FUNCTION_NAME" 2>/dev/null || true
      rmdir "$GADGET_DIR/strings/$LANG_ID" 2>/dev/null || true
      rmdir "$GADGET_DIR" 2>/dev/null || true
    fi
  }
  trap cleanup_partial RETURN

  write_value "0x$vendor" "$GADGET_DIR/idVendor"
  write_value "0x$product_id" "$GADGET_DIR/idProduct"

  mkdir "$GADGET_DIR/strings/$LANG_ID"
  write_value "$serial" "$GADGET_DIR/strings/$LANG_ID/serialnumber"
  write_value "$manufacturer" "$GADGET_DIR/strings/$LANG_ID/manufacturer"
  write_value "$product" "$GADGET_DIR/strings/$LANG_ID/product"

  mkdir "$GADGET_DIR/configs/$CONFIG_NAME"
  mkdir "$GADGET_DIR/configs/$CONFIG_NAME/strings/$LANG_ID"
  write_value "WeDecent serial" "$GADGET_DIR/configs/$CONFIG_NAME/strings/$LANG_ID/configuration"
  write_value "250" "$GADGET_DIR/configs/$CONFIG_NAME/MaxPower"

  mkdir "$GADGET_DIR/functions/$FUNCTION_NAME"
  ln -s "$GADGET_DIR/functions/$FUNCTION_NAME" "$GADGET_DIR/configs/$CONFIG_NAME/$FUNCTION_NAME"

  write_value "$udc" "$GADGET_DIR/UDC"
  committed=1
  trap - RETURN

  echo "Configured $GADGET_NAME on UDC $udc"
  echo "Gadget-side serial endpoint is normally /dev/ttyGS0; verify the actual node before starting wd-agent."
}

teardown_gadget() {
  require_root
  require_configfs
  [[ -d "$GADGET_DIR" ]] || fail "$GADGET_DIR does not exist"

  [[ -d "$GADGET_DIR/functions/$FUNCTION_NAME" ]] || fail "refusing teardown: expected $FUNCTION_NAME is missing"
  [[ -d "$GADGET_DIR/configs/$CONFIG_NAME" ]] || fail "refusing teardown: expected $CONFIG_NAME is missing"
  [[ -L "$GADGET_DIR/configs/$CONFIG_NAME/$FUNCTION_NAME" ]] || fail "refusing teardown: expected function link is missing"

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
  local udc=""
  [[ -r "$GADGET_DIR/UDC" ]] && udc="$(cat "$GADGET_DIR/UDC")"
  if [[ -n "$udc" ]]; then
    echo "configured and bound: $udc"
  else
    echo "configured but unbound"
  fi
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
