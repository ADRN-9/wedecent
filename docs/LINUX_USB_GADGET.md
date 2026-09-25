# Linux USB CDC-ACM gadget helper

WeDecent can use a USB CDC-ACM byte stream as a physical transport on Linux. One side must actually support USB **device/gadget/dual-role** mode; a passive cable between two ordinary USB-host-only PCs does not create a serial link.

The repository includes `scripts/wedecent-linux-usb-gadget.sh` for a deliberately narrow configfs setup. It creates exactly one gadget named `wedecent-cdc-acm` with one ACM function. USB gadget configuration is host administration, not WeDecent trust: terminal identity is still established only by the existing Ed25519/TLS fingerprint and pairing flow.

## Preconditions

The gadget-side Linux system must have:

- a usable USB Device Controller under `/sys/class/udc`;
- configfs mounted with `/sys/kernel/config/usb_gadget` available;
- kernel USB gadget/configfs ACM support;
- root access for setup and teardown;
- a USB vendor ID and product ID that the operator is authorized to use.

The helper intentionally does **not** load kernel modules, mount configfs, choose a UDC, or invent USB vendor/product identifiers. Those choices are platform/administration responsibilities and vary by hardware and deployment.

List candidate UDCs explicitly, for example:

```sh
ls -1 /sys/class/udc
```

## Setup

From the repository root, run as root with an explicitly selected UDC and authorized USB identifiers:

```sh
sudo bash scripts/wedecent-linux-usb-gadget.sh setup \
  --udc '<exact-name-from-/sys/class/udc>' \
  --vendor-id '<4-hex-digit-vendor-id>' \
  --product-id '<4-hex-digit-product-id>' \
  --serial 'wedecent-lab-01'
```

Optional `--manufacturer` and `--product` strings are also accepted. They are USB enumeration metadata only and must never be treated as a WeDecent identity or trust signal.

The helper:

- operates only on `/sys/kernel/config/usb_gadget/wedecent-cdc-acm`;
- refuses setup if that path already exists;
- creates one `acm.usb0` function and one configuration;
- binds only to the exact UDC supplied by the operator;
- cleans up a partially created gadget if setup fails before binding completes;
- does not alter unrelated gadgets.

After setup, verify the actual gadget-side tty. It is commonly `/dev/ttyGS0`, but the operator must inspect the platform rather than assume the name. Then start the agent with an explicit serial endpoint, for example:

```sh
wd-agent serve --listen= --serial /dev/ttyGS0 --authorization-url '<non-production authorization service URL>'
```

Use the normal `wd-agent identity` and pairing-secret workflow to obtain the WeDecent fingerprint and fresh pairing secret. Do not use the USB serial string, VID/PID, UDC name, or tty path as an identity substitute.

On the client side, a Linux host will commonly enumerate the gadget as `/dev/ttyACM0`. Complete the real-device validation using `docs/LINUX_CDC_ACM_HARDWARE_VALIDATION.md`.

## Status

Status does not require mutation:

```sh
bash scripts/wedecent-linux-usb-gadget.sh status
```

The command reports whether the fixed WeDecent gadget is absent, configured but unbound, or bound to a UDC.

## Teardown

Disconnect active WeDecent serial sessions first, then run:

```sh
sudo bash scripts/wedecent-linux-usb-gadget.sh teardown
```

Teardown is intentionally fail-closed. Before unbinding, it requires the fixed gadget to contain exactly the helper's single expected function/configuration layout. If unexpected functions or configurations are present, it refuses to remove the gadget so an operator can inspect it manually.

## Hardware completion criterion

Repository tests can syntax-check the helper but cannot prove a real UDC/configfs/USB-host combination. The roadmap hardware boundary remains open until the CDC-ACM authorized terminal gate succeeds on real hardware. A successful real run should record the gadget-side hardware/platform, selected UDC, client `/dev/ttyACM*` enumeration, and the terminal-gate success marker without recording pairing secrets or connection-grant contents.
