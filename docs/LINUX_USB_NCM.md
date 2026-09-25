# Linux USB NCM networking

WeDecent can reuse its existing direct TCP transport over a point-to-point USB network link. No new WeDecent session transport is required: USB NCM only creates a network interface, while device identity, TLS 1.3, fingerprint pinning, pairing, and connection authorization remain in the existing direct-TCP/session layers.

The repository includes `scripts/wedecent-linux-usb-ncm.sh` for a deliberately narrow Linux configfs NCM gadget. The helper creates the USB network function only. It does **not** assign IP addresses, start DHCP, install routes, change DNS, modify firewall rules, or configure WeDecent trust.

## Why NCM

Linux configfs exposes NCM as the `ncm` gadget function and provides explicit gadget-side and host-side MAC address attributes. The kernel creates a network interface for the function. Network addressing is intentionally kept outside this helper so operators can integrate the link with their existing network policy.

## Preconditions

The gadget-side Linux system must have:

- a USB Device Controller under `/sys/class/udc`;
- configfs available at `/sys/kernel/config/usb_gadget`;
- USB gadget NCM support;
- root access for gadget setup/teardown;
- a USB vendor ID and product ID the operator is authorized to use;
- two explicit, distinct unicast MAC addresses for the gadget and host ends.

The helper never chooses these values automatically.

## Create the USB NCM function

From the repository root, run as root:

```sh
sudo bash scripts/wedecent-linux-usb-ncm.sh setup \
  --udc '<exact-name-from-/sys/class/udc>' \
  --vendor-id '<authorized-4-hex-digit-VID>' \
  --product-id '<authorized-4-hex-digit-PID>' \
  --device-mac '02:00:00:00:00:01' \
  --host-mac '02:00:00:00:00:02'
```

The example MAC addresses are locally administered examples for an isolated lab link. In a managed deployment, choose addresses according to the site's network policy and ensure they do not collide with other interfaces.

The helper operates only on `/sys/kernel/config/usb_gadget/wedecent-ncm`, creates one `ncm.usb0` function, binds only to the exact UDC supplied by the operator, and refuses to overwrite an existing fixed gadget path.

Run the non-mutating status command to identify the gadget-side interface name:

```sh
bash scripts/wedecent-linux-usb-ncm.sh status
```

## Configure the point-to-point IP link

Configure addresses using the platform's normal network-management mechanism. For a temporary isolated lab test, an administrator might choose a dedicated documentation-range subnet such as:

```text
gadget side: 192.0.2.1/30
host side:   192.0.2.2/30
```

The WeDecent helper intentionally does not execute `ip`, NetworkManager, systemd-networkd, DHCP, or firewall commands. Avoid installing a default route on this link unless that is explicitly intended by the deployment.

## Run WeDecent over existing direct TCP

Bind the agent only to the USB-link address when the USB link is intended to be the sole direct network surface, for example:

```sh
wd-agent serve \
  --listen '192.0.2.1:7443' \
  --authorization-url '<authorization service URL>'
```

On the host, pair using the normal expected WeDecent fingerprint:

```sh
wd pair \
  --endpoint '192.0.2.1:7443' \
  --fingerprint '<expected WeDecent SHA256 fingerprint>'
```

A subsequent `wd connect` uses the ordinary `tcp://192.0.2.1:7443` locator. USB MAC addresses, IP addresses, interface names, VID/PID, and physical cable attachment are transport metadata only and are never identity or trust signals.

## Teardown

Stop sessions that depend on the USB link, remove/disable any IP configuration using the same network-management mechanism that created it, then run:

```sh
sudo bash scripts/wedecent-linux-usb-ncm.sh teardown
```

Teardown verifies the fixed gadget still contains exactly the helper-managed single NCM function/configuration before unbinding it. Unexpected gadget layout causes a fail-closed refusal for manual inspection.

## Completion criterion

Repository CI can verify script syntax and non-mutating paths but cannot prove USB enumeration. The USB-networking roadmap item remains open until a real gadget/host pair has enumerated the NCM link and completed an authorized WeDecent terminal session over the existing direct TCP transport on that link.
