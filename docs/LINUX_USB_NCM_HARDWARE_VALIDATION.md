# Linux USB NCM hardware validation

The repository can validate USB NCM helper syntax, but hosted CI cannot prove that a real USB Device Controller, cable, host driver, network interface, and point-to-point route work together. The USB-networking roadmap item therefore has a separate real-hardware gate.

The gate is read-only with respect to host networking. Configure the NCM interface and IP addresses using the platform's normal network-management mechanism before running it. The harness will not add addresses, routes, DHCP, DNS, or firewall rules.

## Peer preparation

On the Linux gadget/device side:

1. Configure the NCM gadget, for example with `scripts/wedecent-linux-usb-ncm.sh`.
2. Configure a point-to-point IP address on the gadget's NCM interface using the deployment's normal network policy.
3. Start `wd-agent` bound to that USB-link IP address and the normal authorization service.
4. Obtain the agent's expected WeDecent fingerprint and create a fresh single-use pairing secret.

On the Linux host/client side:

1. Confirm the USB NCM interface enumerated.
2. Configure the host-side point-to-point IP address.
3. Confirm the kernel route to the gadget-side peer IP uses that USB interface.

USB VID/PID, MAC addresses, interface names, IP addresses, and physical cable attachment are not WeDecent identity or trust signals.

## Pairing gate

From the repository root on the Linux client, set:

```sh
export WEDECENT_USB_NCM_INTERFACE='<USB-backed host interface>'
export WEDECENT_USB_NCM_PEER_IP='<gadget-side IPv4 address>'
export WEDECENT_USB_NCM_PEER_PORT='7443' # optional; 7443 is the default
export WEDECENT_USB_NCM_FINGERPRINT='<expected WeDecent SHA256 fingerprint>'
export WEDECENT_USB_NCM_PAIRING_SECRET='<fresh single-use pairing secret>'
# Optional but recommended:
export WEDECENT_USB_NCM_EXPECT_DEVICE_ID='wd_aaaaaaaaaaaaaaaa'
```

Run:

```sh
bash scripts/test-linux-usb-ncm-hardware.sh
```

Before invoking WeDecent, the harness requires:

- an existing Linux network interface with a device-backed sysfs entry;
- detectable USB ancestry with valid USB vendor/product identifiers;
- an operational interface state;
- an explicit IPv4 peer address;
- `ip route get <peer>` to resolve through the exact configured USB interface.

It then builds `wd`, creates fresh temporary client state, and performs the real `wd pair --endpoint <peer-ip:port>` path with the supplied expected fingerprint and pairing secret. Success ends with:

```text
WEDECENT_USB_NCM_PAIR_HARDWARE_OK
```

## Authorized terminal gate

For the full end-to-end gate, provide a short-lived **non-production** connection-grant JWT in a regular file:

```sh
export WEDECENT_USB_NCM_CONNECTION_GRANT_FILE='/secure/path/to/connection-grant.jwt'
bash scripts/test-linux-usb-ncm-hardware.sh
```

The harness then opens the real `wd connect --endpoint` direct-TCP path. The command marker is split in the local input so terminal echo cannot create a false positive; only execution on the remote PTY produces the contiguous expected marker.

Success ends with:

```text
WEDECENT_USB_NCM_TERMINAL_SESSION_HARDWARE_OK
```

## Completion criterion

Mark the USB-networking roadmap parent complete only after a recorded real-hardware run passes the authorized terminal gate. Record hardware/platform, UDC, host NCM interface, and success marker, but do not record pairing-secret or connection-grant contents.
