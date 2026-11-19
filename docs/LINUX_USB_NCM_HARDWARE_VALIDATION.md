# Linux USB NCM hardware validation

This is a real-hardware gate, not a CI smoke test. It validates the host-side USB NCM network interface, the route to the WeDecent peer, pinned Ed25519/TLS pairing, single-use secret rejection, and an authorized remote terminal session over direct TCP carried by USB NCM.

## Required topology

- A Linux gadget-side device with a USB Device Controller and configfs NCM support.
- A USB cable connecting that gadget to a Linux client host.
- The gadget configured with `scripts/wedecent-linux-usb-ncm.sh`.
- The client host enumerating a real USB network interface bound to Linux `cdc_ncm`.
- An agent bound to the gadget-side NCM address and running the ordinary WeDecent TLS 1.3/pinned-identity path.

A USB network interface, MAC address, VID/PID, IP address, or cable connection is not WeDecent identity. Obtain the expected WeDecent fingerprint independently from the target agent.

## Prepare the gadget

Follow [Linux USB NCM networking](LINUX_USB_NCM.md). Configure the point-to-point IP addresses using the site's network manager, and bind `wd-agent serve` only to the intended gadget-side address for the isolated test. With `--direct-tcp-underlay usb_ncm`, that listener address must be a specific non-loopback NCM IP; wildcard, loopback, and DNS listen addresses are rejected.

## Client hardware gate

On the Linux client, from the repository root, set:

```sh
export WEDECENT_USB_NCM_INTERFACE='enx020000000002'
export WEDECENT_USB_NCM_ENDPOINT='192.0.2.1:7443'
export WEDECENT_USB_NCM_FINGERPRINT='SHA256:<independently-verified-fingerprint>'
export WEDECENT_USB_NCM_PAIRING_SECRET_FILE='/secure/path/pairing-secret.txt'
export WEDECENT_USB_NCM_CONNECTION_GRANT_FILE='/secure/path/first-grant.jwt'
export WEDECENT_USB_NCM_TERMINAL_INPUT_FILE='/secure/path/terminal-input.txt'
export WEDECENT_USB_NCM_TERMINAL_MARKER='WEDECENT_USB_NCM_REMOTE_COMMAND_OK'
export WEDECENT_USB_NCM_RECONNECT_CONNECTION_GRANT_FILE='/secure/path/reconnect-grant.jwt'
export WEDECENT_USB_NCM_RECONNECT_INPUT_FILE='/secure/path/reconnect-input.txt'
export WEDECENT_USB_NCM_RECONNECT_MARKER='WEDECENT_USB_NCM_RECONNECTED_OK'
export WEDECENT_USB_NCM_EXPECT_COMMIT='<full-40-character-clean-commit-sha>'
export WEDECENT_USB_NCM_EXPECT_SOURCE_SHA256='<64-character-git-archive-sha256>'
# Optional expected device ID:
export WEDECENT_USB_NCM_EXPECT_DEVICE_ID='wd_aaaaaaaaaaaaaaaa'
```

The interface must be up, resolve to a USB sysfs device, have USB vendor/product ancestry, and use the Linux `cdc_ncm` driver. The numeric peer endpoint must route through that exact interface. DNS names are rejected.

Before running, obtain the pairing secret from the target agent through a secure out-of-band channel and place it in a private file owned by the client user (mode 0600 or stricter). Do not put the secret in an environment variable or command-line argument. For example, on the agent, write the output of `wd-agent pairing-secret --state <agent-state>` directly to a protected file and transfer that file securely. The client reads it through `--pairing-secret-file`, which rejects symlinks, non-regular files, unsafe permissions, and incorrect ownership.

Both connection-grant files must be private, current-user-owned, non-symlink files containing different short-lived JWTs. The harness rejects identical grant contents before pairing. The server remains authoritative for grant signature, expiry, audience, permission, and replay validation.

Create two terminal input files that print their respective markers remotely and then exit. Neither marker may appear contiguously in its input file.

Run only after all required files and environment variables are prepared:

```sh
bash scripts/test-linux-usb-ncm-hardware.sh
```

The harness builds the real client, derives a valid but incorrect fingerprint and requires the precise `device fingerprint mismatch` rejection, completes pairing using the private single-use secret file, then uses a second client state and requires the precise `invalid or already consumed pairing secret` rejection on replay. It emits:

- `WEDECENT_USB_NCM_WRONG_FINGERPRINT_REJECTED`
- `WEDECENT_USB_NCM_PAIR_HARDWARE_OK`
- `WEDECENT_USB_NCM_REPLAY_REJECTED`

For each transport, separately verify that an explicitly selected transport failure is surfaced without falling back while an alternate route to the same peer is available. The hardware gate is incomplete until this is recorded on the actual endpoint.

## Authorized terminal and reconnect gates

Authorized terminal execution and reconnection are mandatory acceptance conditions, not optional extensions. The harness fails before pairing if either grant, either input file, or either marker is missing. It also rejects reuse of the first grant for reconnection.

The first terminal command must print `WEDECENT_USB_NCM_REMOTE_COMMAND_OK` remotely and exit successfully. Its input file must not contain that marker contiguously, so local/PTY echo cannot satisfy the assertion. The first `wd connect` must finish and close before the second command is attempted.

The second command must use the separate fresh reconnect grant, print `WEDECENT_USB_NCM_RECONNECTED_OK` remotely, and exit successfully. It emits `WEDECENT_USB_NCM_RECONNECT_HARDWARE_OK`.

The script emits `WEDECENT_USB_NCM_ACCEPTANCE_COMPLETE` only after both authorized sessions and all negative pairing checks succeed. Incomplete acceptance never exits successfully.

The harness never creates or weakens a connection grant. Do not put pairing secrets, grant contents, private keys, or terminal payloads in evidence logs.

## Evidence to retain

For each run, record the exact WeDecent commit SHA, Linux distribution/kernel, gadget and client hardware models, USB controller/UDC, host interface and cdc_ncm driver, sanitized endpoint, independently verified device fingerprint, pairing result, remote marker result, reconnect result, incorrect-fingerprint result, replay result, and sanitized logs. Redact IPs if required by the deployment, but do not redact the cryptographic fingerprint needed to independently correlate the device.

## Completion criterion

Do not mark USB NCM complete because the helper or script succeeds on a simulated interface. A real USB gadget/host pair must enumerate, the route must use the verified NCM interface, pairing and replay rejection must succeed, the remote command marker must be returned by the PTY, and a second authorized session must reconnect after the first disconnects.
