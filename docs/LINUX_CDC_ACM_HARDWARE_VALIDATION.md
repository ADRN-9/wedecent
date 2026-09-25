# Linux USB CDC-ACM hardware validation

The Linux CDC-ACM implementation is covered by deterministic serial-device, locator, CLI-selection, agent-lifecycle, PTY, race, and cross-platform build tests. Completing the roadmap item additionally requires a real USB device/gadget link that exposes the WeDecent agent as a CDC-ACM tty on the Linux client.

This hardware gate is deliberately not part of GitHub-hosted CI. It fails rather than silently skips when the configured endpoint is absent, is a symlink, is not a character device, or lacks USB device ancestry in sysfs.

A normal passive USB cable between two ordinary USB-host PCs is not enough. The remote side must support USB device/gadget/dual-role mode and expose a CDC-ACM function, or otherwise present a genuine CDC-ACM device to the client.

## Peer preparation

On the remote/gadget Linux host:

1. Configure a CDC-ACM USB gadget using the platform's normal administration mechanism. The gadget-side tty is typically `/dev/ttyGS0`; exact naming is platform-specific.
2. Start `wd-agent` with `--listen=` and `--serial <gadget-side-tty>` (plus any other desired transports). Serial transport setup does not establish WeDecent trust.
3. Obtain the agent's WeDecent fingerprint from the normal identity command/output.
4. Create a fresh single-use WeDecent pairing secret immediately before the test.
5. Confirm that the Linux client enumerates the peer as a real `/dev/ttyACM*` device.

Do not infer WeDecent identity from USB vendor/product identifiers, serial numbers, tty names, or physical possession of the cable.

## Client pairing gate

On the Linux client, from the repository root, set:

```sh
export WEDECENT_SERIAL_DEVICE='/dev/ttyACM0'
export WEDECENT_SERIAL_FINGERPRINT='<expected WeDecent SHA256 fingerprint>'
export WEDECENT_SERIAL_PAIRING_SECRET='<fresh single-use pairing secret>'
# Optional but recommended: fail if the paired WeDecent device ID differs.
export WEDECENT_SERIAL_EXPECT_DEVICE_ID='wd_aaaaaaaaaaaaaaaa'
```

Run:

```sh
bash scripts/test-linux-cdc-acm-hardware.sh
```

The harness first proves that the configured tty is a non-symlink character device with detectable USB ancestry in sysfs. A successful pairing-only run ends with:

```text
WEDECENT_CDC_ACM_PAIR_HARDWARE_OK
```

The test uses a fresh temporary client state directory and verifies that the real pairing path persists a `serial:///dev/...` locator.

## Authorized terminal gate

For the full transport/session test, provide a short-lived **non-production** connection-grant JWT in a regular file:

```sh
export WEDECENT_SERIAL_CONNECTION_GRANT_FILE='/secure/path/to/connection-grant.jwt'
bash scripts/test-linux-cdc-acm-hardware.sh
```

The harness then opens the real `wd connect --serial` path, executes a marker command through the remote PTY, and requires command output—not merely terminal input echo—to contain the marker. Success ends with:

```text
WEDECENT_CDC_ACM_TERMINAL_SESSION_HARDWARE_OK
```

The connection grant remains subject to the normal server authorization checks. The harness does not create, weaken, bypass, or synthesize a grant.

## Completion criterion

The USB CDC-ACM serial-adapter roadmap checkbox should be marked complete only after a recorded run has passed the full authorized terminal gate over real USB CDC-ACM endpoints. PTYs and repository CI are useful regression coverage but are not hardware evidence.
