# Linux RFCOMM hardware validation

The Linux RFCOMM implementation is covered by deterministic parser, dialer, listener, CLI-selection, race, and cross-platform build tests. Completing the roadmap item additionally requires a real Bluetooth Classic controller and a second Linux host running `wd-agent` with RFCOMM enabled.

This hardware gate is deliberately not part of GitHub-hosted CI. It must fail rather than silently skip when BlueZ, a powered controller, or the paired peer is unavailable.

## Peer preparation

On the remote Linux host:

1. Pair the two hosts at the Bluetooth/BlueZ layer using the normal OS administration process. Bluetooth pairing is transport setup only; it does not establish WeDecent trust.
2. Start `wd-agent` with an explicit RFCOMM channel (`1` through `30`) using either the existing `--rfcomm-channel` option or its config-file equivalent.
3. Obtain the agent's WeDecent fingerprint from the normal identity command/output.
4. Create a fresh single-use WeDecent pairing secret immediately before the test.

Do not infer the WeDecent identity from the Bluetooth address or from BlueZ pairing state.

## Client gate

On the Linux client host, from the repository root, set:

```sh
export WEDECENT_RFCOMM_PEER_MAC='01:23:45:67:89:AB'
export WEDECENT_RFCOMM_CHANNEL='7'
export WEDECENT_RFCOMM_FINGERPRINT='<expected WeDecent SHA256 fingerprint>'
export WEDECENT_RFCOMM_PAIRING_SECRET='<fresh single-use pairing secret>'
# Optional but recommended: fail if the paired WeDecent device ID differs.
export WEDECENT_RFCOMM_EXPECT_DEVICE_ID='wd_aaaaaaaaaaaaaaaa'
```

Run:

```sh
bash scripts/test-linux-rfcomm-hardware.sh
```

A successful pairing-only hardware run ends with:

```text
WEDECENT_RFCOMM_PAIR_HARDWARE_OK
```

The script uses a fresh temporary client state directory and verifies that the trusted locator persisted by the real pairing path is `rfcomm://...`.

## Authorized terminal gate

For the full transport/session test, provide a short-lived **non-production** connection-grant JWT in a regular file:

```sh
export WEDECENT_RFCOMM_CONNECTION_GRANT_FILE='/secure/path/to/connection-grant.jwt'
bash scripts/test-linux-rfcomm-hardware.sh
```

The script then opens the real `wd connect --rfcomm` path, executes a marker command through the remote PTY, and requires the remote command output—not merely PTY input echo—to contain the marker. Success ends with:

```text
WEDECENT_RFCOMM_TERMINAL_SESSION_HARDWARE_OK
```

The connection grant remains subject to the normal server authorization checks. The harness does not create, weaken, bypass, or synthesize a grant.

## Completion criterion

The roadmap checkbox for the Linux BlueZ RFCOMM adapter should be marked complete only after a recorded run has passed the full authorized terminal gate on two real Linux Bluetooth Classic endpoints. Repository CI without Bluetooth hardware is not sufficient evidence.
