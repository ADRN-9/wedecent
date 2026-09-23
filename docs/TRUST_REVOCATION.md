# Terminal trust revocation

WeDecent keeps terminal pairing trust in two independent local stores:

- the client stores trusted remote devices in `trusted-devices.json`;
- the agent stores authorized terminal clients in `trusted-clients.json`.

These files are separate from source-to-router route trust and from the dedicated router-admin controller trust store. Revoking terminal trust does not change either of those other authorization domains.

## Remove a device from a client

List the client's currently paired devices:

```text
wd devices
```

Remove one exact device identity from the client's local trust store:

```text
wd unpair <device-id>
```

`wd unpair` removes only the local device pin and locator. It does not contact the remote device and does not remove this client's authorization from the remote agent.

## Revoke a terminal client on an agent

List clients paired for terminal access:

```text
wd-agent clients list
```

Revoke one exact client identity:

```text
wd-agent clients revoke <client-id>
```

The running agent refreshes terminal trust from `trusted-clients.json` for every new session authorization, so a successful revoke takes effect for new direct and relay sessions without restarting `wd-agent`.

Revocation is not an active-session kill mechanism. A terminal session that was fully established before the trust entry was removed continues until it closes normally or is terminated through another lifecycle mechanism. New sessions from the revoked identity are rejected.

For bidirectional trust removal, perform both operations: unpair the device on the client and revoke the client on the agent.

## Concurrent pairing and revocation

Trust-file mutations use a dedicated `<store>.lock` file plus an OS-backed exclusive file lock. Each writer reloads the latest trust file while holding that lock before changing it. This prevents separate pairing and revocation processes from silently replacing one another's newer snapshot.

The lock file contains no peer records, fingerprints, pairing secrets, account credentials, or bearer tokens. It may remain on disk after a command exits; the operating system releases the actual lock when the owning handle closes or the process terminates.

Malformed device IDs are rejected before a trust store or lock file is mutated. Trust files and lock files reject symbolic-link indirection, and trust-file reads fail closed when a refreshed file cannot be parsed.
