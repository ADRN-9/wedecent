# WeDecent MVP

> **v0.2.1 serverless relay:** the preferred Internet path is now Cloudflare Workers + Durable Objects over secure WebSockets. No VPS and no `cloudflared` daemon are required on either endpoint. See [`docs/CLOUDFLARE_SERVERLESS.md`](docs/CLOUDFLARE_SERVERLESS.md).

## Serverless Internet quick start

Deploy `cloudflare/relay-worker`, add `relay.wedecent.com` as its Custom Domain, and configure the Worker secret `RELAY_ACCESS_TOKEN`. Then on the remote machine:

```bash
export WEDECENT_RELAY_TOKEN='YOUR_PRIVATE_TOKEN'
./bin/wd-agent serve --listen '' --web-relay https://relay.wedecent.com --shell /bin/bash
```

On the client:

```bash
export WEDECENT_RELAY_TOKEN='YOUR_PRIVATE_TOKEN'
./bin/wd pair --web-relay https://relay.wedecent.com --device-id wd_xxxxxxxxxxxxxxxx --fingerprint 'SHA256:...'
./bin/wd connect wd_xxxxxxxxxxxxxxxx
```

The Cloudflare Worker only forwards the **inner TLS 1.3 ciphertext**. Device/client certificate pinning and the one-time pairing flow remain end-to-end between the endpoints.

# WeDecent

WeDecent is a transport-independent secure remote terminal prototype. A device identity is a cryptographic Ed25519 key, not an IP address. The same terminal protocol can therefore be carried over direct LAN connections or an outbound-only relay today, and Bluetooth/USB adapters later.

## What works now

- Linux PTY terminal sessions (`/bin/sh`, `bash`, `zsh`, etc.)
- Direct TCP/LAN connections
- Signed IPv4 multicast LAN discovery
- TLS 1.3 end-to-end encryption with Ed25519 device identities
- SHA-256 SPKI public-key pinning
- Mutual client/device identity after pairing
- 192-bit single-use pairing secrets
- Outbound-only relay mode: the agent can run with **no listening socket**
- Serverless WSS relay via Cloudflare Workers + Durable Objects (`wsrelay://`)
- Relay registration signed by the device key, preventing another key from claiming the same device ID
- Terminal resize and remote exit-code propagation
- Transport locators (`tcp://...`, `relay://...`, `wsrelay://...`) designed for additional transports

## Not implemented yet

- Windows ConPTY agent
- Bluetooth RFCOMM/L2CAP adapter
- USB CDC-ACM / USB gadget adapter
- Desktop GUI/Tauri terminal
- Team accounts, OIDC/SSO, RBAC, audit database
- File transfer and port forwarding
- Production relay rate limiting, multi-region routing, persistence and observability

The current code is an MVP security foundation, not a finished privileged-access product.

## Build

Use Go 1.27.0 or newer within the Go 1.27 release line.

```bash
make test
make build
```

Binaries are written to `./bin`:

- `wd` — client CLI
- `wd-agent` — remote terminal agent
- `wd-relay` — public rendezvous/byte relay

There are no third-party Go dependencies.

Repeatable validation:

```bash
make vet
make test
make smoke-direct
make smoke-relay
```

`smoke-relay` specifically runs the agent with `--listen ''`, proving the terminal works when the remote system has no inbound listening socket.

## Direct LAN quick start

On the remote Linux machine:

```bash
wd-agent init
wd-agent serve --listen 0.0.0.0:7443 --discover --shell /bin/bash
```

`wd-agent init` prints a device ID, a public-key fingerprint and a one-time pairing secret. Keep the secret private.

On the client:

```bash
wd discover
wd pair \
  --endpoint 192.168.1.50:7443 \
  --fingerprint SHA256:<fingerprint-from-agent>
```

The pairing secret is prompted without echo on Linux. Then connect by identity rather than IP:

```bash
wd connect wd_xxxxxxxxxxxxxxxx
```

The saved locator is only a routing hint. Authentication is against the pinned cryptographic identity.

## Outbound-only relay quick start

Point `relay.wedecent.com` at the relay host and install a normal publicly trusted TLS certificate for that hostname.

Run the relay:

```bash
wd-relay \
  --listen :443 \
  --cert /etc/letsencrypt/live/relay.wedecent.com/fullchain.pem \
  --key /etc/letsencrypt/live/relay.wedecent.com/privkey.pem
```

Run the remote agent with no inbound listener:

```bash
wd-agent serve \
  --listen '' \
  --relay relay.wedecent.com:443 \
  --relay-slots 4 \
  --shell /bin/bash
```

Pair from the client using the device ID, device fingerprint and one-time secret obtained out-of-band:

```bash
wd pair \
  --relay relay.wedecent.com:443 \
  --device-id wd_xxxxxxxxxxxxxxxx \
  --fingerprint SHA256:<fingerprint-from-agent>
```

Then:

```bash
wd connect wd_xxxxxxxxxxxxxxxx
```

The path is:

```text
wd client
    │ outer TLS 1.3
    ▼
relay.wedecent.com:443
    │ byte forwarding only
    ▼
agent outbound relay slot

Inside that forwarded stream:

wd client ═════ pinned TLS 1.3 / wedecent/1 ═════ wd-agent
```

The relay can see routing metadata (device ID, connection timing and byte counts) but cannot decrypt terminal frames.

## Security model

1. Every client and agent generates an Ed25519 private key locally.
2. The device ID is deterministically derived from the public key.
3. Self-signed identity certificates are short-lived and automatically renewed while keeping the same key/pin.
4. First pairing requires both the expected device fingerprint and a high-entropy single-use pairing secret.
5. After pairing, the agent only opens a PTY for client public keys in its local trust store.
6. The client pins the agent public key. A malicious LAN host or relay cannot substitute another agent certificate.
7. The remote client cannot choose an executable. The agent operator configures the shell path, avoiding a remote command-string injection API.

### Operational cautions

- Run `wd-agent` as the OS account whose shell access you intend to expose. Do not run it as root unless root terminal access is explicitly required.
- Protect the agent/client state directories. Private identity keys are permissioned `0600` but are not TPM/keychain-backed yet.
- Do not expose the MVP relay as a large public service without adding per-IP/device rate limiting, metrics and abuse controls.
- Signed LAN discovery proves that an advertisement owns the advertised key; it does **not** make an unpaired key trusted.
- A normal USB-C cable between two PCs usually connects two USB hosts and is not itself a serial link. USB terminal transport requires USB gadget/device support, a USB networking mode, or an appropriate adapter.

See `docs/PROTOCOL.md`, `docs/ARCHITECTURE.md`, `docs/DOMAIN.md`, and `docs/ROADMAP.md`.
