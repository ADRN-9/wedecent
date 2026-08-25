# WeDecent Architecture

## Core invariant

Identity, authorization and terminal encryption must not depend on IP addresses or on the transport used to move bytes.

```text
                    ┌────────────────────────┐
                    │    Terminal session    │
                    │ framing / PTY / resize │
                    └────────────┬───────────┘
                                 │
                    ┌────────────▼───────────┐
                    │ Pinned TLS 1.3 E2EE    │
                    │ Ed25519 device identity│
                    └────────────┬───────────┘
                                 │ net.Conn
              ┌──────────────────┼──────────────────┐
              │                  │                  │
          Direct TCP         Relay tunnel      Future adapters
              │                  │                  │
          LAN/link-local   outbound TCP:443   Bluetooth / USB
```

## Components

### `wd`

Client CLI. Owns a client Ed25519 identity, trusted-device records and terminal UI behavior. A future Tauri/xterm.js desktop application should call the same protocol/session layer.

### `wd-agent`

Runs on the remote system. It owns the device identity and trusted-client list, accepts a direct stream and/or maintains outbound relay slots, and starts the configured local shell attached to a real PTY.

### `wd-relay`

A stateless rendezvous relay. Agents create outbound parked TLS connections. A client asks for a device ID; the relay matches one parked connection and forwards bytes in both directions. Agent registration is challenge-signed by the same Ed25519 key that determines the device ID.

The relay does not participate in the inner WeDecent TLS session and therefore does not possess terminal decryption keys.

## Locators

Current locators:

```text
tcp://192.168.1.50:7443
relay://relay.wedecent.com:443/wd_xxxxxxxxxxxxxxxx
```

Future examples:

```text
bluetooth://<platform-specific-peer>
serial:///dev/ttyACM0
usb://<device-id-or-interface>
```

A locator answers **where/how to attempt a connection**. The pinned public key answers **who the peer is**. These must remain separate concepts.

## Direct-to-relay migration

A later connection manager can rank available locators without changing session semantics:

```text
USB / local serial
    ↓ unavailable
LAN direct
    ↓ unavailable
Bluetooth direct
    ↓ unavailable
Internet P2P / QUIC
    ↓ unavailable
WeDecent relay
```

Because authentication is public-key based, changing the chosen locator does not change device identity.
