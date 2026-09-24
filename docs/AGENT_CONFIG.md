# Agent serve configuration

`wd-agent serve` accepts an optional strict JSON configuration file through `--config`.

Configuration precedence is:

1. built-in defaults
2. values from the JSON file
3. explicitly supplied command-line flags

That keeps existing CLI invocations compatible while allowing production services to keep stable listener, relay, routing, and session-policy settings in a file.

Example:

```json
{
  "state": "/var/lib/wedecent",
  "name": "workstation-01",
  "listen": "0.0.0.0:7443",
  "shell": "/bin/bash",
  "discover": true,
  "max_connections": 32,
  "session_idle_timeout": "30m",
  "session_max_duration": "12h",
  "web_relay": "https://relay.wedecent.com",
  "relay_slots": 4,
  "authorization_url": "https://relay.wedecent.com",
  "route_control_listen": "",
  "route_control_transport": "internet",
  "route_tunnel_listen": "",
  "route_tunnel_transport": "internet",
  "route_max_connections": 64
}
```

Run it with:

```bash
wd-agent serve --config /etc/wedecent/agent.json
```

An explicit flag overrides the file:

```bash
wd-agent serve \
  --config /etc/wedecent/agent.json \
  --listen 127.0.0.1:7443 \
  --discover=false
```

## Supported keys

Every current `wd-agent serve` setting has a JSON equivalent:

| JSON key | CLI flag | Type |
| --- | --- | --- |
| `state` | `--state` | string |
| `name` | `--name` | string |
| `listen` | `--listen` | string |
| `shell` | `--shell` | string |
| `discover` | `--discover` | boolean |
| `max_connections` | `--max-connections` | integer |
| `session_idle_timeout` | `--session-idle-timeout` | Go duration string |
| `session_max_duration` | `--session-max-duration` | Go duration string |
| `relay` | `--relay` | string |
| `web_relay` | `--web-relay` | string |
| `relay_slots` | `--relay-slots` | integer |
| `relay_ca` | `--relay-ca` | string |
| `relay_server_name` | `--relay-server-name` | string |
| `authorization_url` | `--authorization-url` | string |
| `route_control_listen` | `--route-control-listen` | string |
| `route_control_transport` | `--route-control-transport` | `lan` or `internet` |
| `route_tunnel_listen` | `--route-tunnel-listen` | string |
| `route_tunnel_transport` | `--route-tunnel-transport` | `lan` or `internet` |
| `route_max_connections` | `--route-max-connections` | integer |

Duration values use the same syntax as the CLI, for example `"30m"`, `"12h"`, or `"0s"` to disable a limit.

## Validation and security behavior

The config loader intentionally fails closed:

- unknown JSON keys are rejected;
- malformed JSON and multiple top-level JSON values are rejected;
- the file must be a regular file and at most 64 KiB;
- symbolic-link config paths are rejected;
- on POSIX systems, group- or world-writable config files are rejected;
- duplicate `--config` arguments are rejected;
- after expansion, the existing `wd-agent serve` parser performs the same transport, connection-limit, routing-transport, and session-policy validation used for CLI-only startup.

The config file is configuration, not a secret store. Do not put private keys, pairing secrets, relay credentials, or other secret material in it. Identity keys and trust state remain in their existing protected state directories.

Config loading happens before agent identity loading, listener creation, relay startup, or other network activity. An invalid config therefore cannot leave a partially started agent behind.
