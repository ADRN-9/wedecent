# Terminal session timeout policy

`wd-agent serve` enforces terminal-session lifetime bounds at the authoritative agent session server. The policy applies equally to accepted direct and relay terminal sessions; it does not apply to router-control or route-tunnel connections.

## Defaults and flags

- `--session-idle-timeout=30m` — close an accepted terminal session after 30 minutes without terminal activity.
- `--session-max-duration=12h` — close an accepted terminal session after 12 hours regardless of activity.
- `0` disables the corresponding limit explicitly.

Both durations must be zero or at least one second, may not exceed seven days, and when both are enabled the idle timeout may not exceed the maximum duration. Invalid policy is rejected before the agent starts; the session server also validates the policy defensively before launching a PTY.

## What counts as activity

The idle timer is reset only after successful interactive terminal activity:

- non-empty client terminal data is written to the PTY;
- a terminal resize is successfully applied;
- PTY output is successfully forwarded to the client.

Protocol Ping/Pong traffic does **not** reset the idle timer. Heartbeats therefore cannot keep an otherwise idle shell alive. The maximum-duration timer is never reset.

## Expiry behavior

When either limit expires, the agent closes the PTY and sends the final terminal close frame with exit code `124` and a sanitized reason:

- `session idle timeout`
- `session maximum duration reached`

The policy path bounds final PTY-output draining to 500 ms and bounds the final network write/peer-close phase, so a peer that stops reading cannot keep an expired session alive indefinitely.

Persistent audit records continue to use stable, payload-free close reasons:

- `policy_idle_timeout`
- `policy_max_duration`

Terminal input/output is never copied into audit events or policy logs.

## Scope

Policy is process configuration. Changes require restarting `wd-agent`; already-running sessions retain the policy that was active when their session timers were created. Config-file support is a separate roadmap item; this slice exposes policy through explicit `wd-agent serve` flags only.
