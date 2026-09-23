# Windows GUI prototype

## Status

This v0.4.4 development slice adds a native Windows prototype over the Local Core `v1` contract. It is intentionally a UI client, not a networking implementation.

The Windows installer copies `wd-core.exe` and `wd-ui.exe` into the protected Program Files install directory alongside the other release binaries. The installer itself does not create a Local Core service, startup task, Run-key entry, or other per-user autostart mechanism. When `wd-ui` starts, it probes the protected Local Core endpoint and, only when the local transport is unavailable, starts the exact sibling `wd-core.exe` as the same interactive user before opening the UI. While the UI remains active, transport-only Core loss can trigger the same bounded launch path again; this is request-driven recovery, not a machine service or independent watchdog.

## Components

- `internal/coreapi/client` is the typed UI-side Local Core client. It implements the complete `v1.Service` interface and opens one protected local IPC connection for exactly one bounded request/response exchange.
- `internal/guiapp` owns platform-neutral GUI session state. It stores only the public `v1.Connection` returned by Local Core, keeps only device ID/name for the device picker, and addresses terminal operations by the opaque connection ID.
- `cmd/wd-ui` is the native Windows shell. It uses Win32 controls directly and adds no third-party GUI framework or CGO dependency.

The Windows CI job builds `wd-ui.exe` and exercises its `version` command so Windows-only code is compiled on every pull request.

## Security boundary

The GUI never reads trust files, account-session files, route-selection policy, private keys, connection grants, route capabilities, relay tickets, peer locators, fingerprints, or TLS configuration.

All device discovery/status, connection establishment, path selection, authorization, terminal I/O, and disconnect operations go through the existing Local Core API. The GUI can provide only values already allowed by that API, such as a trusted device ID, an opaque Local Core connection ID, terminal bytes, and terminal dimensions.

The typed client uses `localipc.Dial`, so Windows connects to the existing current-user named pipe rather than opening localhost TCP. The pipe name is derived from the current user's SID and the server DACL grants access only to that SID. Each API call has a bounded deadline. Context cancellation forces the local IPC connection deadline forward so a stalled response read is unblocked. Response IDs must exactly match the request ID.

Local Core protocol errors are already sanitized by the server and may be shown using their public message. Local dial, named-pipe, OS, and other transport failures are classified as retryable unavailability without retaining their raw error text in GUI-layer errors.

Core launch and recovery remain narrower than general process supervision:

- `wd-ui` first probes `status.get` over the protected Local Core client.
- A sibling core is started only for the local transport `ErrUnavailable` sentinel. An application-level/protocol error from an already-running core never causes another process launch.
- The launcher resolves the running `wd-ui` executable, follows that image's symlink target, selects only `wd-core.exe` in the same resolved directory, and rejects a sibling that is not a regular file. It never searches `PATH`, invokes `cmd.exe`, uses a shell verb, or requests elevation.
- The child inherits the current user's token and environment. This preserves the existing optional environment-based Core configuration without placing secrets or configuration values on a new command line.
- The child is started without a console window. `wd-ui` waits only for the protected endpoint to become healthy; raw process-start/path/OS failures are not surfaced to the GUI.
- Bootstrap and later recovery use the same bounded eight-second health window with short status probes and bounded retry backoff.
- Concurrent recovery attempts are coalesced so one UI process does not start multiple sibling cores for the same outage. Concurrent GUI processes may still race to launch; the local pipe listener's create-only first handle allows only one core to own the per-user endpoint, and endpoint health wins if another process wins that race.
- Recovery is replay-aware. Status/device reads, disconnect, and terminal resize may retry after recovery because they are read-only or idempotent. `connection.connect` and `terminal.write` are never automatically replayed after transport loss because a missing response cannot prove the first request did not take effect. `terminal.read` remains retried by the existing controller so session-loss handling stays in one place.
- `wd-ui` does not terminate the core when the window exits. The Local Core remains an independent same-user process and can serve other local clients.

Terminal input is bounded before it reaches Local Core. The Win32 edit control retains at most `MaxTerminalChunkBytes - 1` UTF-16 code units, leaving room for the carriage return added by the Send action for ordinary ASCII input. The Send path then checks the actual UTF-8 byte length and rejects any payload above the 32 KiB v1 terminal-write limit; the platform-neutral controller repeats the same byte-length check before copying input into a request. Multibyte text therefore cannot bypass the wire-level bound.

Terminal input is copied before crossing the controller boundary. Encoded IPC request buffers, decoded raw response frames, and copied response-result buffers are overwritten on a best-effort basis after use. As elsewhere in the Go codebase, this is memory hygiene rather than a guarantee of cryptographic zeroization.

## Prototype behavior

The window can:

- bootstrap the same-user Local Core on demand when its protected endpoint is absent;
- relaunch a missing Local Core on a later transport-only outage while preserving the existing protocol/session boundary;
- refresh current Local Core status and trusted devices;
- select one trusted device and request `connection.connect`;
- read bounded terminal output through `terminal.read`;
- send one line of terminal input through `terminal.write`;
- send terminal dimensions through `terminal.resize` after connect and after an interactive window resize;
- request `connection.disconnect`;
- perform a short best-effort disconnect when the window is closed.

Only one interactive connection is represented by the prototype at a time. The platform-neutral controller reserves the local UI session while a connect is in flight so repeated button presses cannot create overlapping GUI sessions.

Natural terminal closure is observed through the terminal stream and clears the controller's active UI session after final buffered output is returned. Idle `terminal.read` calls rely on the Local Core's bounded long-poll behavior and simply issue the next one-request/one-response read when an empty still-open result arrives.

Transient terminal-read outages are retried by the controller with bounded exponential backoff from 250 ms to 2 seconds. On Windows, a local transport `ErrUnavailable` first runs the bounded single-flight Core recovery path; the wrapper then returns the original unavailable result so the controller retains ownership of retry timing and session-loss detection. A sanitized remote `connection_unavailable` response is still treated as a transient application-level condition, but it does not authorize a process launch.

A Local Core process restart necessarily loses its process-local connection table. Once the restarted core authoritatively returns `connection_not_found` for the old opaque connection ID, the controller clears that stale GUI session and returns `ErrSessionLost`; a fresh `connection.connect` can then proceed. `connection_not_found` during an explicit disconnect is treated as completed teardown because there is no remaining core-side session to close.

Terminal output remains bounded after it leaves Local Core. The reader permits only one terminal-data event to wait for the Win32 message loop at a time; it does not request another chunk until the UI acknowledges the previous event. The plain-text output control is capped at about 1 MiB of displayed text and resets to a visible truncation marker before additional output is appended.

## Deliberate limitations

This is not a full terminal emulator. The output control is a plain-text Win32 edit control. Invalid UTF-8 is replaced for display, NUL and ESC bytes are rendered visibly, and ANSI/VT escape sequences are not interpreted. The underlying terminal bytes and Local Core protocol are unchanged.

The prototype does not yet provide account sign-in/sign-out, router policy controls, route visualization, multiple simultaneous terminal tabs, clipboard policy, terminal scrollback persistence, or accessibility-specific terminal semantics.

Recovery is request-driven rather than a permanent watchdog: if no UI call observes the outage, `wd-ui` does not poll solely to keep Core alive. There is still no logon autostart mechanism, installer-owned per-user scheduled task, machine service for Core, or upgrade coordinator that shuts down a running per-user Core before binary replacement. Ambiguous `Connect` and terminal-write transport failures are intentionally not replayed automatically. Those lifecycle and UX choices remain separate decisions.
