# Windows GUI prototype

## Status

This v0.4.4 development slice adds a native Windows prototype over the Local Core `v1` contract. It is intentionally a UI client, not a networking implementation.

The Windows installer copies `wd-core.exe` and `wd-ui.exe` into the protected Program Files install directory alongside the other release binaries, but it does not autostart or supervise either process. `wd-core` must already be running as the same interactive user before `wd-ui` can connect to its protected Local Core endpoint.

## Components

- `internal/coreapi/client` is the typed UI-side Local Core client. It implements the complete `v1.Service` interface and opens one protected local IPC connection for exactly one bounded request/response exchange.
- `internal/guiapp` owns platform-neutral GUI session state. It stores only the public `v1.Connection` returned by Local Core, keeps only device ID/name for the device picker, and addresses terminal operations by the opaque connection ID.
- `cmd/wd-ui` is the native Windows shell. It uses Win32 controls directly and adds no third-party GUI framework or CGO dependency.

The Windows CI job builds `wd-ui.exe` and exercises its `version` command so Windows-only code is compiled on every pull request.

## Security boundary

The GUI never reads trust files, account-session files, route-selection policy, private keys, connection grants, route capabilities, relay tickets, peer locators, fingerprints, or TLS configuration.

All device discovery/status, connection establishment, path selection, authorization, terminal I/O, and disconnect operations go through the existing Local Core API. The GUI can provide only values already allowed by that API, such as a trusted device ID, an opaque Local Core connection ID, terminal bytes, and terminal dimensions.

The typed client uses `localipc.Dial`, so Windows connects to the existing current-user named pipe rather than opening localhost TCP. Each call has a bounded deadline. Context cancellation forces the local IPC connection deadline forward so a stalled response read is unblocked. Response IDs must exactly match the request ID.

Local Core protocol errors are already sanitized by the server and may be shown using their public message. Local dial, named-pipe, OS, and other transport failures are classified as retryable unavailability without retaining their raw error text in GUI-layer errors.

Terminal input is bounded before it reaches Local Core. The Win32 edit control retains at most `MaxTerminalChunkBytes - 1` UTF-16 code units, leaving room for the carriage return added by the Send action for ordinary ASCII input. The Send path then checks the actual UTF-8 byte length and rejects any payload above the 32 KiB v1 terminal-write limit; the platform-neutral controller repeats the same byte-length check before copying input into a request. Multibyte text therefore cannot bypass the wire-level bound.

Terminal input is copied before crossing the controller boundary. Encoded IPC request buffers, decoded raw response frames, and copied response-result buffers are overwritten on a best-effort basis after use. As elsewhere in the Go codebase, this is memory hygiene rather than a guarantee of cryptographic zeroization.

## Prototype behavior

The window can:

- refresh current Local Core status and trusted devices;
- select one trusted device and request `connection.connect`;
- read bounded terminal output through `terminal.read`;
- send one line of terminal input through `terminal.write`;
- send terminal dimensions through `terminal.resize` after connect and after an interactive window resize;
- request `connection.disconnect`;
- perform a short best-effort disconnect when the window is closed.

Only one interactive connection is represented by the prototype at a time. The platform-neutral controller reserves the local UI session while a connect is in flight so repeated button presses cannot create overlapping GUI sessions.

Natural terminal closure is observed through the terminal stream and clears the controller's active UI session after final buffered output is returned. Idle `terminal.read` calls rely on the Local Core's bounded long-poll behavior and simply issue the next one-request/one-response read when an empty still-open result arrives.

Transient Local Core outages are retried by the controller with bounded exponential backoff from 250 ms to 2 seconds. A missing pipe, temporary IPC read/write failure, or `connection_unavailable` response therefore does not erase the GUI's active opaque connection ID. If Local Core comes back with the same in-memory session still available, terminal reads resume.

A Local Core process restart necessarily loses its process-local connection table. Once the restarted core authoritatively returns `connection_not_found` for the old opaque connection ID, the controller clears that stale GUI session and returns `ErrSessionLost`; a fresh `connection.connect` can then proceed. `connection_not_found` during an explicit disconnect is treated as completed teardown because there is no remaining core-side session to close.

Terminal output remains bounded after it leaves Local Core. The reader permits only one terminal-data event to wait for the Win32 message loop at a time; it does not request another chunk until the UI acknowledges the previous event. The plain-text output control is capped at about 1 MiB of displayed text and resets to a visible truncation marker before additional output is appended.

## Deliberate limitations

This is not a full terminal emulator. The output control is a plain-text Win32 edit control. Invalid UTF-8 is replaced for display, NUL and ESC bytes are rendered visibly, and ANSI/VT escape sequences are not interpreted. The underlying terminal bytes and Local Core protocol are unchanged.

The prototype does not yet provide account sign-in/sign-out, router policy controls, route visualization, multiple simultaneous terminal tabs, clipboard policy, terminal scrollback persistence, or accessibility-specific terminal semantics.

The installer now handles binary distribution and rollback, but it still does not decide per-user startup, process supervision, automatic core launch, or crash-restart supervision. This lifecycle behavior only defines how an already-running GUI reacts when its separately managed Local Core endpoint is temporarily unavailable or restarted.
