# Desktop UX elaboration contract

This document defines the presentation and interaction contract for the Phase 4 Tauri desktop interface. It extends the process/authority boundary in `DESKTOP_SHELL.md` without moving trust, routing, transport, session, or file authority into the renderer.

## Application layout

The desktop interface is organized as a workspace rather than a sequence of independent demo panels:

- a connection sidebar presents sanitized Local Core status, known devices, local session profiles, and informational transport availability;
- the primary workspace owns terminal tabs and active-session presentation;
- file transfer is contextual to the active authenticated Core-owned connection;
- compact and narrow windows reflow the same controls without changing their authority or command surface.

The renderer may search, filter, group, label, and visually summarize already-sanitized data. Filtering never changes the underlying Local Core inventory and never becomes authorization input.

## Interaction states

Presentation distinguishes these states explicitly where relevant:

- idle/unavailable;
- checking/connecting/busy;
- connected/ready;
- completed successfully;
- failed or requiring attention.

These are renderer presentation states derived from existing application results. They are not new connection, trust, transport, or transfer state machines.

Core unavailable behavior remains fail-closed. The UI must not infer a route, retry through an alternate network path, or synthesize a successful state from stale renderer data.

Device, profile, and transport collections must expose explicit empty-state presentation. Filtered device/profile collections distinguish an empty underlying collection from a non-empty collection with zero matching rows. Those status messages are presentation-only and never alter inventory contents.

## Device and profile UX

Known devices remain sourced only from the sanitized Local Core inventory. The desktop may provide local filtering and clearer connect/profile affordances, but it must not expose endpoints, fingerprints, routing data, credentials, grants, or raw transport authority.

Session profiles remain local presentation shortcuts containing only:

- a bounded local label; and
- a canonical device ID.

The desktop provides in-application save/update/rename interaction rather than relying on browser prompt UI. Opening a profile still resolves its target against the current sanitized Core inventory before any Core-owned connection request is made.

Profile dialogs restore focus to the invoking renderer control when that control still exists. Validation errors remain inside the labelled dialog and do not leak persistence or native implementation details.

## Terminal tabs and keyboard behavior

Terminal tabs preserve the existing Core-owned parent/child session model. Presentation adds:

- one active tab in the tab order;
- stable `tab`/`tabpanel` relationships;
- Left/Right Arrow navigation;
- Home/End navigation;
- Delete to close the focused terminal tab;
- visible keyboard focus.

When a focused tab is closed, focus moves deterministically to the next surviving tab, or to the previous tab when the closed tab was last. Keyboard navigation changes only active presentation state. It does not allocate wire stream IDs, select routes/transports, or replay terminal input.

The interface exposes the device-filter shortcut and terminal-tab keyboard commands in the terminal workspace instead of relying on undocumented shortcuts.

## Renderer-only terminal presentation preferences

Terminal appearance preferences are local renderer presentation state only. The supported preference surface is intentionally bounded to:

- a fixed allowlist of terminal font sizes; and
- compact, comfortable, or spacious local line-height presets.

Preferences are versioned and stored only in renderer-local storage. Invalid, unsupported, or stale values fall back to deterministic defaults. Failure to persist a preference does not affect an active secure session; the preference may remain applied for the current window.

Appearance preferences may update xterm presentation options, but they must not change terminal row/column negotiation, resize commands, Core session state, stream identifiers, routing, transport selection, trust, or any native command surface.

## File-transfer UX

File transfer remains behind the fixed native command surface:

- `file_transfer_status`;
- `file_upload_pick`;
- `file_download_pick`.

The renderer may present availability, busy, cancelled, success, and failure states and validate the bounded remote-relative-path format for early feedback. Native code remains authoritative for path validation, operating-system pickers, local paths, local file bytes, operation lifecycle, no-clobber publication, and transfer cancellation/cleanup.

No progress UI should claim byte-level progress until a bounded native/Core progress contract exists. Completion byte counts returned by the native command may be displayed after validation.

## Accessibility and window behavior

The desktop presentation contract includes:

- visible `:focus-visible` treatment;
- semantic status text and state labels;
- keyboard-operable terminal tabs;
- labelled dialogs and form errors;
- explicit live-region empty/no-result collection states;
- valid static label, `aria-labelledby`, `aria-describedby`, and `aria-controls` references;
- no duplicate static element IDs;
- deterministic focus restoration after modal profile editing and tab closure;
- responsive compact layouts;
- reduced-motion handling;
- no color-only dependency for critical state meaning.

Accessibility additions must not require a broader native command surface.

## Build-time regression gates

Canonical desktop asset builds must verify all of the following:

1. the existing renderer authority/file-transfer boundary;
2. the desktop UX presentation/accessibility contract; and
3. deterministic renderer-only behavior tests for filtering/count summaries, terminal keyboard navigation, close-focus selection, and terminal preference normalization/versioning.

The UX presentation controller and pure behavior model must remain free of Tauri invoke calls, direct network APIs, browser file pickers, helper-process names, and trust/routing/wire-stream authority. The controller consumes existing renderer state and DOM only; the pure model has no DOM or native dependencies.

## Deferred interface work

These require separate contracts rather than UI-only implementation:

- local/remote port forwarding;
- richer Bluetooth/USB discovery that changes locator selection behavior;
- transfer progress streaming;
- new trust, pairing, routing-policy, or router-administration controls.

Those surfaces must first define authorization, limits, lifecycle/cancellation, auditing, and renderer-safe data exposure at the Core/native boundary.
