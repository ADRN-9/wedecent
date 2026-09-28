# Desktop UX hardening v3

This document defines the third-pass desktop presentation hardening layered on `DESKTOP_UX.md`. It remains renderer-only and does not expand trust, routing, transport, session, terminal-dimension, file, or native-command authority.

## Terminal ergonomics

The desktop exposes two additional keyboard paths for already-open terminal tabs:

- `Ctrl/Cmd+PageUp` and `Ctrl/Cmd+PageDown` cycle the active renderer tab;
- `Alt+T` moves focus into the active xterm instance.

The same focus-terminal action is available as a visible button. Cycling changes only renderer selection and then focuses the already-created terminal. It does not allocate a stream, reconnect, select a route, resize the terminal, or replay input.

Profile filtering mirrors device filtering recovery: when the profile search field owns focus, `Escape` clears a non-empty query and re-renders the local filtered view.

## Terminal presentation preferences

The existing bounded font-size and line-height preferences are extended with renderer-only cursor presentation:

- cursor shape: block, underline, or bar;
- cursor blink: on or off;
- reset appearance to deterministic defaults.

Cursor settings are versioned in renderer-local storage and are applied only to xterm presentation options. Invalid or stale values fall back to block + blinking. Resetting appearance updates only renderer-local font, line-height, and cursor settings.

These controls must never change terminal rows/columns, invoke resize, create or close a Core session, allocate a stream, choose a route or transport, or change trust state.

## High-contrast and window resilience

Presentation must remain usable under operating-system forced-colors/high-contrast modes and in short desktop windows. The v3 layer therefore requires:

- `forced-colors: active` treatment that retains visible borders, focus, selected tabs, and state labels without depending on custom colors;
- `prefers-contrast: more` treatment with stronger borders and text contrast;
- a short-window layout that reduces terminal minimum height without hiding the terminal or sidebar controls;
- the existing narrow-window reflow and reduced-motion behavior to continue to apply.

These are CSS-only presentation changes.

## Regression gates

Desktop asset builds must additionally verify:

1. syntax for the v3 model/controller;
2. deterministic cursor-preference normalization/versioning;
3. explicit shortcut classification and cyclic tab selection;
4. presentation-only mutation of xterm cursor options without changing rows/columns;
5. required forced-colors, contrast, and short-window CSS;
6. v3 script ordering after the established UX controller and before file-transfer presentation;
7. absence of Tauri invoke, network, file-picker, trust, routing, stream-authority, resize, or Core lifecycle calls in the v3 presentation layer.

The v3 implementation is additive. Existing renderer file-transfer and UX boundary checks remain mandatory.

## Deferred work

This milestone does not authorize port-forwarding UI, richer transport enumeration, trust/pairing administration, byte-stream transfer progress, or other surfaces that require new Core/native contracts.
