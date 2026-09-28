(function attachUXV3Model(root) {
  const CURSOR_STYLES = Object.freeze(['block', 'underline', 'bar']);
  const DEFAULT_CURSOR_PREFERENCES = Object.freeze({ cursorStyle: 'block', cursorBlink: true });

  function normalizeCursorPreferences(value) {
    return {
      cursorStyle: CURSOR_STYLES.includes(value?.cursorStyle)
        ? value.cursorStyle
        : DEFAULT_CURSOR_PREFERENCES.cursorStyle,
      cursorBlink: typeof value?.cursorBlink === 'boolean'
        ? value.cursorBlink
        : DEFAULT_CURSOR_PREFERENCES.cursorBlink,
    };
  }

  function parseCursorPreferences(raw) {
    if (typeof raw !== 'string' || !raw) {
      return { ...DEFAULT_CURSOR_PREFERENCES };
    }
    try {
      const parsed = JSON.parse(raw);
      if (parsed?.version !== 1) {
        return { ...DEFAULT_CURSOR_PREFERENCES };
      }
      return normalizeCursorPreferences(parsed);
    } catch (_) {
      return { ...DEFAULT_CURSOR_PREFERENCES };
    }
  }

  function serializeCursorPreferences(value) {
    return JSON.stringify({ version: 1, ...normalizeCursorPreferences(value) });
  }

  function shortcutAction(event) {
    const key = typeof event?.key === 'string' ? event.key : '';
    if (event?.altKey && !event?.ctrlKey && !event?.metaKey && !event?.shiftKey && key.toLocaleLowerCase() === 't') {
      return 'focus-terminal';
    }
    if ((event?.ctrlKey || event?.metaKey) && !event?.altKey && !event?.shiftKey && key === 'PageUp') {
      return 'previous-tab';
    }
    if ((event?.ctrlKey || event?.metaKey) && !event?.altKey && !event?.shiftKey && key === 'PageDown') {
      return 'next-tab';
    }
    return 'none';
  }

  function cyclicIndex(index, count, delta) {
    if (!Number.isInteger(index) || !Number.isInteger(count) || !Number.isInteger(delta) || count <= 0) {
      return -1;
    }
    const normalized = index >= 0 && index < count ? index : 0;
    return (normalized + delta + count) % count;
  }

  function applyCursorPreferences(terminal, value) {
    if (!terminal?.options) {
      return false;
    }
    const preferences = normalizeCursorPreferences(value);
    terminal.options.cursorStyle = preferences.cursorStyle;
    terminal.options.cursorBlink = preferences.cursorBlink;
    if (Number.isInteger(terminal.rows) && terminal.rows > 0 && typeof terminal.refresh === 'function') {
      terminal.refresh(0, terminal.rows - 1);
    }
    return true;
  }

  root.WeDecentUXV3Model = Object.freeze({
    CURSOR_STYLES,
    DEFAULT_CURSOR_PREFERENCES,
    normalizeCursorPreferences,
    parseCursorPreferences,
    serializeCursorPreferences,
    shortcutAction,
    cyclicIndex,
    applyCursorPreferences,
  });
})(globalThis);
