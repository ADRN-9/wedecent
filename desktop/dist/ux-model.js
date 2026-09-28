(function attachUXModel(root) {
  const FONT_SIZES = Object.freeze([12, 14, 16, 18, 20]);
  const DENSITIES = Object.freeze({
    compact: 1.0,
    comfortable: 1.2,
    spacious: 1.4,
  });
  const DEFAULT_PREFERENCES = Object.freeze({ fontSize: 14, density: 'comfortable' });

  function normalizedFilter(value) {
    return typeof value === 'string' ? value.trim().toLocaleLowerCase() : '';
  }

  function matchesFilter(text, query) {
    const normalized = normalizedFilter(query);
    return !normalized || String(text ?? '').toLocaleLowerCase().includes(normalized);
  }

  function listSummary(total, visible, query, noun) {
    const normalized = normalizedFilter(query);
    return {
      text: normalized ? `${visible}/${total}` : String(total),
      ariaLabel: normalized
        ? `${visible} of ${total} ${noun}`
        : `${total} ${noun}`,
    };
  }

  function tabTargetIndex(index, key, count) {
    if (!Number.isInteger(index) || !Number.isInteger(count) || count <= 0 || index < 0 || index >= count) {
      return -1;
    }
    if (key === 'ArrowRight') {
      return (index + 1) % count;
    }
    if (key === 'ArrowLeft') {
      return (index - 1 + count) % count;
    }
    if (key === 'Home') {
      return 0;
    }
    if (key === 'End') {
      return count - 1;
    }
    return index;
  }

  function focusIndexAfterClose(index, count) {
    if (!Number.isInteger(index) || !Number.isInteger(count) || count <= 1 || index < 0 || index >= count) {
      return -1;
    }
    return Math.min(index, count - 2);
  }

  function normalizePreferences(value) {
    const fontSize = FONT_SIZES.includes(Number(value?.fontSize))
      ? Number(value.fontSize)
      : DEFAULT_PREFERENCES.fontSize;
    const density = Object.hasOwn(DENSITIES, value?.density)
      ? value.density
      : DEFAULT_PREFERENCES.density;
    return { fontSize, density };
  }

  function parsePreferences(raw) {
    if (typeof raw !== 'string' || !raw) {
      return { ...DEFAULT_PREFERENCES };
    }
    try {
      const parsed = JSON.parse(raw);
      if (parsed?.version !== 1) {
        return { ...DEFAULT_PREFERENCES };
      }
      return normalizePreferences(parsed);
    } catch (_) {
      return { ...DEFAULT_PREFERENCES };
    }
  }

  function serializePreferences(value) {
    const normalized = normalizePreferences(value);
    return JSON.stringify({ version: 1, ...normalized });
  }

  function densityLineHeight(value) {
    return DENSITIES[normalizePreferences({ density: value }).density];
  }

  root.WeDecentUXModel = Object.freeze({
    FONT_SIZES,
    DENSITIES,
    DEFAULT_PREFERENCES,
    normalizedFilter,
    matchesFilter,
    listSummary,
    tabTargetIndex,
    focusIndexAfterClose,
    normalizePreferences,
    parsePreferences,
    serializePreferences,
    densityLineHeight,
  });
})(globalThis);
