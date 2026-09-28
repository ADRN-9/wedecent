const terminalCursorStyleV3 = document.querySelector('#terminal-cursor-style');
const terminalCursorBlinkV3 = document.querySelector('#terminal-cursor-blink');
const terminalResetAppearanceV3 = document.querySelector('#terminal-reset-appearance');
const focusTerminalButtonV3 = document.querySelector('#focus-terminal');
const uxV3Model = globalThis.WeDecentUXV3Model;

if (!uxV3Model) {
  throw new Error('desktop UX v3 behavior model unavailable');
}

const TERMINAL_CURSOR_STORAGE_KEY_V3 = 'wedecent.terminalCursorPreferences.v1';
let terminalCursorPreferencesV3 = loadTerminalCursorPreferencesV3();

function loadTerminalCursorPreferencesV3() {
  try {
    return uxV3Model.parseCursorPreferences(localStorage.getItem(TERMINAL_CURSOR_STORAGE_KEY_V3));
  } catch (_) {
    return { ...uxV3Model.DEFAULT_CURSOR_PREFERENCES };
  }
}

function saveTerminalCursorPreferencesV3() {
  try {
    localStorage.setItem(
      TERMINAL_CURSOR_STORAGE_KEY_V3,
      uxV3Model.serializeCursorPreferences(terminalCursorPreferencesV3),
    );
    return true;
  } catch (_) {
    return false;
  }
}

function applyTerminalCursorPreferencesV3() {
  for (const session of sessions.values()) {
    uxV3Model.applyCursorPreferences(session.terminal, terminalCursorPreferencesV3);
  }
}

function syncTerminalCursorControlsV3() {
  terminalCursorStyleV3.value = terminalCursorPreferencesV3.cursorStyle;
  terminalCursorBlinkV3.checked = terminalCursorPreferencesV3.cursorBlink;
}

function updateTerminalCursorPreferencesV3() {
  terminalCursorPreferencesV3 = uxV3Model.normalizeCursorPreferences({
    cursorStyle: terminalCursorStyleV3.value,
    cursorBlink: terminalCursorBlinkV3.checked,
  });
  syncTerminalCursorControlsV3();
  const persisted = saveTerminalCursorPreferencesV3();
  terminalPreferencesDetail.textContent = persisted
    ? 'Appearance preferences are stored locally in this desktop and never affect Core session authority or wire dimensions.'
    : 'Appearance changed for this window, but the local preference could not be saved.';
  applyTerminalCursorPreferencesV3();
}

function focusActiveTerminalV3() {
  const session = activeSession();
  if (!session?.terminal) {
    terminalDetail.textContent = 'Open a terminal session before moving focus into the terminal.';
    return false;
  }
  session.terminal.focus();
  return true;
}

function syncFocusTerminalActionV3() {
  const available = Boolean(activeSession()?.terminal);
  focusTerminalButtonV3.disabled = !available;
  focusTerminalButtonV3.setAttribute('aria-disabled', available ? 'false' : 'true');
}

function cycleTerminalTabV3(delta) {
  const buttons = [...terminalTabs.querySelectorAll('.terminal-tab')];
  if (buttons.length === 0) {
    return false;
  }
  const current = buttons.findIndex((button) => button.getAttribute('aria-selected') === 'true');
  const index = uxV3Model.cyclicIndex(current, buttons.length, delta);
  const target = index >= 0 ? buttons[index] : null;
  if (!target) {
    return false;
  }
  target.click();
  requestAnimationFrame(() => focusActiveTerminalV3());
  return true;
}

function resetTerminalAppearanceV3() {
  const fontSize = document.querySelector('#terminal-font-size');
  const density = document.querySelector('#terminal-density');
  fontSize.value = String(globalThis.WeDecentUXModel.DEFAULT_PREFERENCES.fontSize);
  density.value = globalThis.WeDecentUXModel.DEFAULT_PREFERENCES.density;
  fontSize.dispatchEvent(new Event('change', { bubbles: true }));

  terminalCursorPreferencesV3 = { ...uxV3Model.DEFAULT_CURSOR_PREFERENCES };
  syncTerminalCursorControlsV3();
  saveTerminalCursorPreferencesV3();
  applyTerminalCursorPreferencesV3();
  terminalPreferencesDetail.textContent = 'Terminal appearance reset to local defaults.';
  focusTerminalButtonV3.focus();
}

terminalCursorStyleV3.addEventListener('change', updateTerminalCursorPreferencesV3);
terminalCursorBlinkV3.addEventListener('change', updateTerminalCursorPreferencesV3);
terminalResetAppearanceV3.addEventListener('click', resetTerminalAppearanceV3);
focusTerminalButtonV3.addEventListener('click', focusActiveTerminalV3);

document.addEventListener('keydown', (event) => {
  const action = uxV3Model.shortcutAction(event);
  if (action === 'none') {
    return;
  }
  event.preventDefault();
  if (action === 'focus-terminal') {
    focusActiveTerminalV3();
  } else if (action === 'previous-tab') {
    cycleTerminalTabV3(-1);
  } else if (action === 'next-tab') {
    cycleTerminalTabV3(1);
  }
});

const terminalV3Observer = new MutationObserver(() => {
  applyTerminalCursorPreferencesV3();
  syncFocusTerminalActionV3();
});
terminalV3Observer.observe(terminalTabs, { childList: true, subtree: true, attributes: true, attributeFilter: ['aria-selected'] });
terminalV3Observer.observe(terminalHeading, { childList: true });

window.addEventListener('DOMContentLoaded', () => {
  syncTerminalCursorControlsV3();
  applyTerminalCursorPreferencesV3();
  syncFocusTerminalActionV3();
}, { once: true });
