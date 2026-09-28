const deviceFilter = document.querySelector('#device-filter');
const profileFilter = document.querySelector('#profile-filter');
const deviceCount = document.querySelector('#device-count');
const profileCount = document.querySelector('#profile-count');
const deviceListState = document.querySelector('#device-list-state');
const profileListState = document.querySelector('#profile-list-state');
const transportListState = document.querySelector('#transport-list-state');
const coreStateChip = document.querySelector('#core-state-chip');
const sessionStateChip = document.querySelector('#session-state-chip');
const profileDialog = document.querySelector('#profile-dialog');
const profileDialogForm = document.querySelector('#profile-dialog-form');
const profileDialogTitle = document.querySelector('#profile-dialog-title');
const profileDialogDetail = document.querySelector('#profile-dialog-detail');
const profileDialogName = document.querySelector('#profile-dialog-name');
const profileDialogError = document.querySelector('#profile-dialog-error');
const profileDialogCancel = document.querySelector('#profile-dialog-cancel');
const terminalFontSize = document.querySelector('#terminal-font-size');
const terminalDensity = document.querySelector('#terminal-density');
const terminalPreferencesDetail = document.querySelector('#terminal-preferences-detail');
const uxModel = globalThis.WeDecentUXModel;

if (!uxModel) {
  throw new Error('desktop UX behavior model unavailable');
}

const TERMINAL_PREFERENCES_STORAGE_KEY = 'wedecent.terminalPreferences.v1';

let profileDialogTarget = null;
let profileDialogReturnFocus = null;
let pendingTabFocus = null;
let terminalPreferences = loadTerminalPreferences();

function listEmptyMessage(noun) {
  if (noun === 'devices') {
    return coreHeading.textContent === 'Local Core unavailable'
      ? 'Device inventory is unavailable until Local Core is restored.'
      : 'No known devices are currently exposed by Local Core.';
  }
  return 'No saved profiles. Save a known device to create a local shortcut.';
}

function updateFilteredList(list, input, count, noun, state) {
  const query = uxModel.normalizedFilter(input.value);
  const items = [...list.children];
  let visible = 0;
  for (const item of items) {
    const matches = uxModel.matchesFilter(item.textContent, query);
    item.hidden = !matches;
    if (matches) {
      visible += 1;
    }
  }

  const summary = uxModel.listSummary(items.length, visible, query, noun);
  count.textContent = summary.text;
  count.setAttribute('aria-label', summary.ariaLabel);

  if (items.length === 0) {
    state.textContent = listEmptyMessage(noun);
    state.hidden = false;
  } else if (visible === 0) {
    state.textContent = `No ${noun} match “${input.value.trim()}”.`;
    state.hidden = false;
  } else {
    state.hidden = true;
  }
}

function syncDeviceRows() {
  const devices = [...knownDevices.values()];
  [...deviceList.children].forEach((item, index) => {
    const device = devices[index];
    if (!device) {
      return;
    }
    item.dataset.deviceId = device.id;
    const connect = item.querySelector('.device-connect');
    const save = item.querySelector('.device-save-profile');
    if (connect) {
      connect.setAttribute('aria-label', `Open terminal for ${device.name || device.id}`);
    }
    if (save) {
      save.setAttribute('aria-label', `Save profile for ${device.name || device.id}`);
    }
  });
  updateFilteredList(deviceList, deviceFilter, deviceCount, 'devices', deviceListState);
}

function syncProfileRows() {
  [...profileList.children].forEach((item, index) => {
    const profile = profiles[index];
    if (!profile) {
      return;
    }
    item.dataset.profileId = profile.id;
    const actions = item.querySelector('.profile-actions');
    if (actions && !actions.querySelector('.profile-rename')) {
      const rename = document.createElement('button');
      rename.type = 'button';
      rename.className = 'profile-rename';
      rename.textContent = 'Rename';
      rename.setAttribute('aria-label', `Rename ${profile.label} profile`);
      const remove = [...actions.querySelectorAll('button')].find((button) => button.textContent === 'Delete');
      actions.insertBefore(rename, remove || null);
    }
  });
  updateFilteredList(profileList, profileFilter, profileCount, 'profiles', profileListState);
}

function syncTransportState() {
  transportListState.hidden = transportList.children.length !== 0;
}

function setChip(chip, label, state) {
  chip.textContent = label;
  chip.dataset.state = state;
}

function syncCoreState() {
  const heading = coreHeading.textContent;
  if (heading === 'Local Core connected') {
    setChip(coreStateChip, 'Connected', 'connected');
  } else if (heading === 'Checking status…') {
    setChip(coreStateChip, 'Checking', 'busy');
  } else {
    setChip(coreStateChip, 'Unavailable', 'error');
  }
  syncDeviceRows();
}

function syncSessionState() {
  const heading = terminalHeading.textContent;
  if (heading.startsWith('Connecting to ')) {
    setChip(sessionStateChip, 'Connecting', 'busy');
    return;
  }
  const session = activeSession();
  if (session?.connectionID) {
    setChip(sessionStateChip, 'Connected', 'connected');
    return;
  }
  if (heading === 'No active session' || heading === 'Session disconnected' || heading === 'Session closed') {
    setChip(sessionStateChip, 'Idle', 'idle');
    return;
  }
  setChip(sessionStateChip, 'Attention', 'error');
}

function syncTerminalSemantics() {
  const tabButtons = [...terminalTabs.querySelectorAll('.terminal-tab')];
  const panels = [...terminalStack.querySelectorAll('.terminal')];
  tabButtons.forEach((button, index) => {
    const panel = panels[index];
    if (!panel) {
      return;
    }
    const session = [...sessions.values()].find((entry) => entry.button === button);
    const stableID = session?.tabID || `terminal-tab-fallback-${index + 1}`;
    const buttonID = `${stableID}-button`;
    const panelID = `${stableID}-panel`;
    button.id = buttonID;
    panel.id = panelID;
    button.setAttribute('aria-controls', panelID);
    button.setAttribute('aria-keyshortcuts', 'ArrowLeft ArrowRight Home End Delete');
    button.tabIndex = button.getAttribute('aria-selected') === 'true' ? 0 : -1;
    panel.setAttribute('aria-labelledby', buttonID);
    button.closest('.terminal-tab-wrap')?.setAttribute('role', 'presentation');
  });
  applyTerminalPreferences();
  restorePendingTabFocus();
  syncSessionState();
}

function showProfileDialog(target, title, detail, suggested) {
  profileDialogTarget = target;
  profileDialogReturnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  profileDialogTitle.textContent = title;
  profileDialogDetail.textContent = detail;
  profileDialogName.value = suggested;
  profileDialogError.hidden = true;
  profileDialogError.textContent = '';
  profileDialog.showModal();
  requestAnimationFrame(() => {
    profileDialogName.focus();
    profileDialogName.select();
  });
}

function openSaveProfileDialog(device) {
  const existing = profiles.find((profile) => profile.device_id === device.id);
  showProfileDialog(
    { mode: 'save', device },
    existing ? 'Update session profile' : 'Save session profile',
    'Only this local label and the canonical device ID are persisted.',
    existing?.label || cleanProfileLabel(device.name) || device.id,
  );
}

function openRenameProfileDialog(profile) {
  showProfileDialog(
    { mode: 'rename', profileID: profile.id },
    'Rename session profile',
    'Renaming changes only the local presentation label.',
    profile.label,
  );
}

function commitProfileDialog() {
  const label = cleanProfileLabel(profileDialogName.value);
  if (!label) {
    profileDialogError.textContent = 'Enter at least one printable character.';
    profileDialogError.hidden = false;
    profileDialogName.focus();
    return;
  }

  const previous = profiles;
  if (profileDialogTarget?.mode === 'save') {
    const device = profileDialogTarget.device;
    if (!validDeviceID(device?.id)) {
      profileDialogError.textContent = 'The selected device is no longer valid.';
      profileDialogError.hidden = false;
      return;
    }
    const index = profiles.findIndex((profile) => profile.device_id === device.id);
    if (index < 0 && profiles.length >= MAX_SESSION_PROFILES) {
      profileDialogError.textContent = `Profile limit reached (${MAX_SESSION_PROFILES}).`;
      profileDialogError.hidden = false;
      return;
    }
    const next = {
      id: index >= 0 ? profiles[index].id : createProfileID(),
      label,
      device_id: device.id,
    };
    profiles = index >= 0
      ? profiles.map((profile, profileIndex) => profileIndex === index ? next : profile)
      : [...profiles, next];
  } else if (profileDialogTarget?.mode === 'rename') {
    const index = profiles.findIndex((profile) => profile.id === profileDialogTarget.profileID);
    if (index < 0) {
      profileDialog.close();
      return;
    }
    profiles = profiles.map((profile, profileIndex) => profileIndex === index
      ? { ...profile, label }
      : profile);
  } else {
    profileDialog.close();
    return;
  }

  if (!persistProfiles()) {
    profiles = previous;
    profileDialogError.textContent = 'The profile could not be persisted locally.';
    profileDialogError.hidden = false;
    return;
  }

  renderProfiles();
  profileDialog.close();
}

function terminalTabFromEventTarget(target) {
  return target instanceof Element ? target.closest('.terminal-tab') : null;
}

function moveTabFocus(current, key) {
  const buttons = [...terminalTabs.querySelectorAll('.terminal-tab')];
  const index = buttons.indexOf(current);
  const targetIndex = uxModel.tabTargetIndex(index, key, buttons.length);
  const next = targetIndex >= 0 ? buttons[targetIndex] : null;
  next?.click();
  next?.focus();
}

function rememberTabFocusAfterClose(closeButton) {
  const wraps = [...terminalTabs.querySelectorAll('.terminal-tab-wrap')];
  const wrap = closeButton.closest('.terminal-tab-wrap');
  const index = wraps.indexOf(wrap);
  const targetIndex = uxModel.focusIndexAfterClose(index, wraps.length);
  pendingTabFocus = targetIndex >= 0
    ? wraps.filter((candidate) => candidate !== wrap)[targetIndex]?.querySelector('.terminal-tab') || null
    : null;
}

function restorePendingTabFocus() {
  if (!pendingTabFocus?.isConnected) {
    return;
  }
  const target = pendingTabFocus;
  pendingTabFocus = null;
  target.click();
  target.focus();
}

function loadTerminalPreferences() {
  try {
    return uxModel.parsePreferences(localStorage.getItem(TERMINAL_PREFERENCES_STORAGE_KEY));
  } catch (_) {
    return { ...uxModel.DEFAULT_PREFERENCES };
  }
}

function saveTerminalPreferences() {
  try {
    localStorage.setItem(TERMINAL_PREFERENCES_STORAGE_KEY, uxModel.serializePreferences(terminalPreferences));
    terminalPreferencesDetail.textContent = 'Appearance preferences are stored locally in this desktop and never affect Core session authority or wire dimensions.';
  } catch (_) {
    terminalPreferencesDetail.textContent = 'Appearance changed for this window, but the local preference could not be saved.';
  }
}

function applyTerminalPreferences() {
  for (const session of sessions.values()) {
    if (!session.terminal) {
      continue;
    }
    session.terminal.options.fontSize = terminalPreferences.fontSize;
    session.terminal.options.lineHeight = uxModel.densityLineHeight(terminalPreferences.density);
    if (session.terminal.rows > 0) {
      session.terminal.refresh(0, session.terminal.rows - 1);
    }
  }
}

function syncTerminalPreferenceControls() {
  terminalFontSize.value = String(terminalPreferences.fontSize);
  terminalDensity.value = terminalPreferences.density;
}

function updateTerminalPreferences() {
  terminalPreferences = uxModel.normalizePreferences({
    fontSize: Number(terminalFontSize.value),
    density: terminalDensity.value,
  });
  syncTerminalPreferenceControls();
  saveTerminalPreferences();
  applyTerminalPreferences();
}

deviceFilter.addEventListener('input', () => updateFilteredList(deviceList, deviceFilter, deviceCount, 'devices', deviceListState));
profileFilter.addEventListener('input', () => updateFilteredList(profileList, profileFilter, profileCount, 'profiles', profileListState));
terminalFontSize.addEventListener('change', updateTerminalPreferences);
terminalDensity.addEventListener('change', updateTerminalPreferences);

deviceList.addEventListener('click', (event) => {
  const save = event.target instanceof Element ? event.target.closest('.device-save-profile') : null;
  if (!save) {
    return;
  }
  const item = save.closest('li');
  const device = item?.dataset.deviceId ? knownDevices.get(item.dataset.deviceId) : null;
  if (!device) {
    return;
  }
  event.preventDefault();
  event.stopImmediatePropagation();
  openSaveProfileDialog(device);
}, true);

profileList.addEventListener('click', (event) => {
  const rename = event.target instanceof Element ? event.target.closest('.profile-rename') : null;
  if (!rename) {
    return;
  }
  const item = rename.closest('li');
  const profile = item?.dataset.profileId
    ? profiles.find((candidate) => candidate.id === item.dataset.profileId)
    : null;
  if (profile) {
    openRenameProfileDialog(profile);
  }
});

terminalTabs.addEventListener('click', (event) => {
  const close = event.target instanceof Element ? event.target.closest('.terminal-tab-close') : null;
  if (close) {
    rememberTabFocusAfterClose(close);
  }
}, true);

terminalTabs.addEventListener('keydown', (event) => {
  const tab = terminalTabFromEventTarget(event.target);
  if (!tab) {
    return;
  }
  if (event.key === 'ArrowRight' || event.key === 'ArrowLeft' || event.key === 'Home' || event.key === 'End') {
    event.preventDefault();
    moveTabFocus(tab, event.key);
  } else if (event.key === 'Delete') {
    event.preventDefault();
    tab.closest('.terminal-tab-wrap')?.querySelector('.terminal-tab-close')?.click();
  }
});

profileDialogForm.addEventListener('submit', (event) => {
  event.preventDefault();
  commitProfileDialog();
});
profileDialogCancel.addEventListener('click', () => {
  profileDialog.close();
});
profileDialog.addEventListener('cancel', () => {
  profileDialogTarget = null;
});
profileDialog.addEventListener('close', () => {
  profileDialogTarget = null;
  const returnFocus = profileDialogReturnFocus;
  profileDialogReturnFocus = null;
  if (returnFocus?.isConnected) {
    requestAnimationFrame(() => returnFocus.focus());
  }
});

document.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && !event.shiftKey && event.key.toLocaleLowerCase() === 'k') {
    event.preventDefault();
    deviceFilter.focus();
    deviceFilter.select();
    return;
  }
  if (event.key === 'Escape' && document.activeElement === deviceFilter && deviceFilter.value) {
    deviceFilter.value = '';
    updateFilteredList(deviceList, deviceFilter, deviceCount, 'devices', deviceListState);
  }
});

const deviceObserver = new MutationObserver(syncDeviceRows);
deviceObserver.observe(deviceList, { childList: true });
const profileObserver = new MutationObserver(syncProfileRows);
profileObserver.observe(profileList, { childList: true });
const transportObserver = new MutationObserver(syncTransportState);
transportObserver.observe(transportList, { childList: true });
const coreObserver = new MutationObserver(syncCoreState);
coreObserver.observe(coreHeading, { childList: true });
const terminalObserver = new MutationObserver(syncTerminalSemantics);
terminalObserver.observe(terminalHeading, { childList: true });
terminalObserver.observe(terminalTabs, { childList: true, subtree: true, attributes: true, attributeFilter: ['aria-selected'] });
terminalObserver.observe(terminalStack, { childList: true });

window.addEventListener('DOMContentLoaded', () => {
  syncTerminalPreferenceControls();
  syncDeviceRows();
  syncProfileRows();
  syncTransportState();
  syncCoreState();
  syncTerminalSemantics();
}, { once: true });
