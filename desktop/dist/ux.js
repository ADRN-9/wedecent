const deviceFilter = document.querySelector('#device-filter');
const profileFilter = document.querySelector('#profile-filter');
const deviceCount = document.querySelector('#device-count');
const profileCount = document.querySelector('#profile-count');
const coreStateChip = document.querySelector('#core-state-chip');
const sessionStateChip = document.querySelector('#session-state-chip');
const profileDialog = document.querySelector('#profile-dialog');
const profileDialogForm = document.querySelector('#profile-dialog-form');
const profileDialogTitle = document.querySelector('#profile-dialog-title');
const profileDialogDetail = document.querySelector('#profile-dialog-detail');
const profileDialogName = document.querySelector('#profile-dialog-name');
const profileDialogError = document.querySelector('#profile-dialog-error');
const profileDialogCancel = document.querySelector('#profile-dialog-cancel');

let profileDialogTarget = null;

function normalizedFilter(value) {
  return typeof value === 'string' ? value.trim().toLocaleLowerCase() : '';
}

function updateFilteredList(list, input, count, noun) {
  const query = normalizedFilter(input.value);
  const items = [...list.children];
  let visible = 0;
  for (const item of items) {
    const matches = !query || item.textContent.toLocaleLowerCase().includes(query);
    item.hidden = !matches;
    if (matches) {
      visible += 1;
    }
  }
  count.textContent = query ? `${visible}/${items.length}` : String(items.length);
  count.setAttribute('aria-label', query
    ? `${visible} of ${items.length} ${noun}`
    : `${items.length} ${noun}`);
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
  updateFilteredList(deviceList, deviceFilter, deviceCount, 'devices');
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
  updateFilteredList(profileList, profileFilter, profileCount, 'profiles');
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
    button.tabIndex = button.getAttribute('aria-selected') === 'true' ? 0 : -1;
    panel.setAttribute('aria-labelledby', buttonID);
    button.closest('.terminal-tab-wrap')?.setAttribute('role', 'presentation');
  });
  syncSessionState();
}

function showProfileDialog(target, title, detail, suggested) {
  profileDialogTarget = target;
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
  profileDialogTarget = null;
}

function terminalTabFromEventTarget(target) {
  return target instanceof Element ? target.closest('.terminal-tab') : null;
}

function moveTabFocus(current, offset) {
  const buttons = [...terminalTabs.querySelectorAll('.terminal-tab')];
  const index = buttons.indexOf(current);
  if (index < 0 || buttons.length === 0) {
    return;
  }
  const next = buttons[(index + offset + buttons.length) % buttons.length];
  next.click();
  next.focus();
}

deviceFilter.addEventListener('input', () => updateFilteredList(deviceList, deviceFilter, deviceCount, 'devices'));
profileFilter.addEventListener('input', () => updateFilteredList(profileList, profileFilter, profileCount, 'profiles'));

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

terminalTabs.addEventListener('keydown', (event) => {
  const tab = terminalTabFromEventTarget(event.target);
  if (!tab) {
    return;
  }
  if (event.key === 'ArrowRight') {
    event.preventDefault();
    moveTabFocus(tab, 1);
  } else if (event.key === 'ArrowLeft') {
    event.preventDefault();
    moveTabFocus(tab, -1);
  } else if (event.key === 'Home' || event.key === 'End') {
    event.preventDefault();
    const buttons = [...terminalTabs.querySelectorAll('.terminal-tab')];
    const next = event.key === 'Home' ? buttons[0] : buttons.at(-1);
    next?.click();
    next?.focus();
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
  profileDialogTarget = null;
});
profileDialog.addEventListener('cancel', () => {
  profileDialogTarget = null;
});
profileDialog.addEventListener('close', () => {
  profileDialogTarget = null;
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
    updateFilteredList(deviceList, deviceFilter, deviceCount, 'devices');
  }
});

const deviceObserver = new MutationObserver(syncDeviceRows);
deviceObserver.observe(deviceList, { childList: true });
const profileObserver = new MutationObserver(syncProfileRows);
profileObserver.observe(profileList, { childList: true });
const coreObserver = new MutationObserver(syncCoreState);
coreObserver.observe(coreHeading, { childList: true });
const terminalObserver = new MutationObserver(syncTerminalSemantics);
terminalObserver.observe(terminalHeading, { childList: true });
terminalObserver.observe(terminalTabs, { childList: true, subtree: true, attributes: true, attributeFilter: ['aria-selected'] });

window.addEventListener('DOMContentLoaded', () => {
  syncDeviceRows();
  syncProfileRows();
  syncCoreState();
  syncTerminalSemantics();
}, { once: true });
