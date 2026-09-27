const coreHeading = document.querySelector('#core-heading');
const coreDetail = document.querySelector('#core-detail');
const coreFields = document.querySelector('#core-fields');
const retryButton = document.querySelector('#retry-status');
const deviceName = document.querySelector('#device-name');
const deviceID = document.querySelector('#device-id');
const apiVersion = document.querySelector('#api-version');
const accountState = document.querySelector('#account-state');
const devicesDetail = document.querySelector('#devices-detail');
const deviceList = document.querySelector('#device-list');
const profilesDetail = document.querySelector('#profiles-detail');
const profileList = document.querySelector('#profile-list');
const transportList = document.querySelector('#transport-list');
const terminalHeading = document.querySelector('#terminal-heading');
const terminalDetail = document.querySelector('#terminal-detail');
const terminalTabs = document.querySelector('#terminal-tabs');
const terminalStack = document.querySelector('#terminal-stack');
const terminalEmpty = document.querySelector('#terminal-empty');
const disconnectButton = document.querySelector('#disconnect-terminal');

const TERMINAL_COLS = 80;
const TERMINAL_ROWS = 24;
const TERMINAL_TYPE = 'xterm-256color';
const READ_DELAY_MS = 25;
const MAX_TERMINAL_TABS = 8;
const MAX_SESSION_PROFILES = 32;
const MAX_PROFILE_LABEL_LENGTH = 64;
const PROFILE_STORAGE_KEY = 'wedecent.sessionProfiles.v1';
const DEVICE_ID_PATTERN = /^wd_[a-z2-7]{16}$/;
const PROFILE_ID_PATTERN = /^profile-[a-zA-Z0-9-]{1,96}$/;

const sessions = new Map();
const parentsByDevice = new Map();
const connectingDevices = new Set();
const knownDevices = new Map();
let profiles = loadProfiles();
let activeTabID = null;
let nextTabID = 1;

function getInvoke() {
  const invoke = window.__TAURI__?.core?.invoke;
  if (typeof invoke !== 'function') {
    throw new Error('Tauri invoke unavailable');
  }
  return invoke;
}

function replaceList(list, items, render) {
  list.replaceChildren(...items.map(render));
}

function textItem(text) {
  const item = document.createElement('li');
  item.textContent = text;
  return item;
}

function validDeviceID(value) {
  return typeof value === 'string' && DEVICE_ID_PATTERN.test(value);
}

function cleanProfileLabel(value) {
  if (typeof value !== 'string') {
    return '';
  }
  return value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, MAX_PROFILE_LABEL_LENGTH);
}

function createProfileID() {
  if (typeof crypto?.randomUUID === 'function') {
    return `profile-${crypto.randomUUID()}`;
  }
  return `profile-${Date.now()}-${Math.random().toString(36).slice(2, 14)}`;
}

function sanitizeProfile(value) {
  if (!value || typeof value !== 'object') {
    return null;
  }
  const id = typeof value.id === 'string' && PROFILE_ID_PATTERN.test(value.id) ? value.id : '';
  const label = cleanProfileLabel(value.label);
  const deviceIDValue = typeof value.device_id === 'string' ? value.device_id : '';
  if (!id || !label || !validDeviceID(deviceIDValue)) {
    return null;
  }
  return { id, label, device_id: deviceIDValue };
}

function loadProfiles() {
  try {
    const raw = localStorage.getItem(PROFILE_STORAGE_KEY);
    if (!raw) {
      return [];
    }
    const stored = JSON.parse(raw);
    if (!stored || stored.version !== 1 || !Array.isArray(stored.profiles)) {
      return [];
    }
    const result = [];
    const seen = new Set();
    for (const candidate of stored.profiles) {
      const profile = sanitizeProfile(candidate);
      if (!profile || seen.has(profile.id)) {
        continue;
      }
      result.push(profile);
      seen.add(profile.id);
      if (result.length >= MAX_SESSION_PROFILES) {
        break;
      }
    }
    return result;
  } catch (_) {
    return [];
  }
}

function persistProfiles() {
  try {
    localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify({ version: 1, profiles }));
    return true;
  } catch (_) {
    return false;
  }
}

function profileItem(profile) {
  const item = document.createElement('li');
  const row = document.createElement('div');
  row.className = 'profile-row';

  const label = document.createElement('span');
  label.className = 'profile-label';
  label.textContent = profile.label;

  const actions = document.createElement('span');
  actions.className = 'profile-actions';

  const open = document.createElement('button');
  open.type = 'button';
  open.textContent = 'Open';
  open.addEventListener('click', () => {
    const device = knownDevices.get(profile.device_id);
    if (!device) {
      terminalHeading.textContent = 'Profile target unavailable';
      terminalDetail.textContent = 'This saved device is not present in the current sanitized Local Core inventory.';
      return;
    }
    void startTerminal(device);
  });

  const remove = document.createElement('button');
  remove.type = 'button';
  remove.textContent = 'Delete';
  remove.addEventListener('click', () => {
    profiles = profiles.filter((candidate) => candidate.id !== profile.id);
    persistProfiles();
    renderProfiles();
  });

  actions.append(open, remove);
  row.append(label, actions);
  item.append(row);
  return item;
}

function renderProfiles() {
  profilesDetail.textContent = profiles.length === 0
    ? 'No saved profiles. Save a known device to create a local non-secret shortcut.'
    : 'Profiles contain only a local label and device ID; Core still resolves and authorizes every connection.';
  replaceList(profileList, profiles, profileItem);
}

function saveProfile(device) {
  if (!validDeviceID(device?.id) || profiles.length >= MAX_SESSION_PROFILES) {
    profilesDetail.textContent = profiles.length >= MAX_SESSION_PROFILES
      ? `Profile limit reached (${MAX_SESSION_PROFILES}). Delete a profile before saving another.`
      : 'The selected device ID is invalid and was not saved.';
    return;
  }
  const suggested = cleanProfileLabel(device.name) || device.id;
  const requested = window.prompt('Profile name', suggested);
  if (requested === null) {
    return;
  }
  const label = cleanProfileLabel(requested);
  if (!label) {
    profilesDetail.textContent = 'Profile names must contain at least one printable character.';
    return;
  }

  const existingIndex = profiles.findIndex((profile) => profile.device_id === device.id);
  const profile = {
    id: existingIndex >= 0 ? profiles[existingIndex].id : createProfileID(),
    label,
    device_id: device.id,
  };
  if (existingIndex >= 0) {
    profiles = profiles.map((candidate, index) => index === existingIndex ? profile : candidate);
  } else {
    profiles = [...profiles, profile];
  }
  if (!persistProfiles()) {
    profilesDetail.textContent = 'The profile could not be persisted locally.';
    return;
  }
  renderProfiles();
}

function deviceItem(device) {
  const item = document.createElement('li');
  const row = document.createElement('div');
  row.className = 'device-row';

  const connect = document.createElement('button');
  connect.type = 'button';
  connect.className = 'device-connect';
  connect.textContent = `${device.name || 'Unnamed device'} — ${device.id}`;
  connect.addEventListener('click', () => startTerminal(device));

  const save = document.createElement('button');
  save.type = 'button';
  save.className = 'device-save-profile';
  save.textContent = 'Save profile';
  save.addEventListener('click', () => saveProfile(device));

  row.append(connect, save);
  item.append(row);
  return item;
}

function showUnavailable() {
  coreHeading.textContent = 'Local Core unavailable';
  coreDetail.textContent = 'The desktop shell will not fall back to a network or alternate control path. Start or restore Local Core, then retry.';
  coreFields.hidden = true;
  devicesDetail.textContent = 'Device inventory is unavailable until Local Core is restored.';
  knownDevices.clear();
  deviceList.replaceChildren();
  transportList.replaceChildren();
  renderProfiles();
}

function showStatus(status) {
  coreHeading.textContent = 'Local Core connected';
  coreDetail.textContent = 'Status is read through the protected local application boundary.';
  deviceName.textContent = status.device_name || 'Unnamed device';
  deviceID.textContent = status.device_id;
  apiVersion.textContent = status.api_version;
  accountState.textContent = status.signed_in ? 'Signed in' : 'Signed out';
  coreFields.hidden = false;
}

function showInventory(inventory) {
  const devices = Array.isArray(inventory.devices)
    ? inventory.devices.filter((device) => validDeviceID(device?.id))
    : [];
  const transports = Array.isArray(inventory.transports) ? inventory.transports : [];
  knownDevices.clear();
  for (const device of devices) {
    knownDevices.set(device.id, { id: device.id, name: typeof device.name === 'string' ? device.name : '' });
  }
  devicesDetail.textContent = devices.length === 0
    ? 'No known devices are currently exposed by Local Core.'
    : 'Choose a device to open an authorized terminal tab through Local Core. Multiplex-capable sessions share one authenticated parent.';
  replaceList(deviceList, devices, deviceItem);
  replaceList(transportList, transports, (transport) => textItem(`${transport.name} — ${transport.available ? 'available' : 'unavailable'}`));
  renderProfiles();
}

function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    binary += String.fromCharCode(...bytes.subarray(offset, Math.min(offset + chunk, bytes.length)));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function getSession(tabID) {
  return sessions.get(tabID) || null;
}

function activeSession() {
  return activeTabID ? getSession(activeTabID) : null;
}

function refreshTerminalChrome() {
  const session = activeSession();
  terminalEmpty.hidden = sessions.size !== 0;
  disconnectButton.disabled = !session?.connectionID;

  for (const [tabID, entry] of sessions) {
    const active = tabID === activeTabID;
    entry.button.setAttribute('aria-selected', active ? 'true' : 'false');
    entry.panel.hidden = !active;
  }

  if (!session) {
    terminalHeading.textContent = 'No active session';
    terminalDetail.textContent = 'Choose a known device. Local Core remains responsible for authorization, path selection, identity verification, and the secure session.';
    return;
  }

  terminalHeading.textContent = session.heading;
  terminalDetail.textContent = session.detail;
  if (session.terminal) {
    session.terminal.focus();
  }
}

function setSessionStatus(session, heading, detail) {
  session.heading = heading;
  session.detail = detail;
  if (session.tabID === activeTabID) {
    refreshTerminalChrome();
  }
}

function createSession(device) {
  if (typeof window.Terminal !== 'function') {
    throw new Error('xterm renderer unavailable');
  }

  const tabID = `terminal-tab-${nextTabID}`;
  nextTabID += 1;

  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'terminal-tab';
  button.setAttribute('role', 'tab');
  button.setAttribute('aria-selected', 'false');
  button.textContent = device.name || device.id;
  button.addEventListener('click', () => {
    activeTabID = tabID;
    refreshTerminalChrome();
  });

  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'terminal-tab-close';
  close.setAttribute('aria-label', `Close ${device.name || device.id} terminal`);
  close.textContent = '×';
  close.addEventListener('click', (event) => {
    event.stopPropagation();
    void closeSession(tabID);
  });

  const tabWrap = document.createElement('span');
  tabWrap.className = 'terminal-tab-wrap';
  tabWrap.append(button, close);
  terminalTabs.append(tabWrap);

  const panel = document.createElement('div');
  panel.className = 'terminal';
  panel.setAttribute('role', 'tabpanel');
  panel.hidden = true;
  terminalStack.append(panel);

  const terminal = new window.Terminal({
    cols: TERMINAL_COLS,
    rows: TERMINAL_ROWS,
    cursorBlink: true,
    convertEol: false,
    scrollback: 5000,
  });
  terminal.open(panel);

  const session = {
    tabID,
    device,
    button,
    tabWrap,
    panel,
    terminal,
    inputDisposable: null,
    connectionID: null,
    terminalID: null,
    generation: 0,
    writeChain: Promise.resolve(),
    heading: `Connecting to ${device.name || device.id}…`,
    detail: 'Local Core is selecting and authorizing the secure path.',
  };
  sessions.set(tabID, session);
  activeTabID = tabID;
  refreshTerminalChrome();
  return session;
}

function removeSessionUI(session) {
  session.inputDisposable?.dispose();
  session.inputDisposable = null;
  session.terminal.dispose();
  session.tabWrap.remove();
  session.panel.remove();
  sessions.delete(session.tabID);
  if (activeTabID === session.tabID) {
    activeTabID = sessions.keys().next().value || null;
  }
  refreshTerminalChrome();
}

async function disconnectParent(parent) {
  if (!parent?.connectionID) {
    return;
  }
  const connectionID = parent.connectionID;
  parent.connectionID = null;
  parentsByDevice.delete(parent.deviceID);
  try {
    await getInvoke()('core_disconnect', { connectionId: connectionID });
  } catch (_) {
    // Local Core owns lifecycle state; an already-closed parent needs no fallback.
  }
}

async function stopSession(
  session,
  heading = 'Session disconnected',
  detail = 'The tab remains local. No alternate transport or control path was attempted.',
  closeRemote = true,
) {
  const connectionID = session.connectionID;
  const terminalID = session.terminalID;
  const parent = parentsByDevice.get(session.device.id);
  session.connectionID = null;
  session.terminalID = null;
  session.generation += 1;
  session.writeChain = Promise.resolve();
  session.inputDisposable?.dispose();
  session.inputDisposable = null;

  if (parent) {
    parent.tabs.delete(session.tabID);
  }

  if (closeRemote && connectionID && terminalID) {
    try {
      await getInvoke()('terminal_stream_close', { connectionId: connectionID, terminalId: terminalID });
    } catch (_) {
      // Child close is best-effort cleanup only; never replay terminal input or choose another path.
    }
  }

  if (parent && parent.tabs.size === 0) {
    await disconnectParent(parent);
  }
  setSessionStatus(session, heading, detail);
}

async function closeSession(tabID) {
  const session = getSession(tabID);
  if (!session) {
    return;
  }
  if (session.connectionID) {
    await stopSession(session);
  }
  removeSessionUI(session);
}

async function readTerminal(session, connectionID, terminalID) {
  const invoke = getInvoke();
  if (terminalID) {
    return invoke('terminal_stream_read', { connectionId: connectionID, terminalId: terminalID });
  }
  return invoke('terminal_read', { connectionId: connectionID });
}

async function pollTerminal(session, connectionID, terminalID, generation) {
  while (
    session.connectionID === connectionID
    && session.terminalID === terminalID
    && session.generation === generation
  ) {
    try {
      const result = await readTerminal(session, connectionID, terminalID);
      if (result.data) {
        session.terminal.write(base64ToBytes(result.data));
      }
      if (result.closed) {
        await stopSession(
          session,
          'Session closed',
          'The secure terminal stream was closed by Local Core or the remote endpoint.',
          false,
        );
        return;
      }
    } catch (_) {
      await stopSession(
        session,
        'Session unavailable',
        'Terminal I/O stopped. No alternate transport or control path was attempted.',
      );
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, READ_DELAY_MS));
  }
}

function queueTerminalWrite(session, connectionID, terminalID, data) {
  const bytes = new TextEncoder().encode(data);
  const dataBase64 = bytesToBase64(bytes);
  session.writeChain = session.writeChain.then(async () => {
    if (session.connectionID !== connectionID || session.terminalID !== terminalID) {
      return;
    }
    const invoke = getInvoke();
    if (terminalID) {
      await invoke('terminal_stream_write', { connectionId: connectionID, terminalId: terminalID, dataBase64 });
    } else {
      await invoke('terminal_write', { connectionId: connectionID, dataBase64 });
    }
  }).catch(async () => {
    if (session.connectionID === connectionID && session.terminalID === terminalID) {
      await stopSession(
        session,
        'Session unavailable',
        'Terminal input failed. No fallback path was attempted.',
      );
    }
  });
}

async function attachSession(session, parent, terminalID) {
  session.connectionID = parent.connectionID;
  session.terminalID = terminalID;
  session.generation += 1;
  session.writeChain = Promise.resolve();
  parent.tabs.add(session.tabID);
  const generation = session.generation;
  const connectionID = parent.connectionID;

  setSessionStatus(
    session,
    session.device.name || session.device.id,
    terminalID
      ? `Connected through Local Core (${parent.path}); this tab is a Core-owned logical terminal on the shared authenticated session.`
      : `Connected through Local Core (${parent.path}); this peer is using the authenticated default terminal stream.`,
  );
  session.inputDisposable = session.terminal.onData((data) => {
    if (session.connectionID === connectionID && session.terminalID === terminalID) {
      queueTerminalWrite(session, connectionID, terminalID, data);
    }
  });
  session.terminal.focus();
  void pollTerminal(session, connectionID, terminalID, generation);
}

async function openLogicalTerminal(parent) {
  const stream = await getInvoke()('terminal_stream_open', {
    connectionId: parent.connectionID,
    cols: TERMINAL_COLS,
    rows: TERMINAL_ROWS,
    term: TERMINAL_TYPE,
  });
  if (!stream || stream.connection_id !== parent.connectionID || typeof stream.id !== 'string') {
    throw new Error('invalid logical terminal result');
  }
  return stream.id;
}

async function startTerminal(device) {
  if (!validDeviceID(device?.id) || !knownDevices.has(device.id)) {
    terminalHeading.textContent = 'Device unavailable';
    terminalDetail.textContent = 'Only devices currently returned by sanitized Local Core inventory can be opened.';
    return;
  }
  if (sessions.size >= MAX_TERMINAL_TABS) {
    terminalHeading.textContent = 'Terminal tab limit reached';
    terminalDetail.textContent = `Close a tab before opening another. The desktop UI is limited to ${MAX_TERMINAL_TABS} simultaneous tabs.`;
    return;
  }

  const existingParent = parentsByDevice.get(device.id);
  if (!existingParent && connectingDevices.has(device.id)) {
    terminalHeading.textContent = 'Connection already in progress';
    terminalDetail.textContent = 'Local Core is already establishing the authenticated parent for this device.';
    return;
  }
  if (existingParent?.mode === 'legacy') {
    terminalHeading.textContent = 'Additional terminal unavailable';
    terminalDetail.textContent = 'This authenticated peer does not expose logical terminal multiplexing. Its default terminal remains open; no alternate connection or transport was attempted.';
    return;
  }

  let session;
  try {
    session = createSession(device);
    let parent = existingParent;
    if (!parent) {
      connectingDevices.add(device.id);
      let connection;
      try {
        connection = await getInvoke()('core_connect', { deviceId: device.id });
      } finally {
        connectingDevices.delete(device.id);
      }
      parent = {
        deviceID: device.id,
        connectionID: connection.id,
        path: connection.path,
        mode: 'pending',
        tabs: new Set(),
      };
      parentsByDevice.set(device.id, parent);

      try {
        const terminalID = await openLogicalTerminal(parent);
        parent.mode = 'multiplex';
        await attachSession(session, parent, terminalID);
        return;
      } catch (_) {
        parent.mode = 'legacy';
        await getInvoke()('terminal_resize', {
          connectionId: parent.connectionID,
          cols: TERMINAL_COLS,
          rows: TERMINAL_ROWS,
        });
        await attachSession(session, parent, null);
        return;
      }
    }

    if (parent.mode !== 'multiplex') {
      throw new Error('logical terminals unavailable');
    }
    const terminalID = await openLogicalTerminal(parent);
    await attachSession(session, parent, terminalID);
  } catch (_) {
    if (session) {
      const parent = parentsByDevice.get(device.id);
      if (parent && parent.tabs.size === 0) {
        await disconnectParent(parent);
      }
      setSessionStatus(
        session,
        'Connection failed',
        'Local Core did not establish an authorized terminal stream. No fallback path was attempted.',
      );
    }
  }
}

async function refreshStatus() {
  retryButton.disabled = true;
  coreHeading.textContent = 'Checking status…';
  coreDetail.textContent = 'Connecting through the protected local application boundary.';
  coreFields.hidden = true;

  try {
    const invoke = getInvoke();
    const [status, inventory] = await Promise.all([
      invoke('core_status'),
      invoke('core_inventory'),
    ]);
    showStatus(status);
    showInventory(inventory);
  } catch (_) {
    showUnavailable();
  } finally {
    retryButton.disabled = false;
  }
}

retryButton.addEventListener('click', refreshStatus);
disconnectButton.addEventListener('click', () => {
  const session = activeSession();
  if (session) {
    void stopSession(session);
  }
});
window.addEventListener('beforeunload', () => {
  const invoke = getInvoke();
  for (const parent of parentsByDevice.values()) {
    if (parent.connectionID) {
      void invoke('core_disconnect', { connectionId: parent.connectionID });
    }
  }
});
window.addEventListener('DOMContentLoaded', () => {
  renderProfiles();
  void refreshStatus();
}, { once: true });
