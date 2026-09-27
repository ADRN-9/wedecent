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
const transportList = document.querySelector('#transport-list');
const terminalHeading = document.querySelector('#terminal-heading');
const terminalDetail = document.querySelector('#terminal-detail');
const terminalTabs = document.querySelector('#terminal-tabs');
const terminalStack = document.querySelector('#terminal-stack');
const terminalEmpty = document.querySelector('#terminal-empty');
const disconnectButton = document.querySelector('#disconnect-terminal');

const TERMINAL_COLS = 80;
const TERMINAL_ROWS = 24;
const READ_DELAY_MS = 25;
const MAX_TERMINAL_TABS = 8;

const sessions = new Map();
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

function deviceItem(device) {
  const item = document.createElement('li');
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'device-connect';
  button.textContent = `${device.name || 'Unnamed device'} — ${device.id}`;
  button.addEventListener('click', () => startTerminal(device));
  item.append(button);
  return item;
}

function showUnavailable() {
  coreHeading.textContent = 'Local Core unavailable';
  coreDetail.textContent = 'The desktop shell will not fall back to a network or alternate control path. Start or restore Local Core, then retry.';
  coreFields.hidden = true;
  devicesDetail.textContent = 'Device inventory is unavailable until Local Core is restored.';
  deviceList.replaceChildren();
  transportList.replaceChildren();
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
  const devices = Array.isArray(inventory.devices) ? inventory.devices : [];
  const transports = Array.isArray(inventory.transports) ? inventory.transports : [];
  devicesDetail.textContent = devices.length === 0
    ? 'No known devices are currently exposed by Local Core.'
    : 'Choose a device to open another authorized terminal tab through Local Core.';
  replaceList(deviceList, devices, deviceItem);
  replaceList(transportList, transports, (transport) => textItem(`${transport.name} — ${transport.available ? 'available' : 'unavailable'}`));
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

async function disconnectSession(session, message = 'Session disconnected') {
  const connectionID = session.connectionID;
  session.connectionID = null;
  session.generation += 1;
  session.writeChain = Promise.resolve();
  session.inputDisposable?.dispose();
  session.inputDisposable = null;

  if (connectionID) {
    try {
      await getInvoke()('core_disconnect', { connectionId: connectionID });
    } catch (_) {
      // Local Core owns lifecycle state; an already-closed connection needs no fallback.
    }
  }
  setSessionStatus(session, message, 'The tab remains local. No alternate transport or control path was attempted.');
}

async function closeSession(tabID) {
  const session = getSession(tabID);
  if (!session) {
    return;
  }
  await disconnectSession(session);
  session.inputDisposable?.dispose();
  session.terminal.dispose();
  session.tabWrap.remove();
  session.panel.remove();
  sessions.delete(tabID);

  if (activeTabID === tabID) {
    activeTabID = sessions.keys().next().value || null;
  }
  refreshTerminalChrome();
}

async function pollTerminal(session, connectionID, generation) {
  const invoke = getInvoke();
  while (session.connectionID === connectionID && session.generation === generation) {
    try {
      const result = await invoke('terminal_read', { connectionId: connectionID });
      if (result.data) {
        session.terminal.write(base64ToBytes(result.data));
      }
      if (result.closed) {
        await disconnectSession(session, 'Session closed');
        setSessionStatus(session, 'Session closed', 'The secure terminal stream was closed by Local Core or the remote endpoint.');
        return;
      }
    } catch (_) {
      await disconnectSession(session, 'Session unavailable');
      setSessionStatus(session, 'Session unavailable', 'Terminal I/O stopped. No alternate transport or control path was attempted.');
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, READ_DELAY_MS));
  }
}

function queueTerminalWrite(session, invoke, connectionID, data) {
  const bytes = new TextEncoder().encode(data);
  const dataBase64 = bytesToBase64(bytes);
  session.writeChain = session.writeChain.then(async () => {
    if (session.connectionID !== connectionID) {
      return;
    }
    await invoke('terminal_write', { connectionId: connectionID, dataBase64 });
  }).catch(async () => {
    if (session.connectionID === connectionID) {
      await disconnectSession(session, 'Session unavailable');
      setSessionStatus(session, 'Session unavailable', 'Terminal input failed. No fallback path was attempted.');
    }
  });
}

async function startTerminal(device) {
  if (sessions.size >= MAX_TERMINAL_TABS) {
    terminalHeading.textContent = 'Terminal tab limit reached';
    terminalDetail.textContent = `Close a tab before opening another. The desktop UI is limited to ${MAX_TERMINAL_TABS} simultaneous tabs.`;
    return;
  }

  let session;
  try {
    session = createSession(device);
    const invoke = getInvoke();
    const connection = await invoke('core_connect', { deviceId: device.id });
    session.connectionID = connection.id;
    session.generation += 1;
    session.writeChain = Promise.resolve();
    const generation = session.generation;

    await invoke('terminal_resize', {
      connectionId: connection.id,
      cols: TERMINAL_COLS,
      rows: TERMINAL_ROWS,
    });

    setSessionStatus(session, device.name || device.id, `Connected through Local Core (${connection.path}).`);
    session.inputDisposable = session.terminal.onData((data) => {
      if (session.connectionID === connection.id) {
        queueTerminalWrite(session, invoke, connection.id, data);
      }
    });

    session.terminal.focus();
    void pollTerminal(session, connection.id, generation);
  } catch (_) {
    if (session) {
      await disconnectSession(session, 'Connection failed');
      setSessionStatus(session, 'Connection failed', 'Local Core did not establish an authorized secure session. No fallback path was attempted.');
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
    void disconnectSession(session);
  }
});
window.addEventListener('beforeunload', () => {
  const invoke = getInvoke();
  for (const session of sessions.values()) {
    if (session.connectionID) {
      void invoke('core_disconnect', { connectionId: session.connectionID });
    }
  }
});
window.addEventListener('DOMContentLoaded', refreshStatus, { once: true });
