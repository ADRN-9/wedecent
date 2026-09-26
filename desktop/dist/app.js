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
const terminalElement = document.querySelector('#terminal');
const disconnectButton = document.querySelector('#disconnect-terminal');

const TERMINAL_COLS = 80;
const TERMINAL_ROWS = 24;
const READ_DELAY_MS = 25;

let terminal = null;
let terminalInputDisposable = null;
let activeConnectionID = null;
let terminalGeneration = 0;
let writeChain = Promise.resolve();

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
    : 'Choose a device to ask Local Core to establish an authorized secure session.';
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

function ensureTerminal() {
  if (terminal) {
    return terminal;
  }
  if (typeof window.Terminal !== 'function') {
    throw new Error('xterm renderer unavailable');
  }
  terminal = new window.Terminal({
    cols: TERMINAL_COLS,
    rows: TERMINAL_ROWS,
    cursorBlink: true,
    convertEol: false,
    scrollback: 5000,
  });
  terminal.open(terminalElement);
  return terminal;
}

async function stopTerminal(message = 'No active session') {
  const connectionID = activeConnectionID;
  activeConnectionID = null;
  terminalGeneration += 1;
  writeChain = Promise.resolve();
  disconnectButton.disabled = true;
  terminalInputDisposable?.dispose();
  terminalInputDisposable = null;

  if (connectionID) {
    try {
      await getInvoke()('core_disconnect', { connectionId: connectionID });
    } catch (_) {
      // Local Core owns lifecycle state; an already-closed connection needs no fallback.
    }
  }
  terminalHeading.textContent = message;
}

async function pollTerminal(connectionID, generation) {
  const invoke = getInvoke();
  while (activeConnectionID === connectionID && terminalGeneration === generation) {
    try {
      const result = await invoke('terminal_read', { connectionId: connectionID });
      if (result.data) {
        ensureTerminal().write(base64ToBytes(result.data));
      }
      if (result.closed) {
        await stopTerminal('Session closed');
        terminalDetail.textContent = 'The secure terminal stream was closed by Local Core or the remote endpoint.';
        return;
      }
    } catch (_) {
      await stopTerminal('Session unavailable');
      terminalDetail.textContent = 'Terminal I/O stopped. No alternate transport or control path was attempted.';
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, READ_DELAY_MS));
  }
}

function queueTerminalWrite(invoke, connectionID, data) {
  const bytes = new TextEncoder().encode(data);
  const dataBase64 = bytesToBase64(bytes);
  writeChain = writeChain.then(async () => {
    if (activeConnectionID !== connectionID) {
      return;
    }
    await invoke('terminal_write', { connectionId: connectionID, dataBase64 });
  }).catch(async () => {
    if (activeConnectionID === connectionID) {
      await stopTerminal('Session unavailable');
      terminalDetail.textContent = 'Terminal input failed. No fallback path was attempted.';
    }
  });
}

async function startTerminal(device) {
  if (activeConnectionID) {
    await stopTerminal();
  }

  const xterm = ensureTerminal();
  xterm.clear();
  terminalHeading.textContent = `Connecting to ${device.name || device.id}…`;
  terminalDetail.textContent = 'Local Core is selecting and authorizing the secure path.';
  disconnectButton.disabled = true;

  try {
    const invoke = getInvoke();
    const connection = await invoke('core_connect', { deviceId: device.id });
    activeConnectionID = connection.id;
    terminalGeneration += 1;
    writeChain = Promise.resolve();
    const generation = terminalGeneration;

    await invoke('terminal_resize', {
      connectionId: connection.id,
      cols: TERMINAL_COLS,
      rows: TERMINAL_ROWS,
    });

    terminalHeading.textContent = device.name || device.id;
    terminalDetail.textContent = `Connected through Local Core (${connection.path}).`;
    disconnectButton.disabled = false;

    terminalInputDisposable?.dispose();
    terminalInputDisposable = xterm.onData((data) => {
      if (activeConnectionID === connection.id) {
        queueTerminalWrite(invoke, connection.id, data);
      }
    });

    xterm.focus();
    void pollTerminal(connection.id, generation);
  } catch (_) {
    await stopTerminal('Connection failed');
    terminalDetail.textContent = 'Local Core did not establish an authorized secure session. No fallback path was attempted.';
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
disconnectButton.addEventListener('click', () => stopTerminal());
window.addEventListener('beforeunload', () => {
  if (activeConnectionID) {
    void getInvoke()('core_disconnect', { connectionId: activeConnectionID });
  }
});
window.addEventListener('DOMContentLoaded', refreshStatus, { once: true });
