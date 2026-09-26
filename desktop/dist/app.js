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

function replaceList(list, items, render) {
  list.replaceChildren(...items.map(render));
}

function textItem(text) {
  const item = document.createElement('li');
  item.textContent = text;
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
    : 'Loaded from Local Core without endpoints or fingerprints.';
  replaceList(deviceList, devices, (device) => textItem(`${device.name || 'Unnamed device'} — ${device.id}`));
  replaceList(transportList, transports, (transport) => textItem(`${transport.name} — ${transport.available ? 'available' : 'unavailable'}`));
}

async function refreshStatus() {
  retryButton.disabled = true;
  coreHeading.textContent = 'Checking status…';
  coreDetail.textContent = 'Connecting through the protected local application boundary.';
  coreFields.hidden = true;

  try {
    const invoke = window.__TAURI__?.core?.invoke;
    if (typeof invoke !== 'function') {
      throw new Error('Tauri invoke unavailable');
    }
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
window.addEventListener('DOMContentLoaded', refreshStatus, { once: true });
