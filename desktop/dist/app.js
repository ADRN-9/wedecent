const coreHeading = document.querySelector('#core-heading');
const coreDetail = document.querySelector('#core-detail');
const coreFields = document.querySelector('#core-fields');
const retryButton = document.querySelector('#retry-status');
const deviceName = document.querySelector('#device-name');
const deviceID = document.querySelector('#device-id');
const apiVersion = document.querySelector('#api-version');
const accountState = document.querySelector('#account-state');

function showUnavailable() {
  coreHeading.textContent = 'Local Core unavailable';
  coreDetail.textContent = 'The desktop shell will not fall back to a network or alternate control path. Start or restore Local Core, then retry.';
  coreFields.hidden = true;
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
    const status = await invoke('core_status');
    showStatus(status);
  } catch (_) {
    showUnavailable();
  } finally {
    retryButton.disabled = false;
  }
}

retryButton.addEventListener('click', refreshStatus);
window.addEventListener('DOMContentLoaded', refreshStatus, { once: true });
