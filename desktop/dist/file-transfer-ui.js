const filePathInput = document.querySelector('#file-remote-path');
const fileUploadButton = document.querySelector('#file-upload');
const fileDownloadButton = document.querySelector('#file-download');
const fileTransferDetail = document.querySelector('#file-transfer-detail');

const MAX_FILE_REMOTE_PATH_BYTES = 4096;
let fileTransferBusy = false;
let fileTransferAvailableConnectionID = null;
let fileTransferStatusGeneration = 0;

function activeFileConnectionID() {
  const session = activeSession();
  return typeof session?.connectionID === 'string' && session.connectionID
    ? session.connectionID
    : null;
}

function validRemoteFilePath(value) {
  return typeof value === 'string'
    && value.length > 0
    && new TextEncoder().encode(value).length <= MAX_FILE_REMOTE_PATH_BYTES
    && !/[\u0000-\u001f\u007f\\]/.test(value);
}

function refreshFileTransferControls() {
  const connectionID = activeFileConnectionID();
  const ready = Boolean(
    connectionID
    && connectionID === fileTransferAvailableConnectionID
    && validRemoteFilePath(filePathInput.value.trim())
    && !fileTransferBusy,
  );
  fileUploadButton.disabled = !ready;
  fileDownloadButton.disabled = !ready;
}

async function refreshFileTransferStatus() {
  const generation = ++fileTransferStatusGeneration;
  const connectionID = activeFileConnectionID();
  fileTransferAvailableConnectionID = null;
  refreshFileTransferControls();

  if (!connectionID) {
    fileTransferDetail.textContent = 'Open and activate an authenticated terminal session to use file transfer.';
    return;
  }

  fileTransferDetail.textContent = 'Checking file-transfer availability through the active Core-owned session…';
  try {
    const status = await getInvoke()('file_transfer_status', { connectionId: connectionID });
    if (generation !== fileTransferStatusGeneration || activeFileConnectionID() !== connectionID) {
      return;
    }
    if (!status || status.available !== true) {
      fileTransferDetail.textContent = 'File transfer is unavailable on this authenticated session. No fallback path was attempted.';
      refreshFileTransferControls();
      return;
    }
    fileTransferAvailableConnectionID = connectionID;
    fileTransferDetail.textContent = 'File transfer is available. The operating-system picker and local file data stay in the trusted native process.';
  } catch (_) {
    if (generation !== fileTransferStatusGeneration || activeFileConnectionID() !== connectionID) {
      return;
    }
    fileTransferDetail.textContent = 'File-transfer availability could not be verified. No fallback path was attempted.';
  }
  refreshFileTransferControls();
}

function validateTransferResult(result) {
  return result
    && typeof result === 'object'
    && typeof result.cancelled === 'boolean'
    && Number.isSafeInteger(result.bytes)
    && result.bytes >= 0;
}

async function runUpload() {
  const connectionID = activeFileConnectionID();
  const remotePath = filePathInput.value.trim();
  if (
    !connectionID
    || connectionID !== fileTransferAvailableConnectionID
    || !validRemoteFilePath(remotePath)
    || fileTransferBusy
  ) {
    refreshFileTransferControls();
    return;
  }

  fileTransferBusy = true;
  refreshFileTransferControls();
  fileTransferDetail.textContent = 'Choose a local file in the native picker. Its path and bytes are not exposed to this renderer.';
  try {
    const result = await getInvoke()('file_upload_pick', { connectionId: connectionID, remotePath });
    if (activeFileConnectionID() !== connectionID || !validateTransferResult(result)) {
      throw new Error('invalid native transfer result');
    }
    fileTransferDetail.textContent = result.cancelled
      ? 'Upload cancelled in the native picker.'
      : `Upload completed: ${result.bytes.toLocaleString()} bytes transferred.`;
  } catch (_) {
    fileTransferDetail.textContent = 'Upload failed. No alternate path or weaker transfer mechanism was attempted.';
  } finally {
    fileTransferBusy = false;
    refreshFileTransferControls();
  }
}

async function runDownload() {
  const connectionID = activeFileConnectionID();
  const remotePath = filePathInput.value.trim();
  if (
    !connectionID
    || connectionID !== fileTransferAvailableConnectionID
    || !validRemoteFilePath(remotePath)
    || fileTransferBusy
  ) {
    refreshFileTransferControls();
    return;
  }

  fileTransferBusy = true;
  refreshFileTransferControls();
  fileTransferDetail.textContent = 'Choose a destination in the native picker. Existing files are never silently replaced.';
  try {
    const result = await getInvoke()('file_download_pick', { connectionId: connectionID, remotePath });
    if (activeFileConnectionID() !== connectionID || !validateTransferResult(result)) {
      throw new Error('invalid native transfer result');
    }
    fileTransferDetail.textContent = result.cancelled
      ? 'Download cancelled in the native picker.'
      : `Download completed: ${result.bytes.toLocaleString()} bytes transferred.`;
  } catch (_) {
    fileTransferDetail.textContent = 'Download failed. No partial destination or fallback path should be used.';
  } finally {
    fileTransferBusy = false;
    refreshFileTransferControls();
  }
}

filePathInput.addEventListener('input', refreshFileTransferControls);
fileUploadButton.addEventListener('click', () => void runUpload());
fileDownloadButton.addEventListener('click', () => void runDownload());
terminalTabs.addEventListener('click', () => queueMicrotask(() => void refreshFileTransferStatus()));

const fileTransferSessionObserver = new MutationObserver(() => {
  queueMicrotask(() => void refreshFileTransferStatus());
});
fileTransferSessionObserver.observe(terminalHeading, { childList: true });
fileTransferSessionObserver.observe(terminalTabs, { childList: true, subtree: true });

window.addEventListener('DOMContentLoaded', () => {
  refreshFileTransferControls();
  void refreshFileTransferStatus();
}, { once: true });
