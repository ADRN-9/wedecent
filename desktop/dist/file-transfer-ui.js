const fileTransferPanel = document.querySelector('.file-transfer-panel');
const filePathInput = document.querySelector('#file-remote-path');
const filePathHint = document.querySelector('#file-path-hint');
const fileUploadButton = document.querySelector('#file-upload');
const fileDownloadButton = document.querySelector('#file-download');
const fileTransferDetail = document.querySelector('#file-transfer-detail');
const fileTransferState = document.querySelector('#file-transfer-state');

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

function setTransferDetail(message, label, state) {
  fileTransferDetail.textContent = message;
  fileTransferState.textContent = label;
  fileTransferState.dataset.state = state;
  fileTransferPanel.setAttribute('aria-busy', state === 'busy' ? 'true' : 'false');
}

function refreshFilePathHint() {
  const value = filePathInput.value.trim();
  if (!value) {
    filePathHint.textContent = 'Relative remote path; controls, backslashes, and paths over 4096 UTF-8 bytes are rejected.';
    filePathHint.dataset.state = 'idle';
    return;
  }
  if (validRemoteFilePath(value)) {
    filePathHint.textContent = `${new TextEncoder().encode(value).length} UTF-8 bytes · valid remote relative path format.`;
    filePathHint.dataset.state = 'valid';
    return;
  }
  filePathHint.textContent = 'Enter a non-empty relative path without controls or backslashes and within 4096 UTF-8 bytes.';
  filePathHint.dataset.state = 'invalid';
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
  refreshFilePathHint();
}

async function refreshFileTransferStatus() {
  const generation = ++fileTransferStatusGeneration;
  const connectionID = activeFileConnectionID();
  fileTransferAvailableConnectionID = null;
  refreshFileTransferControls();

  if (!connectionID) {
    setTransferDetail(
      'Open and activate an authenticated terminal session to use file transfer.',
      'Unavailable',
      'idle',
    );
    return;
  }

  setTransferDetail(
    'Checking file-transfer availability through the active Core-owned session…',
    'Checking',
    'busy',
  );
  try {
    const status = await getInvoke()('file_transfer_status', { connectionId: connectionID });
    if (generation !== fileTransferStatusGeneration || activeFileConnectionID() !== connectionID) {
      return;
    }
    if (!status || status.available !== true) {
      setTransferDetail(
        'File transfer is unavailable on this authenticated session. No fallback path was attempted.',
        'Unavailable',
        'unavailable',
      );
      refreshFileTransferControls();
      return;
    }
    fileTransferAvailableConnectionID = connectionID;
    setTransferDetail(
      'File transfer is available. The operating-system picker and local file data stay in the trusted native process.',
      'Ready',
      'connected',
    );
  } catch (_) {
    if (generation !== fileTransferStatusGeneration || activeFileConnectionID() !== connectionID) {
      return;
    }
    setTransferDetail(
      'File-transfer availability could not be verified. No fallback path was attempted.',
      'Unavailable',
      'error',
    );
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
  setTransferDetail(
    'Choose a local file in the native picker. Its path and bytes are not exposed to this renderer.',
    'Uploading',
    'busy',
  );
  try {
    const result = await getInvoke()('file_upload_pick', { connectionId: connectionID, remotePath });
    if (!validateTransferResult(result)) {
      throw new Error('invalid native transfer result');
    }
    if (result.cancelled) {
      setTransferDetail('Upload cancelled in the native picker.', 'Ready', 'idle');
    } else {
      setTransferDetail(
        `Upload completed: ${result.bytes.toLocaleString()} bytes transferred.`,
        'Complete',
        'success',
      );
    }
  } catch (_) {
    setTransferDetail(
      'Upload failed. No alternate path or weaker transfer mechanism was attempted.',
      'Failed',
      'error',
    );
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
  setTransferDetail(
    'Choose a destination in the native picker. Existing files are never silently replaced.',
    'Downloading',
    'busy',
  );
  try {
    const result = await getInvoke()('file_download_pick', { connectionId: connectionID, remotePath });
    if (!validateTransferResult(result)) {
      throw new Error('invalid native transfer result');
    }
    if (result.cancelled) {
      setTransferDetail('Download cancelled in the native picker.', 'Ready', 'idle');
    } else {
      setTransferDetail(
        `Download completed: ${result.bytes.toLocaleString()} bytes transferred.`,
        'Complete',
        'success',
      );
    }
  } catch (_) {
    setTransferDetail(
      'Download failed. No partial destination or fallback path should be used.',
      'Failed',
      'error',
    );
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
