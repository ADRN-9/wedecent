import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const [html, css, ux] = await Promise.all([
  readFile(resolve(root, 'dist/index.html'), 'utf8'),
  readFile(resolve(root, 'dist/style.css'), 'utf8'),
  readFile(resolve(root, 'dist/ux.js'), 'utf8'),
]);

const fail = (message) => {
  throw new Error(`desktop UX contract: ${message}`);
};

const requiredHTML = [
  'class="workspace"',
  'class="workspace-sidebar"',
  'class="workspace-main"',
  'id="device-filter"',
  'id="profile-filter"',
  'id="core-state-chip"',
  'id="session-state-chip"',
  'id="file-transfer-state"',
  'id="profile-dialog"',
  'role="tablist"',
  'aria-keyshortcuts="Control+K Meta+K"',
];
for (const token of requiredHTML) {
  if (!html.includes(token)) {
    fail(`missing required UI contract ${JSON.stringify(token)}`);
  }
}

const appScript = html.indexOf('<script src="./app.js" defer></script>');
const uxScript = html.indexOf('<script src="./ux.js" defer></script>');
const transferScript = html.indexOf('<script src="./file-transfer-ui.js" defer></script>');
if (appScript < 0 || uxScript <= appScript || transferScript <= uxScript) {
  fail('presentation controller must load after app state and before file-transfer presentation');
}

const forbiddenUX = [
  'getInvoke(',
  '__TAURI__',
  'fetch(',
  'XMLHttpRequest',
  'WebSocket',
  'EventSource',
  'showOpenFilePicker',
  'showSaveFilePicker',
  'file://',
  'wd-desktop-bridge',
  'terminal_bridge_request',
  'connection.path',
  'fingerprint',
  'grant',
  'wireStream',
];
for (const token of forbiddenUX) {
  if (ux.includes(token)) {
    fail(`presentation controller contains forbidden authority token ${JSON.stringify(token)}`);
  }
}

const requiredUX = [
  "event.key === 'ArrowRight'",
  "event.key === 'ArrowLeft'",
  "event.key === 'Home'",
  "event.key === 'Delete'",
  'aria-controls',
  'aria-labelledby',
  'profileDialog.showModal()',
  'deviceFilter.focus()',
  'MutationObserver',
];
for (const token of requiredUX) {
  if (!ux.includes(token)) {
    fail(`missing UX behavior ${JSON.stringify(token)}`);
  }
}

const requiredCSS = [
  ':focus-visible',
  '@media (prefers-reduced-motion: reduce)',
  '@media (max-width: 980px)',
  '.workspace-sidebar',
  '.state-chip',
  'dialog::backdrop',
];
for (const token of requiredCSS) {
  if (!css.includes(token)) {
    fail(`missing visual/accessibility contract ${JSON.stringify(token)}`);
  }
}

console.log('Desktop UX presentation contract verified.');
