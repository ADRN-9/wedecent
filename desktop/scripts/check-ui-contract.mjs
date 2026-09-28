import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const [html, css, ux, uxModel, packageJSON, behaviorTests] = await Promise.all([
  readFile(resolve(root, 'dist/index.html'), 'utf8'),
  readFile(resolve(root, 'dist/style.css'), 'utf8'),
  readFile(resolve(root, 'dist/ux.js'), 'utf8'),
  readFile(resolve(root, 'dist/ux-model.js'), 'utf8'),
  readFile(resolve(root, 'package.json'), 'utf8'),
  readFile(resolve(root, 'scripts/ui-behavior.test.mjs'), 'utf8'),
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
  'id="device-list-state"',
  'id="profile-list-state"',
  'id="transport-list-state"',
  'id="core-state-chip"',
  'id="session-state-chip"',
  'id="file-transfer-state"',
  'id="profile-dialog"',
  'id="terminal-font-size"',
  'id="terminal-density"',
  'role="tablist"',
  'aria-keyshortcuts="Control+K Meta+K"',
];
for (const token of requiredHTML) {
  if (!html.includes(token)) {
    fail(`missing required UI contract ${JSON.stringify(token)}`);
  }
}

const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
const uniqueIDs = new Set(ids);
if (uniqueIDs.size !== ids.length) {
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
  fail(`duplicate element id ${JSON.stringify([...new Set(duplicates)])}`);
}

for (const match of html.matchAll(/\bfor="([^"]+)"/g)) {
  if (!uniqueIDs.has(match[1])) {
    fail(`label references missing control ${JSON.stringify(match[1])}`);
  }
}

for (const match of html.matchAll(/\baria-(?:labelledby|describedby|controls)="([^"]+)"/g)) {
  for (const id of match[1].trim().split(/\s+/)) {
    if (!uniqueIDs.has(id)) {
      fail(`ARIA relationship references missing id ${JSON.stringify(id)}`);
    }
  }
}

if ((html.match(/role="status"/g) || []).length < 3) {
  fail('device/profile/transport empty states must expose status live regions');
}
if (!html.includes('<dialog id="profile-dialog" aria-labelledby="profile-dialog-title" aria-describedby="profile-dialog-detail profile-dialog-error">')) {
  fail('profile dialog must have labelledby and describedby relationships');
}

const appScript = html.indexOf('<script src="./app.js" defer></script>');
const modelScript = html.indexOf('<script src="./ux-model.js" defer></script>');
const uxScript = html.indexOf('<script src="./ux.js" defer></script>');
const transferScript = html.indexOf('<script src="./file-transfer-ui.js" defer></script>');
if (appScript < 0 || modelScript <= appScript || uxScript <= modelScript || transferScript <= uxScript) {
  fail('UX model/controller must load after app state and before file-transfer presentation');
}

const presentationSource = `${ux}\n${uxModel}`;
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
  if (presentationSource.includes(token)) {
    fail(`presentation layer contains forbidden authority token ${JSON.stringify(token)}`);
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
  'profileDialogReturnFocus',
  'pendingTabFocus',
  'deviceFilter.focus()',
  'terminal.options.fontSize',
  'terminal.options.lineHeight',
  'MutationObserver',
];
for (const token of requiredUX) {
  if (!ux.includes(token)) {
    fail(`missing UX behavior ${JSON.stringify(token)}`);
  }
}

const requiredModel = [
  'matchesFilter',
  'listSummary',
  'tabTargetIndex',
  'focusIndexAfterClose',
  'normalizePreferences',
  'parsePreferences',
  'densityLineHeight',
];
for (const token of requiredModel) {
  if (!uxModel.includes(token)) {
    fail(`missing testable UX model behavior ${JSON.stringify(token)}`);
  }
}

const requiredCSS = [
  ':focus-visible',
  '@media (prefers-reduced-motion: reduce)',
  '@media (max-width: 980px)',
  '.workspace-sidebar',
  '.state-chip',
  '.list-state',
  '.terminal-utility-row',
  '.terminal-preferences',
  'dialog::backdrop',
];
for (const token of requiredCSS) {
  if (!css.includes(token)) {
    fail(`missing visual/accessibility contract ${JSON.stringify(token)}`);
  }
}

if (!packageJSON.includes('node --test ./scripts/ui-behavior.test.mjs')) {
  fail('asset build must execute deterministic UI behavior tests');
}
for (const token of ['matchesFilter', 'tabTargetIndex', 'focusIndexAfterClose', 'parsePreferences']) {
  if (!behaviorTests.includes(token)) {
    fail(`behavior tests do not cover ${JSON.stringify(token)}`);
  }
}

console.log('Desktop UX presentation and accessibility contract verified.');
