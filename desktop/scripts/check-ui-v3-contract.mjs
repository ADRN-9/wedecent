import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const [html, css, controller, model, tests] = await Promise.all([
  readFile(resolve(root, 'dist/index.html'), 'utf8'),
  readFile(resolve(root, 'dist/ux-v3.css'), 'utf8'),
  readFile(resolve(root, 'dist/ux-v3.js'), 'utf8'),
  readFile(resolve(root, 'dist/ux-v3-model.js'), 'utf8'),
  readFile(resolve(root, 'scripts/ui-v3-behavior.test.mjs'), 'utf8'),
]);

const fail = (message) => {
  throw new Error(`desktop UX v3 contract: ${message}`);
};

for (const token of [
  'id="focus-terminal"',
  'aria-keyshortcuts="Alt+T"',
  'id="terminal-reset-appearance"',
  'id="terminal-cursor-style"',
  'id="terminal-cursor-blink"',
  '<script src="./ux-v3-model.js" defer></script>',
  '<script src="./ux-v3.js" defer></script>',
  '<link rel="stylesheet" href="./ux-v3.css">',
]) {
  if (!html.includes(token)) {
    fail(`missing v3 interface token ${JSON.stringify(token)}`);
  }
}

const baseController = html.indexOf('<script src="./ux.js" defer></script>');
const modelScript = html.indexOf('<script src="./ux-v3-model.js" defer></script>');
const controllerScript = html.indexOf('<script src="./ux-v3.js" defer></script>');
const transferScript = html.indexOf('<script src="./file-transfer-ui.js" defer></script>');
if (baseController < 0 || modelScript <= baseController || controllerScript <= modelScript || transferScript <= controllerScript) {
  fail('v3 model/controller must load after base UX and before file-transfer presentation');
}

for (const token of [
  '@media (forced-colors: active)',
  '@media (prefers-contrast: more)',
  '@media (max-height: 720px)',
  '.terminal-preferences-v3',
  '.terminal-quick-actions',
]) {
  if (!css.includes(token)) {
    fail(`missing v3 accessibility/window contract ${JSON.stringify(token)}`);
  }
}

const presentationSource = `${controller}\n${model}`;
for (const token of [
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
  'fingerprint',
  'grant',
  'wireStream',
]) {
  if (presentationSource.includes(token)) {
    fail(`v3 presentation contains forbidden authority token ${JSON.stringify(token)}`);
  }
}

for (const token of [
  'cursorStyle',
  'cursorBlink',
  'focusActiveTerminalV3',
  'cycleTerminalTabV3',
  'resetTerminalAppearanceV3',
  'shortcutAction',
  'cyclicIndex',
]) {
  if (!presentationSource.includes(token)) {
    fail(`missing v3 runtime behavior ${JSON.stringify(token)}`);
  }
}

if (/terminal_(?:resize|stream_open)|core_connect|core_disconnect/.test(controller)) {
  fail('v3 controller must not alter terminal dimensions or Core session lifecycle');
}

for (const token of [
  'normalizeCursorPreferences',
  'shortcutAction',
  'cyclicIndex',
  'applyCursorPreferences',
]) {
  if (!tests.includes(token)) {
    fail(`v3 behavior tests do not cover ${JSON.stringify(token)}`);
  }
}

console.log('Desktop UX v3 accessibility and interaction contract verified.');
