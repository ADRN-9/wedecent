import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const html = await readFile(resolve(root, 'dist/index.html'), 'utf8');
const source = await readFile(resolve(root, 'dist/file-transfer-ui.js'), 'utf8');

const fail = (message) => {
  throw new Error(`renderer file-transfer boundary: ${message}`);
};

if (/<input\b[^>]*\btype\s*=\s*["']?file\b/i.test(html)) {
  fail('HTML file inputs are forbidden; native Tauri pickers own local file selection');
}

const forbidden = [
  'file://',
  '__TAURI__.fs',
  'plugin-fs',
  'showOpenFilePicker',
  'showSaveFilePicker',
  'wd-desktop-bridge',
  'terminal_bridge_request',
  'file-upload-open',
  'file-upload-write',
  'file-upload-commit',
  'file-download-open',
  'file-download-read',
  'file-cancel',
  'localPath',
  'local_path',
  'fingerprint',
  'grant',
  'wireStream',
  'streamId',
];
for (const token of forbidden) {
  if (source.includes(token)) {
    fail(`forbidden renderer token ${JSON.stringify(token)}`);
  }
}

const commandMatches = [...source.matchAll(/getInvoke\(\)\('([^']+)'/g)].map((match) => match[1]);
const allowedCommands = new Set([
  'file_transfer_status',
  'file_upload_pick',
  'file_download_pick',
]);
if (commandMatches.length !== 3 || commandMatches.some((command) => !allowedCommands.has(command))) {
  fail(`unexpected native command surface: ${JSON.stringify(commandMatches)}`);
}
for (const command of allowedCommands) {
  if (!commandMatches.includes(command)) {
    fail(`missing fixed native command ${command}`);
  }
}

const appScript = html.indexOf('<script src="./app.js" defer></script>');
const fileScript = html.indexOf('<script src="./file-transfer-ui.js" defer></script>');
if (appScript < 0 || fileScript <= appScript) {
  fail('file-transfer UI must load after the authoritative terminal renderer state');
}

console.log('Renderer file-transfer authority boundary verified.');
