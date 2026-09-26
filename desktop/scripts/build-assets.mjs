import { copyFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(await readFile(resolve(root, 'node_modules/@xterm/xterm/package.json'), 'utf8'));
if (pkg.version !== '6.0.0') {
  throw new Error(`unexpected @xterm/xterm version ${pkg.version}`);
}

const vendor = resolve(root, 'dist/vendor');
await mkdir(vendor, { recursive: true });
await copyFile(resolve(root, 'node_modules/@xterm/xterm/lib/xterm.js'), resolve(vendor, 'xterm.js'));
await copyFile(resolve(root, 'node_modules/@xterm/xterm/css/xterm.css'), resolve(vendor, 'xterm.css'));
await copyFile(resolve(root, 'node_modules/@xterm/xterm/LICENSE'), resolve(vendor, 'XTERM-LICENSE'));
