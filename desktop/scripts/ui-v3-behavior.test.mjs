import assert from 'node:assert/strict';
import test from 'node:test';

await import('../dist/ux-v3-model.js');

const model = globalThis.WeDecentUXV3Model;

if (!model) {
  throw new Error('UX v3 behavior model unavailable');
}

test('cursor preferences are bounded and versioned', () => {
  assert.deepEqual(model.normalizeCursorPreferences({ cursorStyle: 'bar', cursorBlink: false }), {
    cursorStyle: 'bar',
    cursorBlink: false,
  });
  assert.deepEqual(model.normalizeCursorPreferences({ cursorStyle: 'beam', cursorBlink: 'yes' }), {
    cursorStyle: 'block',
    cursorBlink: true,
  });
  assert.deepEqual(model.parseCursorPreferences('{"version":1,"cursorStyle":"underline","cursorBlink":false}'), {
    cursorStyle: 'underline',
    cursorBlink: false,
  });
  assert.deepEqual(model.parseCursorPreferences('{"version":2,"cursorStyle":"bar","cursorBlink":false}'), {
    cursorStyle: 'block',
    cursorBlink: true,
  });
});

test('terminal shortcuts are explicit and do not match modified variants', () => {
  assert.equal(model.shortcutAction({ key: 't', altKey: true }), 'focus-terminal');
  assert.equal(model.shortcutAction({ key: 'PageUp', ctrlKey: true }), 'previous-tab');
  assert.equal(model.shortcutAction({ key: 'PageDown', metaKey: true }), 'next-tab');
  assert.equal(model.shortcutAction({ key: 'PageDown', ctrlKey: true, shiftKey: true }), 'none');
  assert.equal(model.shortcutAction({ key: 't', altKey: true, ctrlKey: true }), 'none');
});

test('cyclic tab selection wraps deterministically', () => {
  assert.equal(model.cyclicIndex(0, 3, -1), 2);
  assert.equal(model.cyclicIndex(2, 3, 1), 0);
  assert.equal(model.cyclicIndex(-1, 3, 1), 1);
  assert.equal(model.cyclicIndex(0, 0, 1), -1);
});

test('cursor preferences mutate presentation only and refresh bounded rows', () => {
  const refreshes = [];
  const terminal = {
    options: { cols: 80, rows: 24 },
    rows: 24,
    refresh(start, end) {
      refreshes.push([start, end]);
    },
  };

  assert.equal(model.applyCursorPreferences(terminal, { cursorStyle: 'bar', cursorBlink: false }), true);
  assert.equal(terminal.options.cursorStyle, 'bar');
  assert.equal(terminal.options.cursorBlink, false);
  assert.equal(terminal.options.cols, 80);
  assert.equal(terminal.options.rows, 24);
  assert.deepEqual(refreshes, [[0, 23]]);
  assert.equal(model.applyCursorPreferences(null, {}), false);
});
