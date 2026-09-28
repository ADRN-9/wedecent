import assert from 'node:assert/strict';
import test from 'node:test';

await import('../dist/ux-model.js');

const model = globalThis.WeDecentUXModel;

if (!model) {
  throw new Error('UX behavior model unavailable');
}

test('filter matching and count summaries remain deterministic', () => {
  const rows = ['Alpha Device', 'Beta Device', 'Gamma Node'];
  const query = ' device ';
  const visible = rows.filter((row) => model.matchesFilter(row, query));
  assert.deepEqual(visible, ['Alpha Device', 'Beta Device']);
  assert.deepEqual(model.listSummary(rows.length, visible.length, query, 'devices'), {
    text: '2/3',
    ariaLabel: '2 of 3 devices',
  });
  assert.deepEqual(model.listSummary(rows.length, rows.length, '', 'devices'), {
    text: '3',
    ariaLabel: '3 devices',
  });
});

test('tab keyboard navigation wraps and honors Home/End', () => {
  assert.equal(model.tabTargetIndex(0, 'ArrowLeft', 3), 2);
  assert.equal(model.tabTargetIndex(2, 'ArrowRight', 3), 0);
  assert.equal(model.tabTargetIndex(1, 'Home', 3), 0);
  assert.equal(model.tabTargetIndex(1, 'End', 3), 2);
  assert.equal(model.tabTargetIndex(1, 'Enter', 3), 1);
  assert.equal(model.tabTargetIndex(-1, 'ArrowRight', 3), -1);
});

test('focus after close prefers the next surviving tab and falls back left', () => {
  assert.equal(model.focusIndexAfterClose(0, 3), 0);
  assert.equal(model.focusIndexAfterClose(1, 3), 1);
  assert.equal(model.focusIndexAfterClose(2, 3), 1);
  assert.equal(model.focusIndexAfterClose(0, 1), -1);
});

test('terminal preferences are bounded and versioned', () => {
  assert.deepEqual(model.normalizePreferences({ fontSize: 18, density: 'spacious' }), {
    fontSize: 18,
    density: 'spacious',
  });
  assert.deepEqual(model.normalizePreferences({ fontSize: 99, density: 'dense' }), {
    fontSize: 14,
    density: 'comfortable',
  });
  assert.deepEqual(model.parsePreferences('{"version":1,"fontSize":12,"density":"compact"}'), {
    fontSize: 12,
    density: 'compact',
  });
  assert.deepEqual(model.parsePreferences('{"version":2,"fontSize":20,"density":"spacious"}'), {
    fontSize: 14,
    density: 'comfortable',
  });
  assert.equal(model.densityLineHeight('compact'), 1);
  assert.equal(model.densityLineHeight('comfortable'), 1.2);
  assert.equal(model.densityLineHeight('spacious'), 1.4);
});
