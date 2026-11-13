import assert from 'node:assert/strict';
import test from 'node:test';

import { copyTextToClipboard } from '../static/js/modules/utils.js';

function mockClipboard(t, writeText) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    value: { clipboard: { writeText } }
  });
  t.after(() => {
    if (descriptor) Object.defineProperty(globalThis, 'navigator', descriptor);
    else delete globalThis.navigator;
  });
}

test('copyTextToClipboard writes the requested text', async t => {
  let copied;
  mockClipboard(t, async text => { copied = text; });

  await copyTextToClipboard('DNS results');

  assert.equal(copied, 'DNS results');
});

test('copyTextToClipboard logs clipboard errors with the caller-specific message', async t => {
  const error = new Error('Clipboard unavailable');
  mockClipboard(t, async () => { throw error; });
  const logged = t.mock.method(console, 'error', () => {});

  await copyTextToClipboard('DNS results', 'Copy failed:');

  assert.deepEqual(logged.mock.calls[0].arguments, ['Copy failed:', error]);
});
