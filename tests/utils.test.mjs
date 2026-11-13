import assert from 'node:assert/strict';
import test from 'node:test';

import {
  commonDomainPresets,
  copyTextToClipboard,
  initializeDomainLookup,
} from '../static/js/modules/utils.js';

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

test('commonDomainPresets returns independent page preset lists', () => {
  const first = commonDomainPresets();
  const second = commonDomainPresets();

  assert.deepEqual(first, [
    { label: 'google.com', value: 'google.com' },
    { label: 'microsoft.com', value: 'microsoft.com' },
    { label: 'openai.com', value: 'openai.com' },
  ]);
  assert.notEqual(first, second);
  assert.notEqual(first[0], second[0]);
});

test('initializeDomainLookup sets a URL domain and schedules its lookup', async t => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'window');
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: { location: { search: '?domain=example.com' } },
  });
  t.after(() => {
    if (descriptor) Object.defineProperty(globalThis, 'window', descriptor);
    else delete globalThis.window;
  });

  let scheduledLookup;
  const schedule = t.mock.method(globalThis, 'setTimeout', callback => {
    scheduledLookup = callback;
  });
  let lookupCount = 0;
  const page = { domain: '', performLookup() { lookupCount += 1; } };

  initializeDomainLookup(page);

  assert.equal(page.domain, 'example.com');
  assert.equal(schedule.mock.calls[0].arguments[1], 100);
  assert.equal(lookupCount, 0);
  scheduledLookup();
  assert.equal(lookupCount, 1);
});

test('initializeDomainLookup leaves pages unchanged without a domain parameter', t => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'window');
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: { location: { search: '?target=example.com' } },
  });
  t.after(() => {
    if (descriptor) Object.defineProperty(globalThis, 'window', descriptor);
    else delete globalThis.window;
  });

  const schedule = t.mock.method(globalThis, 'setTimeout', () => {});
  const page = { domain: 'existing.example', performLookup() {} };

  initializeDomainLookup(page);

  assert.equal(page.domain, 'existing.example');
  assert.equal(schedule.mock.callCount(), 0);
});
