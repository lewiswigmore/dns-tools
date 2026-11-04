import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

import { IntelPage } from '../static/js/modules/components/intel.js';
import { DNSClient } from '../static/js/modules/dns-client.js';

globalThis.localStorage = { getItem: () => null, setItem: () => {} };
globalThis.window = {};

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

function mockLookups(t) {
  const pending = [];
  t.mock.method(globalThis, 'fetch', async address => {
    const url = new URL(address);
    if (url.hostname === 'data.iana.org') {
      return { ok: true, json: async () => ({ services: [[['com'], ['https://rdap.example/']]] }) };
    }
    assert.equal(url.hostname, 'rdap.example');
    return {
      ok: true,
      json: async () => ({
        objectClassName: 'domain',
        events: [{ eventAction: 'registration', eventDate: '2000-01-01T00:00:00Z' }]
      })
    };
  });
  t.mock.method(DNSClient.prototype, 'queryDNS', (domain, type) => {
    if (type !== 'A') return Promise.resolve([]);
    const response = deferred();
    pending.push({ domain, ...response });
    return response.promise;
  });
  return pending;
}

async function analyze(page, target) {
  page.query = target;
  await page.analyze();
}

test('completed assessment is attributed to its domain and cleared for a new target', async t => {
  const pending = mockLookups(t);
  const page = IntelPage();
  await analyze(page, 'GOOGLE.COM');
  const check = page.runFraudCheck();
  pending[0].resolve([]);
  await check;
  assert.ok(page.fraud.data.indicators.some(ind => ind.label === 'Established registration age'));
  const checkedDomain = page.fraud.data.domain;

  await analyze(page, 'github.com');
  assert.equal(page.results.target, 'github.com');
  assert.equal(page.fraud.data, null, 'Google registration age must not remain under GitHub');
  assert.equal(page.fraud.error, null);
  assert.equal(page.fraud.loading, false);
  assert.equal(checkedDomain, 'google.com');
});

for (const state of ['completed', 'pending', 'failed']) {
  for (const change of ['input', 'preset']) {
    test(`${change} clears a ${state} check before Analyze is pressed`, async t => {
      const pending = mockLookups(t);
      const page = IntelPage();
      await analyze(page, 'github.com');
      const check = page.runFraudCheck();
      if (state === 'completed') pending[0].resolve([]);
      if (state === 'failed') pending[0].reject(new Error('Current check failed'));
      if (state !== 'pending') await check;

      if (change === 'preset') {
        page.applyPreset('google.com');
      } else {
        const template = readFileSync(new URL('../templates/intel.html', import.meta.url), 'utf8');
        const handler = template.match(/<input[^>]*x-model="query"[^>]*@input="([^"]+)"/);
        assert.ok(handler, 'The target input must invalidate the current assessment');
        page.query = 'google.com';
        runInNewContext(handler[1], { resetFraudCheck: page.resetFraudCheck.bind(page) });
      }
      assert.equal(page.fraud.data, null);
      assert.equal(page.fraud.error, null);
      assert.equal(page.fraud.loading, false);
      if (state === 'pending') {
        pending[0].resolve([]);
        await check;
        assert.equal(page.fraud.data, null);
      }
      await page.runFraudCheck();
      assert.equal(pending.length, 1, 'Do not check the old analyzed target while the input has changed');
    });
  }
}

test('a late response cannot repopulate an unchecked new target', async t => {
  const pending = mockLookups(t);
  const page = IntelPage();
  await analyze(page, 'google.com');
  const oldCheck = page.runFraudCheck();
  await analyze(page, 'github.com');
  pending[0].resolve([]);
  await oldCheck;
  assert.equal(page.fraud.data, null);
  assert.equal(page.fraud.error, null);
  assert.equal(page.fraud.loading, false);
});

for (const oldOutcome of ['success', 'failure']) {
  for (const oldFinishesFirst of [true, false]) {
    test(`out-of-order ${oldOutcome}: old check finishes ${oldFinishesFirst ? 'before' : 'after'} the new check`, async t => {
      const pending = mockLookups(t);
      const page = IntelPage();
      await analyze(page, 'google.com');
      const oldCheck = page.runFraudCheck();
      await analyze(page, 'github.com');
      const newCheck = page.runFraudCheck();

      const finishOld = async () => {
        if (oldOutcome === 'failure') pending[0].reject(new Error('Old check failed'));
        else pending[0].resolve([]);
        await oldCheck;
      };
      if (oldFinishesFirst) {
        await finishOld();
        assert.equal(page.fraud.loading, true, 'An obsolete finally must not finish the active check');
        assert.equal(page.fraud.error, null, 'An obsolete error must not affect the active check');
        assert.equal(page.fraud.data, null);
      }

      pending[1].resolve([{ value: '192.0.2.1' }]);
      await newCheck;
      const currentData = page.fraud.data;
      assert.equal(currentData.domain, 'github.com');
      assert.equal(page.fraud.loading, false);
      if (!oldFinishesFirst) await finishOld();
      assert.equal(page.fraud.data, currentData, 'An obsolete response must not replace the assessment');
      assert.equal(page.fraud.error, null);
    });
  }
}

test('leaving a domain and returning to it does not revive its previous request', async t => {
  const pending = mockLookups(t);
  const page = IntelPage();
  await analyze(page, 'google.com');
  const oldCheck = page.runFraudCheck();
  await analyze(page, 'github.com');
  await analyze(page, 'google.com');
  pending[0].resolve([]);
  await oldCheck;
  assert.equal(page.fraud.data, null);
});

test('same-domain rechecks keep only the latest request', async t => {
  const pending = mockLookups(t);
  const page = IntelPage();
  await analyze(page, 'google.com');
  const first = page.runFraudCheck();
  const second = page.runFraudCheck();
  pending[1].resolve([{ value: '192.0.2.1' }]);
  await second;
  const latest = page.fraud.data;
  pending[0].resolve([]);
  await first;
  assert.equal(page.fraud.data, latest);
});

for (const target of ['8.8.8.8', '44d88612fea8a8f36de82e1278abb02f4', 'not a domain', '']) {
  test(`switching to ${JSON.stringify(target)} discards the domain check`, async t => {
    const pending = mockLookups(t);
    const page = IntelPage();
    await analyze(page, 'google.com');
    const check = page.runFraudCheck();
    await analyze(page, target);
    pending[0].resolve([]);
    await check;
    assert.equal(page.fraud.data, null);
    assert.equal(page.fraud.error, null);
    assert.equal(page.fraud.loading, false);
  });
}

test('active failures are visible and can be retried', async t => {
  const pending = mockLookups(t);
  const page = IntelPage();
  await analyze(page, 'google.com');
  const failed = page.runFraudCheck();
  pending[0].reject(new Error('Current check failed'));
  await failed;
  assert.equal(page.fraud.error, 'Fraud risk check failed. Please try again.');
  assert.equal(page.fraud.loading, false);
  const retry = page.runFraudCheck();
  assert.equal(page.fraud.error, null);
  pending[1].resolve([]);
  await retry;
  assert.equal(page.fraud.data.domain, 'google.com');
});
