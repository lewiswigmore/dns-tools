import assert from 'node:assert/strict';
import test from 'node:test';

import { DNSClient } from '../static/js/modules/dns-client.js';

globalThis.localStorage = { getItem: () => null, setItem: () => {} };

function trackQueryConcurrency(client) {
  let active = 0;
  let maximum = 0;

  client.queryDNS = async (domain, recordType, providerUrl) => {
    active++;
    maximum = Math.max(maximum, active);
    await new Promise(resolve => setTimeout(resolve, 1));
    active--;
    return [{ value: `${domain}:${recordType}:${providerUrl || 'primary'}` }];
  };

  return () => maximum;
}

test('bulk DNS lookup runs multiple requests concurrently and preserves results', async () => {
  const client = new DNSClient();
  const getMaximumConcurrency = trackQueryConcurrency(client);

  const { results } = await client.performLookup(
    'one.example,two.example,three.example,four.example',
    ['A', 'MX', 'TXT']
  );

  assert.ok(getMaximumConcurrency() > 1);
  assert.ok(getMaximumConcurrency() <= 6);
  assert.deepEqual(results.map(result => result.domain), [
    'one.example', 'two.example', 'three.example', 'four.example'
  ]);
  assert.equal(results[0].records.A[0].value, 'one.example:A:primary');
  assert.equal(results[3].records.TXT[0].value, 'four.example:TXT:primary');
});

test('bulk DNS comparison bounds concurrent requests and keeps provider results', async () => {
  const client = new DNSClient();
  client.updateSettings({ primaryProvider: 'Google', providers: ['Google', 'Cloudflare'] });
  const getMaximumConcurrency = trackQueryConcurrency(client);

  const { results } = await client.performComparison(
    'one.example,two.example,three.example,four.example',
    ['A', 'MX', 'TXT']
  );

  assert.ok(getMaximumConcurrency() > 2);
  assert.ok(getMaximumConcurrency() <= 6);
  assert.deepEqual(results.map(result => result.domain), [
    'one.example', 'two.example', 'three.example', 'four.example'
  ]);
  assert.equal(results[0].comparisons.A.Google.records[0].value,
    'one.example:A:https://dns.google/resolve');
  assert.equal(results[3].comparisons.TXT.Cloudflare.records[0].value,
    'four.example:TXT:https://cloudflare-dns.com/dns-query');
});
