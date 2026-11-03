import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

import { DMARCPage } from '../static/js/modules/components/dmarc.js';
import { DNSClient } from '../static/js/modules/dns-client.js';

globalThis.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };

const policy = 'v=DMARC1; p=reject; adkim=s; aspf=r; rua=mailto:reports@example.com; ruf=mailto:forensics@example.com';
const quotedPolicy = `"${policy}"`;
const splitPolicy = '"v=DM" "ARC1; p=rej" "ect; adkim=s; aspf=r; rua=mailto:reports@example.com; ruf=mailto:forensics@example.com"';
const unrelated = 'google-site-verification=example';

function mockResolvers(t, answers) {
  const requests = [];
  t.mock.method(globalThis, 'fetch', async (address, options) => {
    const url = new URL(address);
    const provider = { 'dns.google': 'Google', 'cloudflare-dns.com': 'Cloudflare' }[url.hostname];
    requests.push({ provider, name: url.searchParams.get('name'), type: url.searchParams.get('type'), accept: options.headers.Accept });
    const values = answers[provider] ?? [];
    return {
      ok: true,
      json: async () => ({
        Answer: values.map(value => ({
          name: `${url.searchParams.get('name')}.`,
          data: value,
          TTL: 300
        }))
      })
    };
  });
  return requests;
}

function createClient(primaryProvider = 'Google') {
  const client = new DNSClient();
  client.updateSettings({ primaryProvider, providers: ['Google', 'Cloudflare'] });
  return client;
}

function noRecordMessageIsVisible(page) {
  const template = readFileSync(new URL('../templates/dmarc.html', import.meta.url), 'utf8');
  const match = template.match(/<div x-show="([^"]+)"[^>]*>\s*<p[^>]*><i[^>]*><\/i>No DMARC record found/);
  assert.ok(match, 'Could not find the DMARC no-record message');
  return Boolean(runInNewContext(match[1], page));
}

function comparisonProviderText(page, provider) {
  const template = readFileSync(new URL('../templates/dmarc.html', import.meta.url), 'utf8');
  const scope = { ...page, provider };
  const visible = [];
  // Evaluate the shipped provider branches and text bindings, not a copy of their display logic.
  for (const [, condition, attributes, content] of template.matchAll(/<template x-if="([^"]+)">\s*<div([^>]*)>([\s\S]*?)<\/div>/g)) {
    if (!runInNewContext(condition, scope)) continue;
    const loop = content.match(/x-for="(\w+) in ([^"]+)"/);
    const scopes = loop
      ? runInNewContext(loop[2], scope).map(value => ({ ...scope, [loop[1]]: value }))
      : [scope];
    for (const context of scopes) {
      const bindings = [...`${attributes}${content}`.matchAll(/x-text="([^"]+)"/g)];
      if (bindings.length) {
        visible.push(...bindings.map(([, expression]) => String(runInNewContext(expression, context))));
      } else {
        visible.push(content.replace(/<[^>]*>/g, '').trim());
      }
    }
  }
  return visible.join('\n');
}

async function lookupPage(t, answers, compareMode = true) {
  mockResolvers(t, answers);
  const client = createClient();
  const queryDNS = client.queryDNS.bind(client);
  // Inject explicit provider errors at the query seam; transport fallback behavior is unchanged.
  t.mock.method(client, 'queryDNS', async (domain, type, providerUrl) => {
    const provider = providerUrl
      ? { 'dns.google': 'Google', 'cloudflare-dns.com': 'Cloudflare' }[new URL(providerUrl).hostname]
      : client.settings.primaryProvider;
    if (answers[provider] instanceof Error) throw answers[provider];
    return queryDNS(domain, type, providerUrl);
  });
  globalThis.window = { dnsClient: client };
  t.after(() => { delete globalThis.window; });
  const page = DMARCPage();
  page.domain = 'example.com';
  page.compareMode = compareMode;
  await page.performLookup();
  return page;
}

for (const [provider, value] of [
  ['Google', policy],
  ['Cloudflare', quotedPolicy],
  ['Cloudflare', splitPolicy]
]) {
  test(`single-provider DMARC lookup parses ${provider} ${value === splitPolicy ? 'split' : value === quotedPolicy ? 'quoted' : 'unquoted'} TXT`, async t => {
    const requests = mockResolvers(t, { [provider]: [unrelated, value] });
    const { result } = await createClient(provider).performDMARCLookup('example.com');

    assert.ok(result, `${provider} incorrectly reported no DMARC record`);
    assert.deepEqual(result, {
      raw: value,
      policy: 'reject',
      adkim: 's',
      aspf: 'r',
      rua: 'mailto:reports@example.com',
      ruf: 'mailto:forensics@example.com'
    });
    assert.deepEqual(requests, [{
      provider,
      name: '_dmarc.example.com',
      type: 'TXT',
      accept: 'application/dns-json'
    }]);
  });
}

for (const cloudflarePolicy of [quotedPolicy, splitPolicy]) {
  test(`provider comparison parses ${cloudflarePolicy === splitPolicy ? 'split' : 'quoted'} Cloudflare TXT and unquoted Google TXT`, async t => {
    const requests = mockResolvers(t, {
      Google: [unrelated, policy],
      Cloudflare: [unrelated, cloudflarePolicy]
    });
    const { comparison } = await createClient().performDMARCComparison('example.com');

    for (const [provider, raw] of [['Google', policy], ['Cloudflare', cloudflarePolicy]]) {
      assert.equal(comparison[provider].status, 'success');
      assert.ok(comparison[provider].dmarc, `${provider} incorrectly reported no DMARC record`);
      assert.equal(comparison[provider].dmarc.p, 'reject');
      assert.equal(comparison[provider].dmarc.adkim, 's');
      assert.equal(comparison[provider].dmarc.aspf, 'r');
      assert.equal(comparison[provider].dmarc.rua, 'mailto:reports@example.com');
      assert.equal(comparison[provider].dmarc.ruf, 'mailto:forensics@example.com');
      assert.equal(comparison[provider].dmarc.raw, raw);
      assert.deepEqual(comparison[provider].records.map(record => record.value), [unrelated, raw]);
    }
    assert.deepEqual(requests.map(request => request.provider).sort(), ['Cloudflare', 'Google']);
    assert.ok(requests.every(request => request.name === '_dmarc.example.com' && request.type === 'TXT'));
  });
}

test('DNS-escaped characters in quoted chunks are parsed without changing the raw record', async t => {
  const raw = '"v=DMARC\\049\\059 p=reject\\059 rua=mailto:reports@example.com"';
  mockResolvers(t, { Cloudflare: [raw] });

  const { result } = await createClient('Cloudflare').performDMARCLookup('example.com');

  assert.ok(result);
  assert.equal(result.policy, 'reject');
  assert.equal(result.rua, 'mailto:reports@example.com');
  assert.equal(result.raw, raw);
});

test('escaped quotes and backslashes remain literal data in parsed tags', async t => {
  const raw = '"v=DMARC1; p=reject; note=a\\"b\\\\c"';
  mockResolvers(t, { Cloudflare: [raw] });

  const { comparison } = await createClient().performDMARCComparison('example.com');

  assert.equal(comparison.Cloudflare.dmarc.p, 'reject');
  assert.equal(comparison.Cloudflare.dmarc.note, 'a"b\\c');
  assert.equal(comparison.Cloudflare.dmarc.raw, raw);
});

test('adjacent, empty and whitespace-separated quoted chunks form one TXT value', async t => {
  const raw = '  "" "v=DMARC1; p=qua""rantine; adkim=s"  ';
  mockResolvers(t, { Google: [raw], Cloudflare: [raw] });
  const client = createClient('Cloudflare');

  const { result } = await client.performDMARCLookup('example.com');
  const { comparison } = await client.performDMARCComparison('example.com');

  assert.equal(result.policy, 'quarantine');
  assert.equal(result.adkim, 's');
  assert.equal(result.raw, raw);
  assert.equal(comparison.Google.dmarc.p, 'quarantine');
  assert.equal(comparison.Cloudflare.dmarc.p, 'quarantine');
  assert.equal(comparison.Cloudflare.dmarc.raw, raw);
});

for (const [domain, expected] of [
  ['google.com', 'reject'],
  ['example.com', 'reject'],
  ['github.com', 'quarantine'],
  ['iana.org', 'none']
]) {
  test(`both providers return the ${expected} policy for ${domain}`, async t => {
    const raw = `v=DMARC1; p=${expected}; rua=mailto:reports@example.com`;
    mockResolvers(t, { Google: [raw], Cloudflare: [`"${raw}"`] });
    const client = createClient();

    for (const provider of ['Google', 'Cloudflare']) {
      client.updateSettings({ primaryProvider: provider, providers: ['Google', 'Cloudflare'] });
      assert.equal((await client.performDMARCLookup(domain)).result.policy, expected);
    }
    const { comparison } = await client.performDMARCComparison(domain);
    assert.equal(comparison.Google.dmarc.p, expected);
    assert.equal(comparison.Cloudflare.dmarc.p, expected);
  });
}

test('a TXT tag named raw cannot overwrite the original comparison record', async t => {
  const raw = '"v=DMARC1; p=reject; raw=not-the-original-record"';
  mockResolvers(t, { Google: [raw], Cloudflare: [raw] });

  const { comparison } = await createClient().performDMARCComparison('example.com');

  assert.equal(comparison.Cloudflare.dmarc.p, 'reject');
  assert.equal(comparison.Cloudflare.dmarc.raw, raw);
});

test('provider comparison keeps different resolver policies independent', async t => {
  mockResolvers(t, {
    Google: ['v=DMARC1; p=reject'],
    Cloudflare: ['"v=DMARC1; p=none"']
  });

  const { comparison } = await createClient().performDMARCComparison('example.com');

  assert.equal(comparison.Google.dmarc.p, 'reject');
  assert.equal(comparison.Cloudflare.dmarc.p, 'none');
});

for (const value of [
  unrelated,
  '"v=spf1; p=reject"',
  'v=DMARC10; p=reject',
  '"v=DMARC1extra; p=reject"',
  '"v=DM\\"ARC1; p=reject"',
  '"v=DMARC1; p=reject" "unterminated',
  '"v=DMARC1\\256; p=reject"'
]) {
  test(`non-DMARC TXT is not reported as a DMARC policy: ${value}`, async t => {
    mockResolvers(t, { Google: [value], Cloudflare: [value] });
    const client = createClient('Cloudflare');

    assert.equal((await client.performDMARCLookup('example.com')).result, null);
    const { comparison } = await client.performDMARCComparison('example.com');
    assert.equal(comparison.Google.dmarc, null);
    assert.equal(comparison.Cloudflare.dmarc, null);
    assert.equal(comparison.Cloudflare.records[0].value, value);
  });
}

test('generic TXT lookup and comparison preserve resolver records unchanged', async t => {
  mockResolvers(t, { Google: [policy, unrelated], Cloudflare: [splitPolicy, unrelated] });
  const client = createClient('Cloudflare');

  const lookup = await client.performLookup('example.com', ['TXT']);
  const comparison = await client.performComparison('example.com', ['TXT']);

  assert.deepEqual(lookup.results[0].records.TXT.map(record => record.value), [splitPolicy, unrelated]);
  assert.deepEqual(comparison.results[0].comparisons.TXT.Google.records.map(record => record.value), [policy, unrelated]);
  assert.deepEqual(comparison.results[0].comparisons.TXT.Cloudflare.records.map(record => record.value), [splitPolicy, unrelated]);
});

test('comparison results do not also show the no-record message', async t => {
  mockResolvers(t, { Google: [policy], Cloudflare: [quotedPolicy] });
  globalThis.window = { dnsClient: createClient() };
  t.after(() => { delete globalThis.window; });
  const page = DMARCPage();
  page.domain = 'example.com';
  page.compareMode = true;

  await page.performLookup();

  assert.equal(page.comparisonResult.Google.dmarc.p, 'reject');
  assert.equal(page.comparisonResult.Cloudflare.dmarc.p, 'reject');
  assert.equal(noRecordMessageIsVisible(page), false);
});

test('the no-record message remains visible for a missing single-provider record', async t => {
  mockResolvers(t, { Cloudflare: [unrelated] });
  globalThis.window = { dnsClient: createClient('Cloudflare') };
  t.after(() => { delete globalThis.window; });
  const page = DMARCPage();
  page.domain = 'example.com';

  await page.performLookup();

  assert.equal(page.result, null);
  assert.equal(noRecordMessageIsVisible(page), true);
});

test('a successful single-provider lookup hides the no-record message', async t => {
  mockResolvers(t, { Cloudflare: [quotedPolicy] });
  globalThis.window = { dnsClient: createClient('Cloudflare') };
  t.after(() => { delete globalThis.window; });
  const page = DMARCPage();
  page.domain = 'example.com';

  await page.performLookup();

  assert.equal(page.result.policy, 'reject');
  assert.equal(noRecordMessageIsVisible(page), false);
});

for (const answers of [
  { Google: [unrelated], Cloudflare: [unrelated] },
  { Google: [], Cloudflare: [] }
]) {
  test(`comparison displays confirmed DMARC absence with ${answers.Google.length ? 'unrelated' : 'empty'} TXT answers`, async t => {
    const page = await lookupPage(t, answers);

    for (const provider of ['Google', 'Cloudflare']) {
      assert.equal(comparisonProviderText(page, provider), 'No DMARC record found');
    }
    assert.equal(noRecordMessageIsVisible(page), false);
  });
}

test('comparison displays only the matching policy, not unrelated TXT returned first', async t => {
  const page = await lookupPage(t, {
    Google: [unrelated, policy],
    Cloudflare: [unrelated, splitPolicy]
  });

  assert.equal(comparisonProviderText(page, 'Google'), policy);
  assert.equal(comparisonProviderText(page, 'Cloudflare'), splitPolicy);
  assert.equal(noRecordMessageIsVisible(page), false);
});

for (const missingAnswer of [[], [unrelated]]) {
  test(`comparison distinguishes a p=none policy from ${missingAnswer.length ? 'unrelated' : 'empty'} TXT at another provider`, async t => {
    const monitorPolicy = '"v=DMARC1; p=none"';
    const page = await lookupPage(t, { Google: [monitorPolicy], Cloudflare: missingAnswer });

    assert.equal(comparisonProviderText(page, 'Google'), monitorPolicy);
    assert.equal(comparisonProviderText(page, 'Cloudflare'), 'No DMARC record found');
    assert.equal(noRecordMessageIsVisible(page), false);
  });
}

for (const successfulAnswer of [[], [unrelated], [quotedPolicy]]) {
  const description = successfulAnswer.includes(quotedPolicy) ? 'policy' : successfulAnswer.length ? 'unrelated TXT' : 'empty TXT';
  test(`comparison keeps an explicit provider error distinct from a successful ${description} result`, async t => {
    const page = await lookupPage(t, {
      Google: new Error('Google resolver unavailable'),
      Cloudflare: successfulAnswer
    });

    assert.equal(comparisonProviderText(page, 'Google'), 'Lookup failed: Google resolver unavailable');
    assert.equal(comparisonProviderText(page, 'Cloudflare'),
      successfulAnswer.includes(quotedPolicy) ? quotedPolicy : 'No DMARC record found');
    assert.equal(noRecordMessageIsVisible(page), false);
  });
}

test('comparison shows resolver failures, not DMARC absence, when both providers fail', async t => {
  const page = await lookupPage(t, {
    Google: new Error('Google resolver unavailable'),
    Cloudflare: new Error('Cloudflare resolver unavailable')
  });

  for (const provider of ['Google', 'Cloudflare']) {
    assert.equal(comparisonProviderText(page, provider), `Lookup failed: ${provider} resolver unavailable`);
  }
  assert.equal(noRecordMessageIsVisible(page), false);
});

test('a failed single-provider lookup does not claim DMARC absence', async t => {
  const page = await lookupPage(t, { Google: new Error('Google resolver unavailable') }, false);

  assert.equal(page.error, 'Failed to lookup DMARC record for example.com');
  assert.equal(noRecordMessageIsVisible(page), false);
});

test('copied comparison results distinguish policy, absence and explicit provider failures', async t => {
  const page = await lookupPage(t, {
    Google: [unrelated, policy],
    Cloudflare: [unrelated]
  });
  const copied = t.mock.method(page, 'copyToClipboard', async () => {});

  await page.copyAllResults();

  const text = copied.mock.calls[0].arguments[0];
  assert.ok(text.includes(policy));
  assert.ok(text.includes('No DMARC record found'));
  assert.ok(!text.includes(unrelated));

  window.dnsClient.performDMARCComparison = async () => ({
    comparison: {
      Google: { status: 'error', error: 'Google resolver unavailable', dmarc: null }
    }
  });
  await page.performLookup();
  await page.copyAllResults();

  const failedText = copied.mock.calls[1].arguments[0];
  assert.ok(failedText.includes('Lookup failed: Google resolver unavailable'));
  assert.ok(!failedText.includes('No DMARC record found'));
  assert.ok(!failedText.includes('undefined'));
});
