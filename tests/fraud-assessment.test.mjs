import assert from 'node:assert/strict';
import test from 'node:test';

import { assessDomainFraudRisk } from '../static/js/modules/fraud-assessment.js';

test('assessDomainFraudRisk shares RDAP and DNS results with the heuristic builder', async () => {
  const domain = 'example.com';
  const requests = [];
  const answers = {
    'example.com:A': [{ value: '192.0.2.1' }],
    'example.com:AAAA': [],
    'example.com:MX': [{ value: 'mail.example.com' }],
    'example.com:NS': [{ value: 'ns1.example.com' }],
    'example.com:TXT': [],
    '_dmarc.example.com:TXT': [],
  };
  const rdap = {
    keyDates: { registration: '2000-01-01T00:00:00Z' },
    status: [],
    roles: { registrant: { name: 'Example' } },
  };

  const assessment = await assessDomainFraudRisk(domain, {
    lookupDomain: async target => {
      requests.push(['RDAP', target]);
      return { result: rdap };
    },
    dnsClient: {
      queryDNS: async (target, type) => {
        requests.push([target, type]);
        return answers[`${target}:${type}`];
      },
    },
  });

  assert.deepEqual(requests, [
    ['RDAP', domain],
    [domain, 'A'],
    [domain, 'AAAA'],
    [domain, 'MX'],
    [domain, 'NS'],
    [domain, 'TXT'],
    [`_dmarc.${domain}`, 'TXT'],
  ]);
  assert.deepEqual(assessment.indicators.map(indicator => indicator.label), [
    'Established registration age',
    'Mail configured without authentication',
  ]);
  assert.equal(assessment.riskLevel, 'medium');
});

test('assessDomainFraudRisk treats RDAP failures as unavailable registration data', async () => {
  const assessment = await assessDomainFraudRisk('example.com', {
    lookupDomain: async () => { throw new Error('RDAP unavailable'); },
    dnsClient: { queryDNS: async () => [] },
  });

  assert.ok(assessment.indicators.some(
    indicator => indicator.label === 'Registration date unavailable'
  ));
});

test('assessDomainFraudRisk propagates DNS query failures', async () => {
  const error = new Error('DNS unavailable');

  await assert.rejects(
    assessDomainFraudRisk('example.com', {
      lookupDomain: async () => ({ result: null }),
      dnsClient: {
        queryDNS: async (_domain, type) => {
          if (type === 'A') throw error;
          return [];
        },
      },
    }),
    error
  );
});
