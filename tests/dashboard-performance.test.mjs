import assert from 'node:assert/strict';
import test from 'node:test';

import { DashboardPage } from '../static/js/modules/components/dashboard.js';

test('dashboard checks DNS providers concurrently', async t => {
  const previousFetch = globalThis.fetch;
  let activeRequests = 0;
  let maximumActiveRequests = 0;

  globalThis.fetch = async () => {
    activeRequests++;
    maximumActiveRequests = Math.max(maximumActiveRequests, activeRequests);
    await new Promise(resolve => setTimeout(resolve, 10));
    activeRequests--;
    return { ok: true };
  };
  t.after(() => {
    globalThis.fetch = previousFetch;
  });

  const dashboard = DashboardPage();
  await dashboard.checkProviderHealth();

  assert.equal(maximumActiveRequests, 2);
  assert.deepEqual(
    dashboard.providerStatus.map(provider => provider.status),
    ['online', 'online']
  );
});
