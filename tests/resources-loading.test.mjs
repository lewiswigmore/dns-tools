import assert from 'node:assert/strict';
import test from 'node:test';

import { ResourcesPage } from '../static/js/modules/components/resources.js';

test('library shows loading until its knowledge base is available', { timeout: 2000 }, async t => {
  const previousWindow = globalThis.window;
  const previousHistory = globalThis.history;
  globalThis.window = { location: { href: 'http://localhost/resources', search: '' } };
  globalThis.history = { replaceState() {} };
  t.after(() => {
    globalThis.window = previousWindow;
    globalThis.history = previousHistory;
  });

  const page = ResourcesPage();
  page.init();
  assert.equal(page.loadingLibrary, true);
  for (let attempt = 0; page.loadingLibrary && attempt < 100; attempt++) {
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.equal(page.loadingLibrary, false);
  assert.equal(page.libraryError, '');
  assert.ok(page.knowledgeBase.length > 0);
  page.searchQuery = 'no-such-concept-xyz';
  assert.equal(page.filteredKnowledgeBase.length, 0);
});
