import assert from 'node:assert/strict';
import test from 'node:test';

import { HistoryPage } from '../static/js/modules/components/history.js';
import { IntelPage } from '../static/js/modules/components/intel.js';

test('history pagination preserves all filtered entries and resets on filtering', () => {
  const page = HistoryPage();
  page.history = Array.from({ length: 45 }, (_, i) => ({
    query: `domain${i}.example`, recordTypes: ['A'], success: true
  }));
  page.applyFilters();
  assert.equal(page.paginatedHistory.length, 20);
  page.goToPage(3);
  assert.equal(page.paginatedHistory.length, 5);
  assert.equal(page.paginatedHistory[0].query, 'domain40.example');
  page.searchFilter = 'domain1.';
  page.applyFilters();
  assert.equal(page.currentPage, 1);
  assert.deepEqual(page.paginatedHistory.map(item => item.query), ['domain1.example']);
  page.goToPage(99);
  assert.equal(page.currentPage, 1);
});

test('knowledge base pagination preserves search results and clamps page navigation', () => {
  const page = IntelPage();
  page.concepts = Array.from({ length: 23 }, (_, i) => ({
    id: `${i}`, title: `Concept ${i}`, summary: '', tags: ['Threat Intel']
  }));
  assert.equal(page.totalPages, 2);
  page.goToPage(2);
  assert.equal(page.paginatedConcepts.length, 3);
  assert.equal(page.paginatedConcepts[0].title, 'Concept 20');
  page.goToPage(99);
  assert.equal(page.currentPage, 2);
});
