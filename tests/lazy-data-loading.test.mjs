import assert from 'node:assert/strict';
import test from 'node:test';

import { CommandPalette } from '../static/js/modules/components/command-palette.js';

test('command palette loads intelligence actions when opened', async t => {
  const previousWindow = globalThis.window;
  const previousDocument = globalThis.document;
  const listeners = new Map();
  globalThis.window = {
    addEventListener: (event, listener) => listeners.set(event, listener)
  };
  globalThis.document = {
    getElementById: () => ({ focus() {} })
  };
  t.after(() => {
    if (previousWindow === undefined) delete globalThis.window;
    else globalThis.window = previousWindow;
    if (previousDocument === undefined) delete globalThis.document;
    else globalThis.document = previousDocument;
  });

  const palette = CommandPalette();
  palette.$nextTick = callback => callback();
  palette.init();

  assert.equal(palette.intelActionsPromise, null);
  assert.equal(palette.allActions.some(action => action.type === 'Security Concept'), false);

  listeners.get('open-command-palette')();
  await palette.intelActionsPromise;

  assert.ok(palette.allActions.some(action => action.type === 'Security Concept'));
  palette.query = 'security';
  palette.filterItems();
  assert.ok(palette.items.some(action => action.type === 'Security Concept'));
  palette.close();
});
