import assert from 'node:assert/strict';
import test from 'node:test';

import { CommandPalette } from '../static/js/modules/components/command-palette.js';

test('command palette loads searchable knowledge-base actions when opened', async t => {
  const listeners = {};
  const previousWindow = globalThis.window;
  globalThis.window = {
    addEventListener: (event, listener) => { listeners[event] = listener; }
  };
  t.after(() => {
    if (previousWindow === undefined) delete globalThis.window;
    else globalThis.window = previousWindow;
  });

  const palette = CommandPalette();
  palette.$nextTick = () => {};
  palette.init();

  assert.ok(palette.allActions.some(action => action.type === 'Navigation'));
  assert.ok(!palette.allActions.some(action => action.type === 'Security Concept'));

  listeners['open-command-palette']();
  await palette.conceptActionsPromise;

  assert.ok(palette.allActions.some(action => action.type === 'Security Concept'));
  palette.query = 'Azure Networking';
  palette.filterItems();
  assert.ok(palette.items.some(action => action.title === 'Azure Networking Basics'));
  palette.close();
});
