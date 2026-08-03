import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const manifestUrl = new URL('../reference/slack-app-manifest.yaml', import.meta.url);

test('Slack app manifest declares the exact reviewed bot scopes for its message shortcut', async () => {
  const manifest = await readFile(manifestUrl, 'utf8');
  const botScopes = manifest.match(/^      - ([a-z:]+)$/gmu)?.map((line) => line.trim().slice(2)) ?? [];

  assert.deepEqual(botScopes, ['chat:write', 'commands']);
  assert.match(manifest, /^  shortcuts:\n    - name: Create Simply360 record$/mu);
  assert.match(manifest, /^  interactivity:\n    is_enabled: true$/mu);
});
