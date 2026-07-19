// Scaffold smoke test — verifies the placeholder descriptor is well-formed.
// Runs against the compiled ESM output in dist/ (npm test builds first).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeProof } from '../dist/index.js';

test('proof descriptor names the three Slack surfaces', () => {
  const info = describeProof();
  assert.deepEqual(
    [...info.provenSurfaces].sort(),
    ['EVENT_DESTINATION', 'INBOUND_TRIGGER', 'REMOTE_ACTION'],
  );
});

test('proof targets the dedicated synthetic dev workspace', () => {
  const info = describeProof();
  assert.equal(info.slackWorkspace, 'Simply360 Developer Test');
});
