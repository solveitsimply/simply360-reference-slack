import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeProof } from '../dist/index.js';

test('proof descriptor names the three Slack surfaces and provider-neutral hello', () => {
  const info = describeProof();
  assert.deepEqual(
    [...info.provenSurfaces].sort(),
    ['EVENT_DESTINATION', 'INBOUND_TRIGGER', 'REMOTE_ACTION'],
  );
  assert.ok(info.scenarios.includes('provider-neutral-simply360-oauth-install'));
  assert.ok(info.scenarios.includes('refresh-replay-family-revocation'));
});

test('proof targets only the dedicated synthetic dev workspace', () => {
  const info = describeProof();
  assert.equal(info.slackWorkspace, 'Simply360 Developer Test');
  assert.equal(info.slackApp, 'Simply360 Reference for Slack (Dev)');
});
