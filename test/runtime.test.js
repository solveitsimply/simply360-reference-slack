import { createHmac } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  LocalSimply360Double,
  LocalSlackDouble,
  MemoryIdempotencyStore,
  SlackReferenceRuntime,
  signWebhookV2,
} from '../dist/index.js';

const key = { kid: 'current', secret: 'event-secret-with-enough-entropy' };
const signingSecret = 'slack-signing-secret';
const nowSeconds = 1_785_242_800;

const fixture = () => {
  const slack = new LocalSlackDouble();
  const simply360 = new LocalSimply360Double();
  const runtime = new SlackReferenceRuntime(
    {
      teamSimplyId: 'TEAM-0001-AAAA',
      teamIntegrationSimplyId: 'TINT-0001-AAAA',
      slackTeamId: 'T00000001',
      eventSigningKeys: [key],
      slackSigningSecrets: [signingSecret],
      eventChannel: 'C123456789',
    },
    slack,
    simply360,
    new MemoryIdempotencyStore(),
    new MemoryIdempotencyStore(),
    new MemoryIdempotencyStore(),
  );
  return { slack, simply360, runtime };
};

test('signed event delivery posts an allowlisted summary and dedupes retries', async () => {
  const { slack, runtime } = fixture();
  const body = JSON.stringify({
    eventSimplyId: 'EVNT-0001-AAAA',
    teamSimplyId: 'TEAM-0001-AAAA',
    teamIntegrationSimplyId: 'TINT-0001-AAAA',
    eventType: 'dataRecord.created',
    protocolVersion: 2,
    payloadSchemaId: 'simply360.event.data-record/v1',
    payloadSchemaVersion: 1,
    occurredAt: '2026-07-28T12:00:00.000Z',
    payload: {
      eventType: 'dataRecord.created',
      dataCollectionSimplyId: 'COLL-0001-AAAA',
      dataRecordSimplyId: 'RECD-0001-AAAA',
    },
  });
  const fields = {
    timestampUnixSeconds: nowSeconds,
    eventId: 'EVNT-0001-AAAA',
    deliveryId: 'DLVR-0001-AAAA',
    attemptId: 'ATMP-0001-AAAA',
  };
  const signatureHeader = signWebhookV2(body, fields, key);
  assert.equal(await runtime.receiveEvent({ rawBody: body, signatureHeader, now: nowSeconds * 1000 }), 'DELIVERED');
  assert.equal(await runtime.receiveEvent({ rawBody: body, signatureHeader, now: nowSeconds * 1000 }), 'DUPLICATE');
  assert.equal(slack.messages.length, 1);
  assert.match(slack.messages[0].text, /dataRecord\.created/);
});

test('event delivery rejects cross-installation payloads despite a valid HMAC', async () => {
  const { runtime } = fixture();
  const body = JSON.stringify({
    eventSimplyId: 'EVNT-0001-AAAA',
    teamSimplyId: 'TEAM-0001-AAAA',
    teamIntegrationSimplyId: 'TINT-0001-BBBB',
    eventType: 'dataRecord.created',
    protocolVersion: 2,
    payloadSchemaId: 'simply360.event.data-record/v1',
    payloadSchemaVersion: 1,
    occurredAt: '2026-07-28T12:00:00.000Z',
    payload: {
      eventType: 'dataRecord.created',
      dataCollectionSimplyId: 'COLL-0001-AAAA',
      dataRecordSimplyId: 'RECD-0001-AAAA',
    },
  });
  const signatureHeader = signWebhookV2(
    body,
    {
      timestampUnixSeconds: nowSeconds,
      eventId: 'EVNT-0001-AAAA',
      deliveryId: 'DLVR-0001-AAAA',
      attemptId: 'ATMP-0001-AAAA',
    },
    key,
  );
  await assert.rejects(runtime.receiveEvent({ rawBody: body, signatureHeader, now: nowSeconds * 1000 }), /does not belong/);
});

test('provider action validates input and has exactly-once provider idempotency', async () => {
  const { slack, runtime } = fixture();
  const input = { channel: 'C123456789', text: 'A safe update' };
  const first = await runtime.sendToChannel(input, 'action:installation:0001');
  const replay = await runtime.sendToChannel(input, 'action:installation:0001');
  assert.deepEqual(replay, first);
  assert.equal(slack.messages.length, 1);
  await assert.rejects(runtime.sendToChannel({ ...input, adminId: 42 }, 'action:installation:0002'), /unknown property/);
});

test('provider action collapses concurrent retries and rejects key reuse with different input', async () => {
  const { slack, runtime } = fixture();
  const input = { channel: 'C123456789', text: 'A concurrent update' };
  const [left, right] = await Promise.all([
    runtime.sendToChannel(input, 'action:installation:concurrent'),
    runtime.sendToChannel(input, 'action:installation:concurrent'),
  ]);
  assert.deepEqual(left, right);
  assert.equal(slack.messages.length, 1);
  await assert.rejects(
    runtime.sendToChannel(
      { channel: 'C123456789', text: 'A different update' },
      'action:installation:concurrent',
    ),
    /already used for a different request/,
  );
});

test('public event contract rejects undeclared payload data and lifecycle traffic on the event destination', async () => {
  const { runtime } = fixture();
  const base = {
    eventSimplyId: 'EVNT-0001-AAAA',
    teamSimplyId: 'TEAM-0001-AAAA',
    teamIntegrationSimplyId: 'TINT-0001-AAAA',
    eventType: 'dataRecord.created',
    protocolVersion: 2,
    payloadSchemaId: 'simply360.event.data-record/v1',
    payloadSchemaVersion: 1,
    occurredAt: '2026-07-28T12:00:00.000Z',
    payload: {
      eventType: 'dataRecord.created',
      dataCollectionSimplyId: 'COLL-0001-AAAA',
      dataRecordSimplyId: 'RECD-0001-AAAA',
      confidentialField: 'not declared',
    },
  };
  const body = JSON.stringify(base);
  const signatureHeader = signWebhookV2(
    body,
    {
      timestampUnixSeconds: nowSeconds,
      eventId: base.eventSimplyId,
      deliveryId: 'DLVR-0001-AAAB',
      attemptId: 'ATMP-0001-AAAB',
    },
    key,
  );
  await assert.rejects(
    runtime.receiveEvent({ rawBody: body, signatureHeader, now: nowSeconds * 1000 }),
    /unknown property/,
  );

  const lifecycle = {
    ...base,
    eventType: 'app.uninstalled',
    protocolVersion: 1,
    payloadSchemaId: 'simply360.event.app-lifecycle/v1',
    payload: {
      eventType: 'app.uninstalled',
      integrationInstallationOperationSimplyId: 'IOPS-0001-AAAA',
      appSlug: 'reference-slack',
      appVersion: '1.0.0',
      idempotencyKey: 'uninstall-TINT-0001-AAAA',
    },
  };
  const lifecycleBody = JSON.stringify(lifecycle);
  const lifecycleSignature = signWebhookV2(
    lifecycleBody,
    {
      timestampUnixSeconds: nowSeconds,
      eventId: lifecycle.eventSimplyId,
      deliveryId: 'DLVR-0001-AAAC',
      attemptId: 'ATMP-0001-AAAC',
    },
    key,
  );
  await assert.rejects(
    runtime.receiveEvent({
      rawBody: lifecycleBody,
      signatureHeader: lifecycleSignature,
      now: nowSeconds * 1000,
    }),
    /does not belong/,
  );
});

test('Slack-signed explicit message shortcut publishes one trigger and rejects tampering', async () => {
  const { simply360, runtime } = fixture();
  const payload = JSON.stringify({
    type: 'message_action',
    callback_id: 's360_create_record',
    trigger_id: '13345224609.738474920.8088930838d88f008e0',
    team: { id: 'T00000001' },
    channel: { id: 'C123456789' },
    user: { id: 'U00000001' },
    message: { ts: '1785242800.0001', text: 'Create a record' },
  });
  const body = new URLSearchParams({ payload }).toString();
  const signature = `v0=${createHmac('sha256', signingSecret).update(`v0:${nowSeconds}:${body}`).digest('hex')}`;
  assert.deepEqual(
    await runtime.receiveSlackRequest({ rawBody: body, signature, timestamp: String(nowSeconds), now: nowSeconds * 1000 }),
    { outcome: 'TRIGGERED' },
  );
  assert.deepEqual(
    await runtime.receiveSlackRequest({ rawBody: body, signature, timestamp: String(nowSeconds), now: nowSeconds * 1000 }),
    { outcome: 'DUPLICATE' },
  );
  assert.equal(simply360.triggers.length, 1);
  await assert.rejects(
    runtime.receiveSlackRequest({ rawBody: `${body} `, signature, timestamp: String(nowSeconds), now: nowSeconds * 1000 }),
    /SIGNATURE_MISMATCH/,
  );
});

test('Slack-signed shortcut rejects a different Slack workspace before publishing', async () => {
  const { simply360, runtime } = fixture();
  const payload = JSON.stringify({
    type: 'message_action',
    callback_id: 's360_create_record',
    trigger_id: '13345224609.738474920.8088930838d88f008e0',
    team: { id: 'T99999999' },
    channel: { id: 'C123456789' },
    user: { id: 'U00000001' },
    message: { ts: '1785242800.0002', text: 'Wrong workspace' },
  });
  const body = new URLSearchParams({ payload }).toString();
  const signature = `v0=${createHmac('sha256', signingSecret).update(`v0:${nowSeconds}:${body}`).digest('hex')}`;
  await assert.rejects(
    runtime.receiveSlackRequest({ rawBody: body, signature, timestamp: String(nowSeconds), now: nowSeconds * 1000 }),
    /does not belong to this installation/,
  );
  assert.equal(simply360.triggers.length, 0);
});

test('Slack-signed shortcut enforces the exact trigger schema and one payload field', async () => {
  const { simply360, runtime } = fixture();
  const invalidPayload = JSON.stringify({
    type: 'message_action',
    callback_id: 's360_create_record',
    trigger_id: '13345224609.738474920.8088930838d88f008e0',
    team: { id: 'T00000001' },
    channel: { id: 'X123456789' },
    user: { id: 'U00000001' },
    message: { ts: '1785242800.0003', text: 'Invalid channel shape' },
  });
  const body = new URLSearchParams({ payload: invalidPayload }).toString();
  const signature = `v0=${createHmac('sha256', signingSecret).update(`v0:${nowSeconds}:${body}`).digest('hex')}`;
  await assert.rejects(
    runtime.receiveSlackRequest({
      rawBody: body,
      signature,
      timestamp: String(nowSeconds),
      now: nowSeconds * 1000,
    }),
    /channel must be a Slack channel ID/,
  );

  const duplicatedBody = `${body}&payload=${encodeURIComponent(invalidPayload)}`;
  const duplicatedSignature = `v0=${createHmac('sha256', signingSecret)
    .update(`v0:${nowSeconds}:${duplicatedBody}`)
    .digest('hex')}`;
  await assert.rejects(
    runtime.receiveSlackRequest({
      rawBody: duplicatedBody,
      signature: duplicatedSignature,
      timestamp: String(nowSeconds),
      now: nowSeconds * 1000,
    }),
    /form is invalid/,
  );
  assert.equal(simply360.triggers.length, 0);
});
