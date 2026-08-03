import { test } from 'node:test';
import assert from 'node:assert/strict';
import { signWebhookV2, verifyWebhookV2 } from '../dist/index.js';

const body =
  '{"eventSimplyId":"EVNT-0001-AAAA","teamSimplyId":"TEAM-0001-AAAA","teamIntegrationSimplyId":"TINT-0001-AAAA","eventType":"dataRecord.created","protocolVersion":2,"payloadSchemaId":"simply360.event.data-record/v1","payloadSchemaVersion":1,"occurredAt":"2026-07-28T12:00:00.000Z","payload":{"eventType":"dataRecord.created","dataCollectionSimplyId":"COLL-0001-AAAA","dataRecordSimplyId":"RECD-0001-AAAA"}}';
const fields = {
  timestampUnixSeconds: 1_785_242_800,
  eventId: 'EVNT-0001-AAAA',
  deliveryId: 'DLVR-0001-AAAA',
  attemptId: 'ATMP-0001-AAAA',
};
const key = { kid: 'current-2026-07', secret: 'test-signing-secret-with-enough-entropy' };

test('webhook v2 accepts exact bytes and all signed coordinates', () => {
  const signatureHeader = signWebhookV2(body, fields, key);
  const result = verifyWebhookV2({
    rawBody: body,
    signatureHeader,
    keys: [key],
    now: fields.timestampUnixSeconds * 1000,
    identityHeaders: {
      eventId: fields.eventId,
      deliveryId: fields.deliveryId,
      attemptId: fields.attemptId,
      timestampUnixSeconds: fields.timestampUnixSeconds,
    },
  });
  assert.equal(result.ok, true);
  assert.match(signatureHeader, /^v2;kid=current-2026-07;t=/);
});

test('webhook v2 rejects body tampering, stale attempts and identity mismatch', () => {
  const signatureHeader = signWebhookV2(body, fields, key);
  assert.deepEqual(
    verifyWebhookV2({ rawBody: `${body} `, signatureHeader, keys: [key], now: fields.timestampUnixSeconds * 1000 }),
    { ok: false, code: 'SIGNATURE_MISMATCH', message: 'HMAC signature does not match' },
  );
  assert.equal(
    verifyWebhookV2({ rawBody: body, signatureHeader, keys: [key], now: (fields.timestampUnixSeconds + 301) * 1000 }).code,
    'TIMESTAMP_OUT_OF_WINDOW',
  );
  assert.equal(
    verifyWebhookV2({
      rawBody: body,
      signatureHeader,
      keys: [key],
      now: fields.timestampUnixSeconds * 1000,
      identityHeaders: { attemptId: 'ATMP-0001-BBBB' },
    }).code,
    'IDENTITY_HEADER_MISMATCH',
  );
});

test('webhook v2 accepts only current and explicitly overlapping previous keys', () => {
  const previous = { kid: 'previous-2026-06', secret: 'previous-signing-secret-with-enough-entropy' };
  const signatureHeader = signWebhookV2(body, fields, previous);
  assert.equal(
    verifyWebhookV2({ rawBody: body, signatureHeader, keys: [key, previous], now: fields.timestampUnixSeconds * 1000 }).ok,
    true,
  );
  assert.equal(
    verifyWebhookV2({ rawBody: body, signatureHeader, keys: [key], now: fields.timestampUnixSeconds * 1000 }).code,
    'UNKNOWN_KEY',
  );
  assert.equal(
    verifyWebhookV2({
      rawBody: body,
      signatureHeader,
      keys: [key, previous, { kid: 'third', secret: 'third-signing-secret-with-enough-entropy' }],
      now: fields.timestampUnixSeconds * 1000,
    }).code,
    'INVALID_KEY_SET',
  );
});
