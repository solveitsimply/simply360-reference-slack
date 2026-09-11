import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';

import { signWebhookV2 } from '@simply360/integration-sdk';

import { HelloHostedRouter, HelloLifecycleFencedError } from '../dist/index.js';

const NOW = Date.UTC(2026, 8, 6, 12, 0, 0);
const TEAM = 'TEAM-0001-AAAA';
const INSTALLATION = 'TINT-0001-AAAA';
const KEY = {
  kid: 'whk_AAAAAAAAAAAAAAAAAAAAAAAA',
  secret: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
};

const oauth = (overrides = {}) => ({
  begin: async () => ({
    authorizationUrl: 'https://api.dev.simply360.app/oauth/authorize?state=opaque',
    state: 'opaque',
    browserNonce: 'browser nonce',
    expiresAt: new Date(NOW + 600_000).toISOString(),
  }),
  complete: async () => ({
    binding: {
      teamIntegrationSimplyId: INSTALLATION,
      teamUserLinkSimplyId: 'TUSR-0001-AAAA',
      integrationInstallationGrantSimplyId: 'IIUG-0001-AAAA',
    },
  }),
  ...overrides,
});

const state = (overrides = {}) => ({
  recordWebhookDelivery: async () => 'RECORDED',
  fenceAndCleanupInstallation: async () => ({ replayed: false }),
  fenceAndCleanupGrantAuthority: async () => ({ replayed: false }),
  ...overrides,
});

const router = (overrides = {}) => new HelloHostedRouter({
  oauth: oauth(overrides.oauth),
  state: state(overrides.state),
  resolveWebhookKey: overrides.resolveWebhookKey ?? (async (kid) => kid === KEY.kid ? {
    teamSimplyId: TEAM,
    teamIntegrationSimplyId: INSTALLATION,
    keys: [KEY],
  } : null),
  eventTypes: overrides.eventTypes ?? ['dataRecord.created'],
  lifecycleEventTypes: overrides.lifecycleEventTypes ?? ['app.install.completed', 'app.setup.completed', 'app.uninstalled', 'app.grant.revoked', 'app.account-link.revoked'],
  now: () => NOW,
});

const request = (overrides = {}) => ({
  method: 'GET',
  path: '/healthz',
  query: {},
  headers: {},
  body: Buffer.alloc(0),
  ...overrides,
});

const lifecyclePayload = (eventType, extra = {}) => ({
  eventType,
  integrationInstallationOperationSimplyId: 'OPER-0001-AAAA',
  appSlug: 'hello-private-dev',
  appVersion: '1.0.9',
  idempotencyKey: `lifecycle-${eventType}`,
  ...extra,
});

const occurrence = (eventType, payload, overrides = {}) => ({
  eventSimplyId: 'EVNT-0001-AAAA',
  teamSimplyId: TEAM,
  teamIntegrationSimplyId: INSTALLATION,
  eventType,
  protocolVersion: eventType.startsWith('app.') ? 1 : 2,
  payloadSchemaId: eventType.startsWith('app.') ? 'simply360.event.app-lifecycle/v1' : 'simply360.event.data-record/v1',
  payloadSchemaVersion: 1,
  occurredAt: new Date(NOW).toISOString(),
  payload,
  ...overrides,
});

const signedRequest = async (path, value, overrides = {}) => {
  const body = JSON.stringify(value);
  const signed = await signWebhookV2({
    key: KEY,
    timestampUnixSeconds: NOW / 1_000,
    eventId: value.eventSimplyId,
    deliveryId: 'DLVY-0001-AAAA',
    attemptId: 'ATTP-0001-AAAA',
    rawBody: body,
  });
  return request({
    method: 'POST',
    path,
    body: Buffer.from(body),
    headers: {
      'content-type': 'application/json',
      'x-s360-signature': signed.signatureHeaderValue,
      'x-s360-event-id': value.eventSimplyId,
      'x-s360-delivery-id': 'DLVY-0001-AAAA',
      'x-s360-attempt-id': 'ATTP-0001-AAAA',
    },
    ...overrides,
  });
};

test('exposes exactly the five reviewed routes and never exposes the legacy router', async () => {
  const instance = router();
  assert.equal((await instance.handle(request())).statusCode, 200);
  for (const [method, path] of [
    ['GET', '/'],
    ['POST', '/slack/events'],
    ['GET', '/oauth/slack/install'],
    ['POST', '/oauth/simply360/start'],
    ['GET', '/events/simply360'],
  ]) {
    const response = await instance.handle(request({ method, path }));
    assert.equal(response.statusCode, 404, `${method} ${path}`);
  }
});

test('starts hosted consent and binds callback completion to the secure browser nonce', async () => {
  const completions = [];
  const instance = router({ oauth: {
    complete: async (input) => {
      completions.push(input);
      return {
        binding: {
          teamIntegrationSimplyId: INSTALLATION,
          teamUserLinkSimplyId: 'TUSR-0001-AAAA',
          integrationInstallationGrantSimplyId: 'IIUG-0001-AAAA',
          accessToken: 'must-not-project',
        },
      };
    },
  } });
  const started = await instance.handle(request({ path: '/oauth/simply360/start' }));
  assert.equal(started.statusCode, 303);
  assert.match(started.headers.Location, /^https:\/\/api\.dev\.simply360\.app\/oauth\/authorize/u);
  assert.match(started.headers['Set-Cookie'], /HttpOnly; Secure; SameSite=Lax/u);
  assert.match(started.headers['Set-Cookie'], /Path=\/oauth\/simply360\/callback/u);

  const completed = await instance.handle(request({
    path: '/oauth/simply360/callback',
    query: { state: 'opaque', code: 'authorization-code' },
    headers: { cookie: 'other=x; s360_hello_nonce=browser%20nonce' },
  }));
  assert.equal(completed.statusCode, 200);
  assert.deepEqual(completions, [{ state: 'opaque', code: 'authorization-code', browserNonce: 'browser nonce' }]);
  assert.deepEqual(JSON.parse(completed.body), {
    outcome: 'CONNECTED',
    teamIntegrationSimplyId: INSTALLATION,
    teamUserLinkSimplyId: 'TUSR-0001-AAAA',
    integrationInstallationGrantSimplyId: 'IIUG-0001-AAAA',
  });
  assert.doesNotMatch(completed.body, /token/ui);
  assert.match(completed.headers['Set-Cookie'], /Max-Age=0/u);

  for (const query of [
    { state: 'opaque', code: 'code', error: 'denied' },
    { state: 'opaque' },
  ]) {
    const rejected = await instance.handle(request({
      path: '/oauth/simply360/callback', query, headers: { cookie: 's360_hello_nonce=browser%20nonce' },
    }));
    assert.equal(rejected.statusCode, 400);
  }
});

test('accepts a declared signed public event and rejects signature, identity, channel, and body violations', async () => {
  const recorded = [];
  const instance = router({ state: { recordWebhookDelivery: async (installation, evidence) => {
    recorded.push({ installation, evidence });
    return recorded.length === 1 ? 'RECORDED' : 'DUPLICATE';
  } } });
  const value = occurrence('dataRecord.created', {
    eventType: 'dataRecord.created',
    dataCollectionSimplyId: 'DCOL-0001-AAAA',
    dataRecordSimplyId: 'DREC-0001-AAAA',
  });
  const valid = await signedRequest('/events/simply360', value);
  assert.equal((await instance.handle(valid)).statusCode, 200);
  assert.equal(JSON.parse((await instance.handle(valid)).body).outcome, 'DUPLICATE');
  assert.equal(recorded[0].installation, INSTALLATION);
  assert.match(recorded[0].evidence.bodySha256, /^[a-f0-9]{64}$/u);

  const tampered = { ...valid, body: Buffer.from(valid.body.toString().replace('DREC-0001-AAAA', 'DREC-9999-ZZZZ')) };
  assert.equal((await instance.handle(tampered)).statusCode, 401);
  const wrongIdentity = { ...valid, headers: { ...valid.headers, 'x-s360-event-id': 'EVNT-9999-ZZZZ' } };
  assert.equal((await instance.handle(wrongIdentity)).statusCode, 401);
  assert.equal((await instance.handle(await signedRequest('/lifecycle', value))).statusCode, 403);
  assert.equal((await instance.handle({ ...valid, headers: { ...valid.headers, 'content-type': 'text/plain' } })).statusCode, 415);
  assert.equal((await instance.handle({ ...valid, body: Buffer.alloc(256 * 1024 + 1) })).statusCode, 413);
  assert.equal((await instance.handle({ ...valid, body: Buffer.from([0xff]) })).statusCode, 400);

  const wrongTeam = occurrence('dataRecord.created', value.payload, { teamSimplyId: 'TEAM-9999-ZZZZ' });
  assert.equal((await instance.handle(await signedRequest('/events/simply360', wrongTeam))).statusCode, 403);

  const undeclaredLifecycle = occurrence('app.suspended', lifecyclePayload('app.suspended'));
  assert.equal((await instance.handle(await signedRequest('/lifecycle', undeclaredLifecycle))).statusCode, 403);
});

test('durably fences uninstall and exact grant/account-link cleanup before acknowledging lifecycle delivery', async () => {
  const calls = [];
  let uninstallAttempts = 0;
  const instance = router({ state: {
    fenceAndCleanupInstallation: async (installation, evidence) => {
      calls.push({ kind: 'installation', installation, evidence });
      uninstallAttempts += 1;
      if (uninstallAttempts === 1) throw new Error('injected cleanup interruption');
      return { replayed: uninstallAttempts > 2 };
    },
    fenceAndCleanupGrantAuthority: async (installation, authority, evidence) => {
      calls.push({ kind: 'grant', installation, authority, evidence });
      return { replayed: false };
    },
  } });

  const uninstall = await signedRequest('/lifecycle', occurrence('app.uninstalled', lifecyclePayload('app.uninstalled')));
  const interrupted = await instance.handle(uninstall);
  assert.equal(interrupted.statusCode, 503);
  assert.deepEqual(JSON.parse(interrupted.body), { error: 'DELIVERY_RETRY_REQUIRED' });

  const cleaned = await instance.handle(uninstall);
  assert.equal(cleaned.statusCode, 200);
  const expectedCleanupIdentity = {
    schemaVersion: 'simply360.reference-slack.installation-cleanup-receipt/v1',
    installationSimplyId: INSTALLATION,
    integrationInstallationOperationSimplyId: 'OPER-0001-AAAA',
    eventSimplyId: 'EVNT-0001-AAAA',
    verifiedBodySha256: createHash('sha256').update(uninstall.body).digest('hex'),
  };
  assert.deepEqual(JSON.parse(cleaned.body), {
    outcome: 'CLEANED',
    cleanupReceipt: { ...expectedCleanupIdentity, outcome: 'CLEANED' },
  });

  const replayed = await instance.handle(uninstall);
  assert.equal(replayed.statusCode, 200);
  assert.deepEqual(JSON.parse(replayed.body), {
    outcome: 'DUPLICATE',
    cleanupReceipt: { ...expectedCleanupIdentity, outcome: 'REPLAYED' },
  });
  assert.equal(calls[0].installation, INSTALLATION);
  assert.equal(calls[0].evidence.eventSimplyId, 'EVNT-0001-AAAA');

  const revoked = await signedRequest('/lifecycle', occurrence('app.grant.revoked', lifecyclePayload('app.grant.revoked', {
    grantSimplyId: 'IIUG-0001-AAAA',
  })));
  assert.equal((await instance.handle(revoked)).statusCode, 200);
  assert.deepEqual(calls.at(-1).authority, {
    grant: 'simply360',
    integrationInstallationGrantSimplyId: 'IIUG-0001-AAAA',
  });

  const accountLinkRevoked = await signedRequest('/lifecycle', occurrence(
    'app.account-link.revoked',
    lifecyclePayload('app.account-link.revoked', {
      integrationProviderAccountLinkSimplyId: 'IPAL-0001-AAAA',
    }),
  ));
  assert.equal((await instance.handle(accountLinkRevoked)).statusCode, 200);
  assert.deepEqual(calls.at(-1).authority, {
    grant: 'provider',
    integrationProviderAccountLinkSimplyId: 'IPAL-0001-AAAA',
  });
});

test('never exports an uninstall receipt for invalid operation or installation authority', async () => {
  const cleanups = [];
  const instance = router({ state: {
    fenceAndCleanupInstallation: async (...args) => {
      cleanups.push(args);
      return { replayed: false };
    },
  } });
  const missingOperation = occurrence('app.uninstalled', {
    eventType: 'app.uninstalled',
    appSlug: 'hello-private-dev',
    appVersion: '1.0.9',
    idempotencyKey: 'lifecycle-app.uninstalled',
  });
  const invalid = await instance.handle(await signedRequest('/lifecycle', missingOperation));
  assert.equal(invalid.statusCode, 400);
  assert.deepEqual(JSON.parse(invalid.body), { error: 'INVALID_EVENT' });

  const wrongInstallation = occurrence(
    'app.uninstalled',
    lifecyclePayload('app.uninstalled'),
    { teamIntegrationSimplyId: 'TINT-9999-ZZZZ' },
  );
  const denied = await instance.handle(await signedRequest('/lifecycle', wrongInstallation));
  assert.equal(denied.statusCode, 403);
  assert.deepEqual(JSON.parse(denied.body), { error: 'EVENT_AUTHORITY_MISMATCH' });
  assert.deepEqual(cleanups, []);
  assert.doesNotMatch(invalid.body + denied.body, /cleanupReceipt/u);
});

test('maps a durable lifecycle fence to a non-retryable conflict', async () => {
  const instance = router({ state: {
    recordWebhookDelivery: async () => { throw new HelloLifecycleFencedError('cleaned'); },
  } });
  const value = occurrence('dataRecord.created', {
    eventType: 'dataRecord.created',
    dataCollectionSimplyId: 'DCOL-0001-AAAA',
    dataRecordSimplyId: 'DREC-0001-AAAA',
  });
  assert.equal((await instance.handle(await signedRequest('/events/simply360', value))).statusCode, 409);
});
