import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  adaptHelloRouterToApiGateway,
  createHelloLambdaHandler,
  resolveHelloWebhookKeyBinding,
} from '../dist/index.js';

const NOW = Date.UTC(2026, 8, 6, 12, 0, 0);
const CURRENT = {
  kid: 'whk_AAAAAAAAAAAAAAAAAAAAAAAA',
  secret: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
};
const PREVIOUS = {
  kid: 'whk_BBBBBBBBBBBBBBBBBBBBBBBB',
  secret: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
  validUntil: new Date(NOW + 60_000).toISOString(),
};

const runtimeSecret = (overrides = {}) => JSON.stringify({
  helloStateEncryptionKeyCurrent: '0123456789abcdef0123456789abcdef',
  simply360WebhookKeyBindings: [{
    teamSimplyId: 'TEAM-0001-AAAA',
    teamIntegrationSimplyId: 'TINT-0001-AAAA',
    current: CURRENT,
    previous: PREVIOUS,
  }],
  unrelatedCoResidentSetting: 'preserved',
  ...overrides,
});

const environment = (overrides = {}) => ({
  AWS_REGION: 'us-east-1',
  HELLO_STATE_TABLE_NAME: 'simply360-reference-slack-dev-hello-state',
  HELLO_RUNTIME_SECRET_ID: 's360/reference-slack/dev/runtime',
  S360_AUTHORIZATION_ENDPOINT: 'https://api.dev.simply360.app/oauth/authorize',
  S360_TOKEN_ENDPOINT: 'https://api.dev.simply360.app/oauth/token',
  S360_CLIENT_ID: 'hello-public-native-client',
  S360_REDIRECT_URI: 'https://reference-slack.dev.simply360.app/oauth/simply360/callback',
  S360_INTEGRATION_PUBLISHER_SIMPLY_ID: 'IPUB-0001-AAAA',
  S360_INTEGRATION_APP_SIMPLY_ID: 'IAPP-0001-AAAA',
  S360_INTEGRATION_APP_VERSION_SIMPLY_ID: 'IAVR-0001-AAAA',
  S360_INTEGRATION_APP_RELEASE_SIMPLY_ID: 'IARL-0001-AAAA',
  S360_INTEGRATION_APP_OAUTH_CLIENT_SIMPLY_ID: 'IAOC-0001-AAAA',
  S360_OAUTH_SCOPES: 'records:read,offline_access',
  S360_EVENT_TYPES: 'dataRecord.created',
  S360_LIFECYCLE_EVENT_TYPES: 'app.uninstalled,app.grant.revoked',
  ...overrides,
});

test('adapts the API Gateway v2 bytes, query, normalized headers, and cookies', async () => {
  const handled = [];
  const adapter = adaptHelloRouterToApiGateway({
    handle: async (request) => {
      handled.push(request);
      return { statusCode: 202, headers: { 'X-Test': 'accepted' }, body: '{"ok":true}' };
    },
  });
  const result = await adapter({
    rawPath: '/events/simply360',
    rawQueryString: 'state=a%20b&code=c',
    requestContext: { http: { method: 'post' } },
    headers: { 'Content-Type': 'application/json' },
    cookies: ['s360_hello_nonce=second'],
    body: Buffer.from('{"snowman":"☃"}').toString('base64'),
    isBase64Encoded: true,
  });
  assert.deepEqual(result, {
    statusCode: 202,
    headers: { 'X-Test': 'accepted' },
    body: '{"ok":true}',
    isBase64Encoded: false,
  });
  assert.equal(handled[0].method, 'POST');
  assert.equal(handled[0].path, '/events/simply360');
  assert.deepEqual(Object.fromEntries(Object.entries(handled[0].query)), { state: 'a b', code: 'c' });
  assert.equal(handled[0].headers['content-type'], 'application/json');
  assert.equal(handled[0].headers.cookie, 's360_hello_nonce=second');
  assert.equal(Buffer.from(handled[0].body).toString(), '{"snowman":"☃"}');
});

test('preserves the sanitized signed uninstall cleanup receipt response', async () => {
  const cleanupReceipt = {
    schemaVersion: 'simply360.reference-slack.installation-cleanup-receipt/v1',
    installationSimplyId: 'TINT-0001-AAAA',
    integrationInstallationOperationSimplyId: 'OPER-0001-AAAA',
    eventSimplyId: 'EVNT-0001-AAAA',
    verifiedBodySha256: 'a'.repeat(64),
    outcome: 'CLEANED',
  };
  const adapter = adaptHelloRouterToApiGateway({
    handle: async () => ({
      statusCode: 200,
      headers: {
        'Cache-Control': 'no-store',
        'Content-Type': 'application/json; charset=utf-8',
      },
      body: JSON.stringify({ outcome: 'CLEANED', cleanupReceipt }),
    }),
  });
  const result = await adapter({
    rawPath: '/lifecycle',
    requestContext: { http: { method: 'POST' } },
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
  assert.equal(result.statusCode, 200);
  assert.equal(result.headers['Cache-Control'], 'no-store');
  assert.deepEqual(JSON.parse(result.body), { outcome: 'CLEANED', cleanupReceipt });
  assert.doesNotMatch(result.body, /signature|secret|token/iu);
});

test('rejects API Gateway requests without exact method/path context before routing', async () => {
  const adapter = adaptHelloRouterToApiGateway({ handle: async () => {
    throw new Error('router must not be reached');
  } });
  await assert.rejects(adapter({ rawPath: '/healthz', requestContext: {} }), /request context is incomplete/u);
  await assert.rejects(adapter({
    rawPath: '/oauth/simply360/callback',
    rawQueryString: 'state=first&state=second&code=code',
    requestContext: { http: { method: 'GET' } },
  }), /duplicate query parameter/u);
  await assert.rejects(adapter({
    rawPath: '/healthz',
    requestContext: { http: { method: 'GET' } },
    headers: { Cookie: 'first=one' },
    cookies: ['second=two'],
  }), /duplicate cookie input/u);
});

test('resolves current and bounded overlapping previous keys to one exact installation', () => {
  assert.deepEqual(resolveHelloWebhookKeyBinding(runtimeSecret(), CURRENT.kid, NOW), {
    teamSimplyId: 'TEAM-0001-AAAA',
    teamIntegrationSimplyId: 'TINT-0001-AAAA',
    keys: [CURRENT, { kid: PREVIOUS.kid, secret: PREVIOUS.secret }],
  });
  assert.deepEqual(resolveHelloWebhookKeyBinding(runtimeSecret(), PREVIOUS.kid, NOW), {
    teamSimplyId: 'TEAM-0001-AAAA',
    teamIntegrationSimplyId: 'TINT-0001-AAAA',
    keys: [CURRENT, { kid: PREVIOUS.kid, secret: PREVIOUS.secret }],
  });
  assert.equal(resolveHelloWebhookKeyBinding(runtimeSecret(), PREVIOUS.kid, NOW + 60_001), null);
  assert.equal(resolveHelloWebhookKeyBinding(runtimeSecret(), 'whk_CCCCCCCCCCCCCCCCCCCCCCCC', NOW), null);
});

test('fails closed on duplicate kid custody, malformed coordinates, malformed JSON, and oversized secrets', () => {
  const duplicate = runtimeSecret({
    simply360WebhookKeyBindings: [
      {
        teamSimplyId: 'TEAM-0002-BBBB',
        teamIntegrationSimplyId: 'TINT-0001-AAAA',
        current: CURRENT,
      },
      {
        teamSimplyId: 'TEAM-0002-BBBB',
        teamIntegrationSimplyId: 'TINT-0002-BBBB',
        current: CURRENT,
      },
    ],
  });
  assert.throws(() => resolveHelloWebhookKeyBinding(duplicate, CURRENT.kid, NOW), /globally unique/u);
  const duplicateInstallation = runtimeSecret({
    simply360WebhookKeyBindings: [
      {
        teamSimplyId: 'TEAM-0001-AAAA',
        teamIntegrationSimplyId: 'TINT-0001-AAAA',
        current: CURRENT,
      },
      {
        teamSimplyId: 'TEAM-0002-BBBB',
        teamIntegrationSimplyId: 'TINT-0001-AAAA',
        current: { kid: 'whk_CCCCCCCCCCCCCCCCCCCCCCCC', secret: CURRENT.secret },
      },
    ],
  });
  assert.throws(() => resolveHelloWebhookKeyBinding(duplicateInstallation, CURRENT.kid, NOW), /installation bindings must be unique/u);
  assert.throws(() => resolveHelloWebhookKeyBinding(runtimeSecret({
    simply360WebhookKeyBindings: [{
      teamSimplyId: 'TEAM-0001-AAAA',
      teamIntegrationSimplyId: 'TINT-0001-AAAA',
      current: CURRENT,
      previous: { ...PREVIOUS, validUntil: new Date(NOW + 7 * 24 * 60 * 60 * 1_000 + 1).toISOString() },
    }],
  }), CURRENT.kid, NOW), /overlap exceeds seven days/u);
  assert.throws(() => resolveHelloWebhookKeyBinding(runtimeSecret({
    simply360WebhookKeyBindings: [{
      teamSimplyId: 'not-a-simply-id',
      teamIntegrationSimplyId: 'TINT-0001-AAAA',
      current: CURRENT,
    }],
  }), CURRENT.kid, NOW));
  assert.throws(() => resolveHelloWebhookKeyBinding('{', CURRENT.kid, NOW), /unavailable/u);
  assert.throws(() => resolveHelloWebhookKeyBinding('x'.repeat(65 * 1024), CURRENT.kid, NOW), /unavailable/u);
});

test('keeps subscription and lifecycle declarations on their exact public channels', () => {
  assert.equal(typeof createHelloLambdaHandler({ environment: environment() }), 'function');
  assert.throws(() => createHelloLambdaHandler({ environment: environment({
    S360_EVENT_TYPES: 'app.uninstalled',
  }) }));
  assert.throws(() => createHelloLambdaHandler({ environment: environment({
    S360_LIFECYCLE_EVENT_TYPES: 'dataRecord.created',
  }) }));
});
