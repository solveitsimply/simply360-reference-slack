import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  HelloOAuthClient,
  HelloOAuthCompletionUnknownError,
  HelloOAuthDeniedError,
  HelloOAuthRefreshUnavailableError,
  createHardenedHelloOAuthFetch,
} from '../dist/index.js';

const configuration = {
  authorizationEndpoint: 'https://api.dev.simply360.app/oauth/authorize',
  tokenEndpoint: 'https://api.dev.simply360.app/oauth/token',
  clientId: 'hello-public-native-client',
  redirectUri: 'https://reference-slack.dev.simply360.app/oauth/simply360/callback',
  allowedRedirectUris: ['https://reference-slack.dev.simply360.app/oauth/simply360/callback'],
  environment: 'dev',
  integrationPublisherSimplyId: 'IPUB-0001-AAAA',
  integrationAppSimplyId: 'IAPP-0001-AAAA',
  integrationAppVersionSimplyId: 'IAVR-0001-AAAA',
  integrationAppReleaseSimplyId: 'IARL-0001-AAAA',
  integrationAppOAuthClientSimplyId: 'IAOC-0001-AAAA',
  scopes: ['records:read', 'offline_access'],
};

const binding = (overrides = {}) => ({
  principalType: 'USER_DELEGATED',
  teamSimplyId: 'TEAM-0001-AAAA',
  teamIntegrationSimplyId: 'TINT-0001-AAAA',
  teamUserLinkSimplyId: 'TUSR-0001-AAAA',
  integrationInstallationEpochSimplyId: 'IIEP-0001-AAAA',
  integrationPublisherSimplyId: configuration.integrationPublisherSimplyId,
  integrationAppSimplyId: configuration.integrationAppSimplyId,
  integrationAppVersionSimplyId: configuration.integrationAppVersionSimplyId,
  integrationAppReleaseSimplyId: configuration.integrationAppReleaseSimplyId,
  integrationAppOAuthClientSimplyId: configuration.integrationAppOAuthClientSimplyId,
  integrationInstallationConsentSimplyId: 'IICS-0001-AAAA',
  integrationInstallationGrantSimplyId: 'IIUG-0001-AAAA',
  clientId: configuration.clientId,
  audience: 'urn:simply360:public-api',
  resource: 'urn:simply360:team-api',
  environment: 'dev',
  phase: 'ACTIVE',
  scopes: configuration.scopes,
  ...overrides,
});

const tokenResponse = (bindingOverrides = {}, tokenOverrides = {}) => ({
  access_token: 'access-token-value',
  refresh_token: 'refresh-token-value',
  token_type: 'Bearer',
  expires_in: 3600,
  scope: 'records:read offline_access',
  authorization_binding: binding(bindingOverrides),
  ...tokenOverrides,
});

const namespaceKey = (namespace) => JSON.stringify(namespace);

class MemoryHelloOAuthStore {
  intents = new Map();
  credentials = new Map();
  savedCredentials = [];

  constructor(now = Date.now) {
    this.now = now;
  }

  async createPendingOAuthIntent(state, browserNonce, expiresAt, value) {
    if (this.intents.has(state)) throw new Error('duplicate state');
    this.intents.set(state, { browserNonce, expiresAt, value });
  }

  async consumePendingOAuthIntent(state, browserNonce) {
    const intent = this.intents.get(state);
    if (!intent || intent.browserNonce !== browserNonce || intent.expiresAt.getTime() <= this.now()) {
      throw new Error('unavailable state');
    }
    this.intents.delete(state);
    return structuredClone(intent.value);
  }

  async loadCredential(namespace) {
    return structuredClone(this.credentials.get(namespaceKey(namespace)));
  }

  async saveCredential(namespace, value, expectedRevision) {
    const key = namespaceKey(namespace);
    const existing = this.credentials.get(key);
    if (
      (expectedRevision === null && existing !== undefined) ||
      (expectedRevision !== null && existing?.revision !== expectedRevision)
    ) {
      const error = new Error('hello state changed before the conditional write completed');
      error.name = 'ConcurrentHelloStateUpdateError';
      throw error;
    }
    const result = {
      revision: expectedRevision === null ? 1 : expectedRevision + 1,
      value: structuredClone(value),
    };
    this.credentials.set(key, result);
    this.savedCredentials.push({ namespace: structuredClone(namespace), ...structuredClone(result) });
    return structuredClone(result);
  }
}

const jsonResponse = (value, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => structuredClone(value),
  text: async () => JSON.stringify(value),
});

const startClient = async (fetchImpl) => {
  const now = Date.UTC(2026, 8, 6, 12, 0, 0);
  const store = new MemoryHelloOAuthStore(() => now);
  const client = new HelloOAuthClient({
    configuration,
    store,
    fetchImpl,
    now: () => now,
  });
  const started = await client.begin();
  return { client, store, started, now };
};

test('rejects a pending OAuth intent at its exact injected expiry without calling the token endpoint', async () => {
  let now = Date.UTC(2026, 8, 6, 12, 0, 0);
  let calls = 0;
  const store = new MemoryHelloOAuthStore(() => now);
  const client = new HelloOAuthClient({
    configuration,
    store,
    fetchImpl: async () => {
      calls += 1;
      return jsonResponse(tokenResponse());
    },
    now: () => now,
  });
  const started = await client.begin();
  now = Date.parse(started.expiresAt);

  await assert.rejects(
    client.complete({ state: started.state, browserNonce: started.browserNonce, code: 'expired-code' }),
    /unavailable state/u,
  );
  assert.equal(calls, 0);
});

test('begins a public NATIVE/NONE S256 flow without caller-selected Team or installation authority', async () => {
  const { store, started, now } = await startClient(async () => {
    throw new Error('token endpoint must not be called during begin');
  });
  const url = new URL(started.authorizationUrl);
  assert.equal(url.origin + url.pathname, configuration.authorizationEndpoint);
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('client_id'), configuration.clientId);
  assert.equal(url.searchParams.get('redirect_uri'), configuration.redirectUri);
  assert.equal(url.searchParams.get('scope'), 'records:read offline_access');
  assert.equal(url.searchParams.get('resource'), 'urn:simply360:team-api');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.match(url.searchParams.get('code_challenge'), /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(url.searchParams.get('state'), started.state);
  for (const forbidden of ['teamSimplyId', 'teamIntegrationSimplyId', 'installation_id', 'memberSimplyId', 'grant']) {
    assert.equal(url.searchParams.has(forbidden), false);
  }
  assert.match(started.state, /^[A-Za-z0-9_-]{43}$/u);
  assert.match(started.browserNonce, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(started.expiresAt, new Date(now + 10 * 60 * 1_000).toISOString());
  const pending = store.intents.get(started.state);
  assert.equal(pending.browserNonce, started.browserNonce);
  assert.equal(pending.value.clientId, configuration.clientId);
  assert.equal(pending.value.integrationAppSimplyId, configuration.integrationAppSimplyId);
  assert.match(pending.value.codeVerifier, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal('teamSimplyId' in pending.value, false);
  assert.equal('teamIntegrationSimplyId' in pending.value, false);
});

test('exchanges without client secret and stores the returned exact member grant namespace', async () => {
  const requests = [];
  const { client, store, started, now } = await startClient(async (url, init) => {
    requests.push({ url, init });
    return jsonResponse({
      ...tokenResponse(),
      internalAuthorityRevision: 99,
      subject: 'must-be-stripped-by-sdk',
    });
  });
  const result = await client.complete({
    state: started.state,
    browserNonce: started.browserNonce,
    code: 'authorization-code',
  });

  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, configuration.tokenEndpoint);
  assert.equal(requests[0].init.headers.Authorization, undefined);
  const body = new URLSearchParams(requests[0].init.body);
  assert.equal(body.get('grant_type'), 'authorization_code');
  assert.equal(body.get('client_id'), configuration.clientId);
  assert.equal(body.get('redirect_uri'), configuration.redirectUri);
  assert.equal(body.get('code'), 'authorization-code');
  assert.match(body.get('code_verifier'), /^[A-Za-z0-9_-]{43}$/u);
  assert.deepEqual(result.namespace, {
    teamIntegrationSimplyId: 'TINT-0001-AAAA',
    scope: 'member',
    memberSimplyId: 'TUSR-0001-AAAA',
    grant: 'simply360',
    integrationInstallationGrantSimplyId: 'IIUG-0001-AAAA',
  });
  assert.equal(store.savedCredentials.length, 1);
  assert.deepEqual(store.savedCredentials[0].namespace, result.namespace);
  assert.equal(store.savedCredentials[0].value.accessToken, 'access-token-value');
  assert.equal(store.savedCredentials[0].value.refreshToken, 'refresh-token-value');
  assert.equal(store.savedCredentials[0].value.expiresAt, new Date(now + 3600_000).toISOString());
  assert.equal('subject' in result.binding, false);
  assert.equal('internalAuthorityRevision' in result.binding, false);
  assert.equal(store.intents.has(started.state), false);
});

test('denial consumes browser-bound state and never calls the token endpoint', async () => {
  let calls = 0;
  const { client, started } = await startClient(async () => {
    calls += 1;
    return jsonResponse(tokenResponse());
  });
  await assert.rejects(
    client.complete({ state: started.state, browserNonce: started.browserNonce, error: 'access_denied' }),
    HelloOAuthDeniedError,
  );
  await assert.rejects(
    client.complete({ state: started.state, browserNonce: started.browserNonce, code: 'late-code' }),
    /unavailable state/u,
  );
  assert.equal(calls, 0);
});

test('fails closed on mismatched app identity, scope, resource, and absent rotating refresh token', async (t) => {
  const cases = [
    ['app', tokenResponse({ integrationAppSimplyId: 'IAPP-9999-ZZZZ' })],
    ['scope', tokenResponse({}, { scope: 'offline_access' })],
    ['resource', tokenResponse({ resource: 'urn:other:resource' })],
    ['refresh', tokenResponse({}, { refresh_token: undefined })],
  ];
  for (const [name, response] of cases) {
    await t.test(name, async () => {
      const { client, store, started } = await startClient(async () => jsonResponse(response));
      await assert.rejects(
        client.complete({ state: started.state, browserNonce: started.browserNonce, code: 'code' }),
        HelloOAuthCompletionUnknownError,
      );
      assert.equal(store.savedCredentials.length, 0);
      assert.equal(store.intents.has(started.state), false);
    });
  }
});

test('refresh fences before dispatch and leaves an unknown outcome unavailable for retry', async () => {
  let requests = 0;
  const { client, store, started } = await startClient(async (_url, init) => {
    requests += 1;
    const body = new URLSearchParams(init.body);
    if (body.get('grant_type') === 'authorization_code') return jsonResponse(tokenResponse());
    throw new Error('connection lost after dispatch');
  });
  const completed = await client.complete({
    state: started.state,
    browserNonce: started.browserNonce,
    code: 'authorization-code',
  });
  await assert.rejects(client.refresh(completed.binding), HelloOAuthCompletionUnknownError);
  assert.equal(requests, 2);
  const stored = await store.loadCredential(completed.namespace);
  assert.equal(stored.revision, 2);
  assert.equal(stored.value.status, 'REFRESH_IN_PROGRESS');
  await assert.rejects(client.refresh(completed.binding), HelloOAuthRefreshUnavailableError);
  assert.equal(requests, 2);
});

test('rotates a refresh token only when the returned public identity is unchanged', async () => {
  let grantType;
  const { client, store, started } = await startClient(async (_url, init) => {
    const body = new URLSearchParams(init.body);
    grantType = body.get('grant_type');
    return jsonResponse(grantType === 'authorization_code'
      ? tokenResponse()
      : tokenResponse({}, { access_token: 'rotated-access', refresh_token: 'rotated-refresh' }));
  });
  const completed = await client.complete({
    state: started.state,
    browserNonce: started.browserNonce,
    code: 'authorization-code',
  });
  const refreshed = await client.refresh(completed.binding);
  assert.equal(grantType, 'refresh_token');
  assert.deepEqual(refreshed, completed);
  const stored = await store.loadCredential(completed.namespace);
  assert.equal(stored.revision, 3);
  assert.equal(stored.value.status, 'ACTIVE');
  assert.equal(stored.value.accessToken, 'rotated-access');
  assert.equal(stored.value.refreshToken, 'rotated-refresh');
});

test('refresh identity drift leaves the exact grant durably fenced', async () => {
  let refresh = false;
  const { client, store, started } = await startClient(async (_url, init) => {
    const body = new URLSearchParams(init.body);
    refresh = body.get('grant_type') === 'refresh_token';
    return jsonResponse(refresh
      ? tokenResponse({ integrationInstallationGrantSimplyId: 'IIUG-9999-ZZZZ' })
      : tokenResponse());
  });
  const completed = await client.complete({
    state: started.state,
    browserNonce: started.browserNonce,
    code: 'authorization-code',
  });
  await assert.rejects(client.refresh(completed.binding), HelloOAuthCompletionUnknownError);
  assert.equal(refresh, true);
  const stored = await store.loadCredential(completed.namespace);
  assert.equal(stored.revision, 2);
  assert.equal(stored.value.status, 'REFRESH_IN_PROGRESS');
});

test('two hosted-consent selections retain independent installation and user-grant custody', async () => {
  let issuance = 0;
  const store = new MemoryHelloOAuthStore();
  const client = new HelloOAuthClient({
    configuration,
    store,
    fetchImpl: async () => {
      issuance += 1;
      return jsonResponse(tokenResponse(issuance === 1 ? {} : {
        teamIntegrationSimplyId: 'TINT-0002-BBBB',
        teamUserLinkSimplyId: 'TUSR-0002-BBBB',
        integrationInstallationEpochSimplyId: 'IIEP-0002-BBBB',
        integrationInstallationConsentSimplyId: 'IICS-0002-BBBB',
        integrationInstallationGrantSimplyId: 'IIUG-0002-BBBB',
      }, {
        access_token: `access-${issuance}`,
        refresh_token: `refresh-${issuance}`,
      }));
    },
  });
  const first = await client.begin();
  const firstCompleted = await client.complete({
    state: first.state,
    browserNonce: first.browserNonce,
    code: 'first-code',
  });
  const second = await client.begin();
  const secondCompleted = await client.complete({
    state: second.state,
    browserNonce: second.browserNonce,
    code: 'second-code',
  });

  assert.notDeepEqual(firstCompleted.namespace, secondCompleted.namespace);
  assert.equal(store.credentials.size, 2);
  assert.equal((await store.loadCredential(firstCompleted.namespace)).value.accessToken, 'access-1');
  assert.equal((await store.loadCredential(secondCompleted.namespace)).value.accessToken, 'access-2');
});

test('rejects unsafe endpoints, redirect drift, duplicate scopes, and absent offline access', () => {
  for (const changed of [
    { authorizationEndpoint: 'http://api.dev.simply360.app/oauth/authorize' },
    { tokenEndpoint: 'https://user@example.test/oauth/token' },
    { redirectUri: 'https://other.example.test/callback' },
    { scopes: ['records:read', 'records:read', 'offline_access'] },
    { scopes: ['records:read', 'unknown:scope', 'offline_access'] },
    { scopes: ['records:read'] },
    { integrationAppSimplyId: 'numeric-id-42' },
  ]) {
    assert.throws(() => new HelloOAuthClient({
      configuration: { ...configuration, ...changed },
      store: new MemoryHelloOAuthStore(),
    }));
  }
});

test('default-compatible token transport rejects redirects, non-JSON, and oversized responses', async (t) => {
  await t.test('pins redirect policy and accepts one bounded JSON body', async () => {
    let observed;
    const transport = createHardenedHelloOAuthFetch(async (input, init) => {
      observed = { input, init };
      return new Response(JSON.stringify(tokenResponse()), {
        status: 200,
        headers: { 'content-type': 'application/json; charset=utf-8' },
      });
    });
    const response = await transport(configuration.tokenEndpoint, {
      method: 'POST',
      headers: { Accept: 'application/json' },
      body: 'grant_type=refresh_token',
    });
    assert.equal(observed.input, configuration.tokenEndpoint);
    assert.equal(observed.init.redirect, 'error');
    assert.ok(observed.init.signal instanceof AbortSignal);
    assert.deepEqual(await response.json(), tokenResponse());
  });

  await t.test('rejects non-JSON success', async () => {
    const transport = createHardenedHelloOAuthFetch(async () => new Response('not json', {
      status: 200,
      headers: { 'content-type': 'text/plain' },
    }));
    await assert.rejects(
      transport(configuration.tokenEndpoint, { method: 'POST', headers: {}, body: '' }),
      /content type/u,
    );
  });

  await t.test('rejects oversized body', async () => {
    const transport = createHardenedHelloOAuthFetch(async () => new Response('x'.repeat(65 * 1024), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));
    await assert.rejects(
      transport(configuration.tokenEndpoint, { method: 'POST', headers: {}, body: '' }),
      /byte limit/u,
    );
  });
});
