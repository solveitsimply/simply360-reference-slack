import { createHmac } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  FetchOAuthTransport,
  SlackWebApiClient,
  parseTokenResponse,
  verifySlackSignature,
} from '../dist/index.js';

test('Slack Web API adapter pins endpoint, rejects redirects and sends deterministic client_msg_id', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ ok: true, channel: 'C123456789', ts: '1800000000.000001' }), {
      status: 200,
      headers: { 'content-type': 'application/json; charset=utf-8' },
    });
  };
  const client = new SlackWebApiClient(`xoxe.xoxb-local-${'a'.repeat(32)}`, fetchImpl);
  await client.postMessage({ channel: 'C123456789', text: 'hello' }, 'action:installation:0001');
  await client.postMessage({ channel: 'C123456789', text: 'hello' }, 'action:installation:0001');
  assert.equal(calls[0].url, 'https://slack.com/api/chat.postMessage');
  assert.equal(calls[0].init.redirect, 'error');
  assert.equal(calls[0].init.headers.Authorization, `Bearer xoxe.xoxb-local-${'a'.repeat(32)}`);
  const firstBody = JSON.parse(calls[0].init.body);
  const secondBody = JSON.parse(calls[1].init.body);
  assert.match(firstBody.client_msg_id, /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-a[a-f0-9]{3}-[a-f0-9]{12}$/);
  assert.equal(firstBody.client_msg_id, secondBody.client_msg_id);
});

test('HTTP clients terminate oversized or non-JSON responses', async () => {
  const oversizedClient = new SlackWebApiClient(`xoxe.xoxb-local-${'a'.repeat(32)}`, async () =>
    new Response('x'.repeat(64 * 1024 + 1), { status: 200, headers: { 'content-type': 'application/json' } }));
  await assert.rejects(
    oversizedClient.postMessage({ channel: 'C123456789', text: 'hello' }, 'action:installation:0001'),
    /byte limit/,
  );

  const wrongTypeClient = new SlackWebApiClient(`xoxe.xoxb-local-${'a'.repeat(32)}`, async () =>
    new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } }));
  await assert.rejects(
    wrongTypeClient.postMessage({ channel: 'C123456789', text: 'hello' }, 'action:installation:0001'),
    /content type/,
  );
});

test('Simply360 OAuth transport uses client-secret basic and accepts forward-compatible token extras', async () => {
  let captured;
  const transport = new FetchOAuthTransport(async (url, init) => {
    captured = { url: String(url), init };
    return new Response(
      JSON.stringify({
        access_token: 'opaque-access',
        refresh_token: 'opaque-refresh',
        token_type: 'bearer',
        expires_in: 900,
        scope: 'records:read offline_access',
        future_server_field: 'ignored',
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  });
  const result = parseTokenResponse(
    await transport.postForm(
      'https://simply360.example/oauth/token',
      new URLSearchParams({ grant_type: 'authorization_code', code: 'code' }),
      { clientId: 'client', clientSecret: 'secret' },
    ),
  );
  assert.equal(captured.url, 'https://simply360.example/oauth/token');
  assert.equal(captured.init.redirect, 'error');
  assert.equal(captured.init.headers.Authorization, `Basic ${Buffer.from('client:secret').toString('base64')}`);
  assert.equal(result.tokenType, 'Bearer');
  assert.deepEqual(result.scope, ['records:read', 'offline_access']);
});

test('Slack request verification accepts only current/previous secrets over exact raw bytes', () => {
  const rawBody = new TextEncoder().encode('payload=%7B%22type%22%3A%22message_action%22%7D');
  const timestamp = '1785242800';
  const previous = 'previous-slack-signing-secret';
  const signature = `v0=${createHmac('sha256', previous)
    .update(Buffer.concat([Buffer.from(`v0:${timestamp}:`), Buffer.from(rawBody)]))
    .digest('hex')}`;
  assert.equal(
    verifySlackSignature({
      rawBody,
      signature,
      timestamp,
      signingSecrets: ['current-slack-signing-secret', previous],
      now: Number(timestamp) * 1000,
    }).ok,
    true,
  );
  assert.equal(
    verifySlackSignature({
      rawBody: Buffer.concat([Buffer.from(rawBody), Buffer.from(' ')]),
      signature,
      timestamp,
      signingSecrets: ['current-slack-signing-secret', previous],
      now: Number(timestamp) * 1000,
    }).code,
    'SIGNATURE_MISMATCH',
  );
});
