import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LocalSlackOAuthDouble, SlackOAuthClient } from '../dist/index.js';

test('Slack OAuth requests only chat:write, validates state and supports revocation', async () => {
  const provider = new LocalSlackOAuthDouble();
  const client = new SlackOAuthClient(provider.clientConfig(), provider);
  const started = client.start();
  const url = new URL(started.url);
  assert.equal(url.origin, 'https://slack.com');
  assert.equal(url.searchParams.get('scope'), 'chat:write');
  assert.equal(url.searchParams.get('state'), started.state);
  client.verifyState(started.state, started.state);
  assert.throws(() => client.verifyState(started.state, `${started.state}x`), /state mismatch/);

  const grant = await client.exchange(provider.authorize());
  assert.equal(grant.teamName, 'Simply360 Developer Test');
  assert.deepEqual(grant.scope, ['chat:write']);
  assert.equal(provider.isActive(grant.accessToken), true);
  const rotated = await client.refresh(grant.refreshToken);
  assert.notEqual(rotated.accessToken, grant.accessToken);
  assert.equal(provider.isActive(grant.accessToken), false);
  await assert.rejects(client.refresh(grant.refreshToken), /rotating bot grant/);
  await client.revoke(rotated.accessToken);
  assert.equal(provider.isActive(rotated.accessToken), false);
  await assert.rejects(client.revoke(rotated.accessToken), /already revoked/);
});

test('Slack authorization codes are single use', async () => {
  const provider = new LocalSlackOAuthDouble();
  const client = new SlackOAuthClient(provider.clientConfig(), provider);
  const code = provider.authorize();
  await client.exchange(code);
  await assert.rejects(client.exchange(code), /reviewed rotating bot grant/);
});

test('Slack token refresh cannot change the bound workspace', async () => {
  const provider = new LocalSlackOAuthDouble('T00000001');
  const transport = {
    exchange: (input) => provider.exchange(input),
    refresh: async () => ({
      ok: true,
      access_token: ['xoxe.xoxb', 'local', 'workspace', 'change'].join('-'),
      refresh_token: ['xoxe', 'local', 'workspace', 'change'].join('-'),
      expires_in: 43_200,
      token_type: 'bot',
      scope: 'chat:write',
      bot_user_id: 'U0000BOT1',
      team: { id: 'T00000002', name: 'Wrong workspace' },
    }),
    revoke: (accessToken) => provider.revoke(accessToken),
  };
  const client = new SlackOAuthClient(provider.clientConfig(), transport);
  const grant = await client.exchange(provider.authorize());
  await assert.rejects(
    client.refresh(grant.refreshToken),
    /reviewed rotating bot grant/,
  );
});
