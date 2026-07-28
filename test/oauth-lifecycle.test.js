import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  LocalSimply360Double,
  Simply360OAuthClient,
  computeS256CodeChallenge,
} from '../dist/index.js';

const authorize = async (server, client, teamIntegrationSimplyId, scopes, consentApproved) => {
  const started = client.start(scopes);
  const request = new URL(started.url);
  assert.equal(request.searchParams.get('response_type'), 'code');
  assert.equal(request.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(request.searchParams.get('state'));
  const code = server.issueAuthorizationCode({
    teamIntegrationSimplyId,
    clientId: request.searchParams.get('client_id'),
    redirectUri: request.searchParams.get('redirect_uri'),
    codeChallenge: request.searchParams.get('code_challenge'),
    requestedScopes: request.searchParams.get('scope').split(' '),
    consentApproved,
  });
  return client.exchange(code, started.codeVerifier);
};

test('Direction-45 hello lifecycle is exact-instance, replay-safe and fail-closed', async () => {
  const server = new LocalSimply360Double();
  const client = new Simply360OAuthClient(server.oauthClientConfig(), server);
  const first = server.createInstallation('TEAM-0001-AAAA');
  const second = server.createInstallation('TEAM-0001-AAAA');
  assert.notEqual(first, second);

  const firstPending = await authorize(
    server,
    client,
    first,
    ['schema:read', 'records:read', 'records:write', 'offline_access'],
    true,
  );
  assert.equal(server.setupStatus(firstPending.accessToken).state, 'PENDING_SETUP');
  assert.throws(() => server.readRecords(firstPending.accessToken), /PENDING_SETUP/);
  assert.throws(() => server.createRecord(firstPending.accessToken, 'must fail'), /PENDING_SETUP/);

  server.completeSetup(firstPending.accessToken);
  const firstActive = await client.refresh(firstPending.refreshToken);
  const firstRecord = server.createRecord(firstActive.accessToken, 'First installation record');
  assert.deepEqual(server.readRecords(firstActive.accessToken), [
    { recordSimplyId: firstRecord, name: 'First installation record' },
  ]);

  const secondPending = await authorize(server, client, second, ['records:read', 'offline_access'], true);
  server.completeSetup(secondPending.accessToken);
  const secondActive = await client.refresh(secondPending.refreshToken);
  assert.deepEqual(server.readRecords(secondActive.accessToken), []);
  assert.throws(() => server.createRecord(secondActive.accessToken, 'denied'), /records:write/);

  const userLinkA = server.linkUser(first, 'USER-0001-AAAA');
  const userLinkB = server.linkUser(first, 'USER-0001-BBBB');
  server.revokeUserLink(first, userLinkA);
  assert.deepEqual(server.activeUserLinks(first), [userLinkB]);
  assert.deepEqual(server.activeUserLinks(second), []);

  const blueprintOnFirst = server.installSharedBlueprint(first, 'slack-message-log');
  const blueprintOnSecond = server.installSharedBlueprint(second, 'slack-message-log');
  assert.equal(blueprintOnFirst, blueprintOnSecond);

  await assert.rejects(
    authorize(server, client, second, ['records:read', 'records:write', 'offline_access'], false),
    /scope widening requires explicit Team Admin re-consent/,
  );
  const widenedPending = await authorize(
    server,
    client,
    second,
    ['records:read', 'records:write', 'offline_access'],
    true,
  );
  assert.equal(server.setupStatus(widenedPending.accessToken).state, 'ACTIVE');

  const spentRefresh = firstActive.refreshToken;
  const newest = await client.refresh(spentRefresh);
  await assert.rejects(client.refresh(spentRefresh), /refresh token replay revoked the family/);
  assert.throws(() => server.readRecords(newest.accessToken), /revoked/);

  assert.deepEqual(server.readRecords(secondActive.accessToken), []);
  server.uninstall(second);
  assert.throws(() => server.readRecords(secondActive.accessToken), /revoked/);
});

test('authorization codes are exact, S256-bound and single-use', async () => {
  const server = new LocalSimply360Double();
  const config = server.oauthClientConfig();
  const client = new Simply360OAuthClient(config, server);
  const installation = server.createInstallation('TEAM-0001-AAAA');
  const verifier = 'v'.repeat(43);
  const code = server.issueAuthorizationCode({
    teamIntegrationSimplyId: installation,
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    codeChallenge: computeS256CodeChallenge(verifier),
    requestedScopes: ['records:read', 'offline_access'],
    consentApproved: true,
  });
  await assert.rejects(client.exchange(code, 'x'.repeat(43)), /invalid_grant/);
  await assert.rejects(client.exchange(code, verifier), /invalid_grant/);
});
