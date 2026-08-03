import { createHmac } from 'node:crypto';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  FileRemoteTriggerPublisher,
  JsonFileReferenceStore,
  LocalSimply360Double,
  LocalSlackOAuthDouble,
  ReferenceInstallationState,
  Simply360OAuthClient,
  SlackOAuthClient,
  SlackReferenceRouter,
  signWebhookV2,
  startReferenceServer,
} from '../dist/index.js';

const eventKey = {
  kid: 'current',
  secret: 'reference-event-secret-with-at-least-32-bytes',
};
const slackSigningSecrets = new Map([
  ['T00000001', 'slack-signing-secret-for-workspace-one'],
  ['T00000002', 'slack-signing-secret-for-workspace-two'],
  ['T00000003', 'slack-signing-secret-for-workspace-three'],
]);

class CountingSlack {
  messages = [];

  async postMessage(input, idempotencyKey) {
    const messageTimestamp = `${1_900_000_000 + this.messages.length}.000001`;
    this.messages.push({ ...input, idempotencyKey, messageTimestamp });
    return { channel: input.channel, messageTimestamp };
  }
}

const jsonCall = async (router, method, path, body, headers = {}) => {
  const requestHeaders = new Headers(headers);
  if (body !== undefined) requestHeaders.set('content-type', 'application/json');
  const response = await router.handle(
    new Request(`http://reference.local${path}`, {
      method,
      headers: requestHeaders,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    }),
  );
  const value = await response.json();
  return { status: response.status, value };
};

const createFixture = async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 's360-reference-slack-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const stateFile = join(directory, 'state', 'reference.json');
  const simply360 = new LocalSimply360Double();
  const simply360OAuth = new Simply360OAuthClient(
    simply360.oauthClientConfig(),
    simply360,
  );
  const installations = [
    {
      teamIntegrationSimplyId: simply360.createInstallation('TEAM-0001-AAAA'),
      teamSimplyId: 'TEAM-0001-AAAA',
      expectedSlackTeamId: 'T00000001',
      eventChannel: 'C123456789',
    },
    {
      teamIntegrationSimplyId: simply360.createInstallation('TEAM-0001-AAAA'),
      teamSimplyId: 'TEAM-0001-AAAA',
      expectedSlackTeamId: 'T00000002',
      eventChannel: 'C223456789',
    },
    {
      teamIntegrationSimplyId: simply360.createInstallation('TEAM-0001-BBBB'),
      teamSimplyId: 'TEAM-0001-BBBB',
      expectedSlackTeamId: 'T00000003',
      eventChannel: 'C323456789',
    },
  ];
  const slackOAuthProviders = new Map(
    installations.map((installation, index) => [
      installation.expectedSlackTeamId,
      new LocalSlackOAuthDouble(
        installation.expectedSlackTeamId,
        `Synthetic workspace ${index + 1}`,
      ),
    ]),
  );
  const slackClients = new Map(
    installations.map((installation) => [
      installation.teamIntegrationSimplyId,
      new CountingSlack(),
    ]),
  );
  const makeRouter = () => {
    const store = new JsonFileReferenceStore(stateFile);
    return new SlackReferenceRouter({
      stateFile,
      store,
      simply360OAuth,
      slackOAuthForInstallation: (installation) => {
        const provider = slackOAuthProviders.get(installation.expectedSlackTeamId);
        if (!provider) throw new Error('unexpected Slack workspace');
        return new SlackOAuthClient(provider.clientConfig(), provider);
      },
      slackClientForInstallation: (installation) => {
        const client = slackClients.get(installation.teamIntegrationSimplyId);
        if (!client) throw new Error('unexpected installation');
        return client;
      },
      triggerPublisherForInstallation: (installation, sharedStore) =>
        new FileRemoteTriggerPublisher(
          sharedStore,
          installation.teamIntegrationSimplyId,
        ),
      eventSigningKeysForInstallation: () => [eventKey],
      slackSigningSecretsForWorkspace: (slackTeamId) => {
        const secret = slackSigningSecrets.get(slackTeamId);
        if (!secret) throw new Error('unexpected Slack workspace');
        return [secret];
      },
    });
  };
  return {
    stateFile,
    simply360,
    simply360OAuth,
    installations,
    slackOAuthProviders,
    slackClients,
    makeRouter,
  };
};

const connect = async (fixture, router, installation) => {
  const created = await jsonCall(
    router,
    'POST',
    '/installations',
    installation,
  );
  assert.equal(created.status, 201);
  assert.equal(created.value.installation.status, 'PENDING_SETUP');

  const simplyStarted = await jsonCall(
    router,
    'POST',
    '/oauth/simply360/start',
    { teamIntegrationSimplyId: installation.teamIntegrationSimplyId },
  );
  assert.equal(simplyStarted.status, 200);
  const simplyAuthorization = new URL(simplyStarted.value.authorizationUrl);
  const simplyCode = fixture.simply360.issueAuthorizationCode({
    teamIntegrationSimplyId: installation.teamIntegrationSimplyId,
    clientId: simplyAuthorization.searchParams.get('client_id'),
    redirectUri: simplyAuthorization.searchParams.get('redirect_uri'),
    codeChallenge: simplyAuthorization.searchParams.get('code_challenge'),
    requestedScopes: simplyAuthorization.searchParams.get('scope').split(' '),
    consentApproved: true,
  });
  const simplyCallbackResponse = await router.handle(
    new Request(
      `http://reference.local/oauth/simply360/callback?${new URLSearchParams({
        state: simplyStarted.value.state,
        code: simplyCode,
      })}`,
    ),
  );
  assert.equal(simplyCallbackResponse.status, 200);
  assert.equal(
    (await simplyCallbackResponse.json()).outcome,
    'SIMPLY360_CONNECTED',
  );

  const slackStarted = await jsonCall(
    router,
    'POST',
    '/oauth/slack/start',
    { teamIntegrationSimplyId: installation.teamIntegrationSimplyId },
  );
  assert.equal(slackStarted.status, 200);
  const slackProvider = fixture.slackOAuthProviders.get(
    installation.expectedSlackTeamId,
  );
  const slackCallbackResponse = await router.handle(
    new Request(
      `http://reference.local/oauth/slack/callback?${new URLSearchParams({
        state: slackStarted.value.state,
        code: slackProvider.authorize(),
      })}`,
    ),
  );
  assert.equal(slackCallbackResponse.status, 200);
  const slackCallback = await slackCallbackResponse.json();
  assert.equal(
    slackCallback.slackTeamId,
    installation.expectedSlackTeamId,
  );

  const activated = await jsonCall(router, 'POST', '/setup', {
    teamIntegrationSimplyId: installation.teamIntegrationSimplyId,
  });
  assert.deepEqual(activated, {
    status: 200,
    value: {
      outcome: 'ACTIVE',
      teamIntegrationSimplyId: installation.teamIntegrationSimplyId,
    },
  });
};

const signedSlackShortcut = (installation, messageTimestamp) => {
  const payload = JSON.stringify({
    type: 'message_action',
    callback_id: 's360_create_record',
    trigger_id: '13345224609.738474920.8088930838d88f008e0',
    team: { id: installation.expectedSlackTeamId },
    channel: { id: installation.eventChannel },
    user: { id: 'U00000001' },
    message: { ts: messageTimestamp, text: 'Create a durable record' },
  });
  const body = new URLSearchParams({ payload }).toString();
  const timestamp = String(Math.floor(Date.now() / 1000));
  const secret = slackSigningSecrets.get(installation.expectedSlackTeamId);
  const signature = `v0=${createHmac('sha256', secret)
    .update(`v0:${timestamp}:${body}`)
    .digest('hex')}`;
  return { body, timestamp, signature };
};

const signedOccurrence = (installation, eventType, coordinates) => {
  const lifecycle = eventType.startsWith('app.');
  const occurrence = {
    eventSimplyId: coordinates.eventId,
    teamSimplyId: installation.teamSimplyId,
    teamIntegrationSimplyId: installation.teamIntegrationSimplyId,
    eventType,
    protocolVersion: lifecycle ? 1 : 2,
    payloadSchemaId: lifecycle
      ? 'simply360.event.app-lifecycle/v1'
      : 'simply360.event.data-record/v1',
    payloadSchemaVersion: 1,
    occurredAt: new Date().toISOString(),
    payload: lifecycle
      ? {
          eventType,
          integrationInstallationOperationSimplyId: 'IOPS-0001-AAAA',
          appSlug: 'simply360-reference-slack',
          appVersion: '0.1.0',
          idempotencyKey: `lifecycle-${coordinates.eventId}`,
        }
      : {
          eventType,
          dataCollectionSimplyId: 'COLL-0001-AAAA',
          dataRecordSimplyId: 'RECD-0001-AAAA',
        },
  };
  const body = JSON.stringify(occurrence);
  const timestampUnixSeconds = Math.floor(Date.now() / 1000);
  const signature = signWebhookV2(
    body,
    { timestampUnixSeconds, ...coordinates },
    eventKey,
  );
  return { body, signature, timestampUnixSeconds };
};

test('HTTP router is durable across concurrency and restart and isolates sibling installations', async (t) => {
  const fixture = await createFixture(t);
  let router = fixture.makeRouter();
  const [first, sibling, otherTeam] = fixture.installations;
  await connect(fixture, router, first);
  await connect(fixture, router, sibling);
  await connect(fixture, router, otherTeam);
  const setupView = await jsonCall(
    router,
    'GET',
    `/setup?teamIntegrationSimplyId=${first.teamIntegrationSimplyId}`,
  );
  assert.equal(setupView.status, 200);
  assert.equal(setupView.value.setupReady, true);
  assert.equal(setupView.value.installation.status, 'ACTIVE');

  const firstBlueprint = await jsonCall(router, 'POST', '/blueprints/install', {
    teamIntegrationSimplyId: first.teamIntegrationSimplyId,
    packageKey: 'slack-message-log',
  });
  const siblingBlueprint = await jsonCall(router, 'POST', '/blueprints/install', {
    teamIntegrationSimplyId: sibling.teamIntegrationSimplyId,
    packageKey: 'slack-message-log',
  });
  const otherTeamBlueprint = await jsonCall(router, 'POST', '/blueprints/install', {
    teamIntegrationSimplyId: otherTeam.teamIntegrationSimplyId,
    packageKey: 'slack-message-log',
  });
  assert.equal(
    firstBlueprint.value.teamBlueprintSimplyId,
    siblingBlueprint.value.teamBlueprintSimplyId,
  );
  assert.notEqual(
    firstBlueprint.value.teamBlueprintSimplyId,
    otherTeamBlueprint.value.teamBlueprintSimplyId,
  );

  const firstLink = await jsonCall(router, 'POST', '/account-links', {
    teamIntegrationSimplyId: first.teamIntegrationSimplyId,
    userSimplyId: 'USER-0001-AAAA',
  });
  const repeatedLink = await jsonCall(router, 'POST', '/account-links', {
    teamIntegrationSimplyId: first.teamIntegrationSimplyId,
    userSimplyId: 'USER-0001-AAAA',
  });
  assert.equal(firstLink.status, 201);
  assert.equal(repeatedLink.status, 200);
  assert.equal(repeatedLink.value.linkSimplyId, firstLink.value.linkSimplyId);
  assert.equal(repeatedLink.value.replayed, true);
  assert.equal(
    (
      await jsonCall(
        router,
        'DELETE',
        `/account-links/${firstLink.value.linkSimplyId}`,
        undefined,
        { 'X-S360-Team-Integration-Id': first.teamIntegrationSimplyId },
      )
    ).status,
    200,
  );
  const relinked = await jsonCall(router, 'POST', '/account-links', {
    teamIntegrationSimplyId: first.teamIntegrationSimplyId,
    userSimplyId: 'USER-0001-AAAA',
  });
  assert.notEqual(relinked.value.linkSimplyId, firstLink.value.linkSimplyId);

  const actionBody = {
    input: { channel: first.eventChannel, text: 'Post once' },
    idempotencyKey: 'action:router:concurrency:0001',
  };
  const actionHeaders = {
    'X-S360-Team-Integration-Id': first.teamIntegrationSimplyId,
  };
  const [actionLeft, actionRight] = await Promise.all([
    jsonCall(router, 'POST', '/actions/send-to-channel', actionBody, actionHeaders),
    jsonCall(router, 'POST', '/actions/send-to-channel', actionBody, actionHeaders),
  ]);
  assert.deepEqual(actionLeft.value, actionRight.value);
  assert.equal(fixture.slackClients.get(first.teamIntegrationSimplyId).messages.length, 1);

  router = fixture.makeRouter();
  const restartedAction = await jsonCall(
    router,
    'POST',
    '/actions/send-to-channel',
    actionBody,
    actionHeaders,
  );
  assert.deepEqual(restartedAction.value, actionLeft.value);
  assert.equal(fixture.slackClients.get(first.teamIntegrationSimplyId).messages.length, 1);
  const conflictingAction = await jsonCall(
    router,
    'POST',
    '/actions/send-to-channel',
    {
      ...actionBody,
      input: { channel: first.eventChannel, text: 'Conflicting body' },
    },
    actionHeaders,
  );
  assert.equal(conflictingAction.status, 409);
  assert.equal(conflictingAction.value.error, 'IDEMPOTENCY_CONFLICT');

  const event = signedOccurrence(first, 'dataRecord.created', {
    eventId: 'EVNT-0001-AAAB',
    deliveryId: 'DLVR-0001-AAAB',
    attemptId: 'ATMP-0001-AAAB',
  });
  const eventHeaders = {
    'content-type': 'application/json',
    'X-S360-Signature': event.signature,
  };
  const firstEvent = await router.handle(
    new Request('http://reference.local/events/simply360', {
      method: 'POST',
      headers: eventHeaders,
      body: event.body,
    }),
  );
  assert.deepEqual(await firstEvent.json(), { outcome: 'DELIVERED' });
  router = fixture.makeRouter();
  const replayedEvent = await router.handle(
    new Request('http://reference.local/events/simply360', {
      method: 'POST',
      headers: eventHeaders,
      body: event.body,
    }),
  );
  assert.deepEqual(await replayedEvent.json(), { outcome: 'DUPLICATE' });
  assert.equal(fixture.slackClients.get(first.teamIntegrationSimplyId).messages.length, 2);

  const shortcut = signedSlackShortcut(first, '1900000000.000001');
  const shortcutRequest = () =>
    new Request('http://reference.local/events/slack', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'X-Slack-Signature': shortcut.signature,
        'X-Slack-Request-Timestamp': shortcut.timestamp,
      },
      body: shortcut.body,
    });
  assert.deepEqual(await (await router.handle(shortcutRequest())).json(), {
    outcome: 'TRIGGERED',
  });
  router = fixture.makeRouter();
  assert.deepEqual(await (await router.handle(shortcutRequest())).json(), {
    outcome: 'DUPLICATE',
  });
  const beforeUninstall = await new JsonFileReferenceStore(fixture.stateFile).read();
  assert.equal(Object.keys(beforeUninstall.remoteTriggers).length, 1);

  const lifecycle = signedOccurrence(first, 'app.uninstalled', {
    eventId: 'EVNT-0001-AAAC',
    deliveryId: 'DLVR-0001-AAAC',
    attemptId: 'ATMP-0001-AAAC',
  });
  const lifecycleRequest = () =>
    new Request('http://reference.local/lifecycle', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'X-S360-Signature': lifecycle.signature,
      },
      body: lifecycle.body,
    });
  const uninstalled = await router.handle(lifecycleRequest());
  assert.equal(uninstalled.status, 200);
  assert.deepEqual(await uninstalled.json(), {
    outcome: 'UNINSTALLED',
    slackRevocationOutcome: 'SUCCEEDED',
    replayed: false,
  });
  router = fixture.makeRouter();
  assert.deepEqual(await (await router.handle(lifecycleRequest())).json(), {
    outcome: 'UNINSTALLED',
    slackRevocationOutcome: 'SUCCEEDED',
    replayed: true,
  });

  const afterUninstall = await new JsonFileReferenceStore(fixture.stateFile).read();
  const firstState = afterUninstall.installations[first.teamIntegrationSimplyId];
  assert.equal(firstState.status, 'UNINSTALLED');
  assert.equal(firstState.simply360Credential, undefined);
  assert.equal(firstState.slackCredential, undefined);
  assert.equal(
    Object.values(firstState.userLinks).some((link) => link.active),
    false,
  );
  assert.equal(Object.keys(afterUninstall.remoteTriggers).length, 0);
  const shared = Object.values(afterUninstall.sharedBlueprints).find(
    (blueprint) =>
      blueprint.teamBlueprintSimplyId ===
      firstBlueprint.value.teamBlueprintSimplyId,
  );
  assert.deepEqual(shared.installationSimplyIds, [
    sibling.teamIntegrationSimplyId,
  ]);

  const fencedAction = await jsonCall(
    router,
    'POST',
    '/actions/send-to-channel',
    {
      input: { channel: first.eventChannel, text: 'Must remain fenced' },
      idempotencyKey: 'action:router:after-uninstall',
    },
    actionHeaders,
  );
  assert.equal(fencedAction.status, 400);
  assert.match(fencedAction.value.message, /not active/);
  const fencedShortcut = await router.handle(shortcutRequest());
  assert.equal(fencedShortcut.status, 400);
  assert.match((await fencedShortcut.json()).message, /no active installation/);

  const siblingAction = await jsonCall(
    router,
    'POST',
    '/actions/send-to-channel',
    {
      input: { channel: sibling.eventChannel, text: 'Sibling remains active' },
      idempotencyKey: 'action:router:sibling:0001',
    },
    { 'X-S360-Team-Integration-Id': sibling.teamIntegrationSimplyId },
  );
  assert.equal(siblingAction.status, 200);
  assert.equal(
    fixture.slackClients.get(sibling.teamIntegrationSimplyId).messages.length,
    1,
  );

  assert.equal((await stat(fixture.stateFile)).mode & 0o777, 0o600);
});

test('actual HTTP server adapter serves the router and corrupt state fails closed', async (t) => {
  const fixture = await createFixture(t);
  const router = fixture.makeRouter();
  const server = await startReferenceServer(router);
  t.after(() => server.close());
  const health = await fetch(`${server.origin}/health`);
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: 'ok' });
  await writeFile(
    fixture.stateFile,
    '{"schemaVersion":1,"nextUserLinkSequence":0}\n',
    { mode: 0o600 },
  );
  const rejected = await fetch(`${server.origin}/health`);
  assert.equal(rejected.status, 400);
  assert.match((await rejected.json()).message, /corrupt/);
  assert.match(await readFile(fixture.stateFile, 'utf8'), /schemaVersion/);
});

test('Slack OAuth rejects a grant for a different workspace', async () => {
  const provider = new LocalSlackOAuthDouble('T00000001');
  const wrongClient = new SlackOAuthClient(
    { ...provider.clientConfig(), expectedTeamId: 'T00000002' },
    provider,
  );
  await assert.rejects(
    wrongClient.exchange(provider.authorize()),
    /reviewed rotating bot grant/,
  );
});
