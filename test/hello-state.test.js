import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';

import {
  ConcurrentHelloStateUpdateError,
  HelloIdempotencyCompletionUnknownError,
  HelloLifecycleFencedError,
  HelloOperationNoEffectError,
  HelloOperationInProgressError,
  HelloStateStore,
  IdempotencyConflictError,
  OAuthStateUnavailableError,
} from '../dist/index.js';

const conditionalFailure = () => Object.assign(new Error('condition failed'), {
  name: 'ConditionalCheckFailedException',
});
const transactionFailure = () => Object.assign(new Error('transaction cancelled'), {
  name: 'TransactionCanceledException',
});

const clone = (value) => structuredClone(value);

class MemoryDynamo {
  items = new Map();
  failNextUpdate = false;
  failNextBatchWrite = false;

  coordinate(key) {
    return `${key.pk}\0${key.sk}`;
  }

  async send(command) {
    const input = command.input;
    switch (command.constructor.name) {
      case 'PutCommand': {
        const coordinate = this.coordinate(input.Item);
        const existing = this.items.get(coordinate);
        if (input.ConditionExpression?.includes('attribute_not_exists') && existing !== undefined) {
          throw conditionalFailure();
        }
        if (input.ConditionExpression?.includes(':expectedRevision')) {
          if (
            existing?.recordType !== input.ExpressionAttributeValues[':recordType'] ||
            existing?.revision !== input.ExpressionAttributeValues[':expectedRevision']
          ) {
            throw conditionalFailure();
          }
        }
        this.items.set(coordinate, clone(input.Item));
        return {};
      }
      case 'GetCommand': {
        const item = this.items.get(this.coordinate(input.Key));
        return { Item: item === undefined ? undefined : clone(item) };
      }
      case 'TransactGetCommand': {
        return {
          Responses: input.TransactItems.map(({ Get }) => {
            const item = this.items.get(this.coordinate(Get.Key));
            return { Item: item === undefined ? undefined : clone(item) };
          }),
        };
      }
      case 'DeleteCommand': {
        const coordinate = this.coordinate(input.Key);
        const item = this.items.get(coordinate);
        if (input.ConditionExpression !== undefined) {
          if (item === undefined) throw conditionalFailure();
          const values = input.ExpressionAttributeValues;
          if (
            input.ConditionExpression.includes(':now') &&
            (item.recordType !== values[':recordType'] || item.expiresAtEpoch <= values[':now'])
          ) {
            throw conditionalFailure();
          }
          if (
            input.ConditionExpression.includes(':browserNonceHash') &&
            item.browserNonceHash !== values[':browserNonceHash']
          ) {
            throw conditionalFailure();
          }
          if (
            input.ConditionExpression.includes(':expectedRevision') &&
            (item.recordType !== values[':recordType'] || item.revision !== values[':expectedRevision'])
          ) {
            throw conditionalFailure();
          }
          if (
            input.ConditionExpression.includes('claimOwner = :claimOwner') &&
            (item.status !== values[':inProgress'] || item.claimOwner !== values[':claimOwner'])
          ) {
            throw conditionalFailure();
          }
        }
        this.items.delete(coordinate);
        return { Attributes: input.ReturnValues === 'ALL_OLD' ? clone(item) : undefined };
      }
      case 'UpdateCommand': {
        if (this.failNextUpdate) {
          this.failNextUpdate = false;
          throw new Error('simulated ambiguous update failure');
        }
        const coordinate = this.coordinate(input.Key);
        const item = this.items.get(coordinate);
        const values = input.ExpressionAttributeValues;
        if (values[':recordType'] === 'LIFECYCLE_FENCE') {
          if (
            item?.recordType !== values[':recordType'] ||
            item?.status !== values[':inProgress'] ||
            item?.eventSimplyId !== values[':eventSimplyId'] ||
            item?.bodySha256 !== values[':bodySha256']
          ) {
            throw conditionalFailure();
          }
          this.items.set(coordinate, { ...item, status: values[':cleaned'] });
          return {};
        }
        if (
          item?.status !== values[':inProgress'] ||
          item?.claimOwner !== values[':claimOwner'] ||
          item?.requestFingerprint !== values[':requestFingerprint']
        ) {
          throw conditionalFailure();
        }
        this.items.set(coordinate, {
          ...item,
          status: values[':complete'],
          encryptedValue: clone(values[':encryptedValue']),
          expiresAtEpoch: values[':expiresAt'],
          claimOwner: undefined,
        });
        return {};
      }
      case 'TransactWriteCommand': {
        const next = new Map([...this.items.entries()].map(([key, value]) => [key, clone(value)]));
        for (const item of input.TransactItems) {
          if (item.ConditionCheck) {
            if (next.has(this.coordinate(item.ConditionCheck.Key))) throw transactionFailure();
            continue;
          }
          if (item.Put) {
            const coordinate = this.coordinate(item.Put.Item);
            const existing = next.get(coordinate);
            if (item.Put.ConditionExpression?.includes('attribute_not_exists') && existing !== undefined) {
              throw transactionFailure();
            }
            if (
              item.Put.ConditionExpression?.includes(':expectedRevision') &&
              (existing?.recordType !== item.Put.ExpressionAttributeValues[':recordType'] ||
                existing?.revision !== item.Put.ExpressionAttributeValues[':expectedRevision'])
            ) {
              throw transactionFailure();
            }
            next.set(coordinate, clone(item.Put.Item));
            continue;
          }
          if (item.Delete) {
            const coordinate = this.coordinate(item.Delete.Key);
            const existing = next.get(coordinate);
            const values = item.Delete.ExpressionAttributeValues;
            if (
              existing === undefined ||
              (item.Delete.ConditionExpression.includes(':now') &&
                (existing.recordType !== values[':recordType'] || existing.expiresAtEpoch <= values[':now'])) ||
              (item.Delete.ConditionExpression.includes(':expectedRevision') &&
                (existing.recordType !== values[':recordType'] || existing.revision !== values[':expectedRevision']))
            ) {
              throw transactionFailure();
            }
            next.delete(coordinate);
            continue;
          }
          if (item.Update) {
            if (this.failNextUpdate) {
              this.failNextUpdate = false;
              throw new Error('simulated ambiguous update failure');
            }
            const coordinate = this.coordinate(item.Update.Key);
            const existing = next.get(coordinate);
            const values = item.Update.ExpressionAttributeValues;
            if (
              existing?.status !== values[':inProgress'] ||
              existing?.claimOwner !== values[':claimOwner'] ||
              existing?.requestFingerprint !== values[':requestFingerprint']
            ) {
              throw transactionFailure();
            }
            next.set(coordinate, {
              ...existing,
              status: values[':complete'],
              encryptedValue: clone(values[':encryptedValue']),
              expiresAtEpoch: values[':expiresAt'],
              claimOwner: undefined,
            });
            continue;
          }
          throw new Error('unsupported transaction item');
        }
        this.items = next;
        return {};
      }
      case 'QueryCommand': {
        const pk = input.ExpressionAttributeValues[':pk'];
        const prefix = input.ExpressionAttributeValues[':prefix'];
        const items = [...this.items.values()]
          .filter((item) => item.pk === pk && (prefix === undefined || item.sk.startsWith(prefix)))
          .map(({ pk: itemPk, sk }) => ({ pk: itemPk, sk }));
        return { Items: clone(items) };
      }
      case 'BatchWriteCommand': {
        if (this.failNextBatchWrite) {
          this.failNextBatchWrite = false;
          throw new Error('simulated cleanup interruption');
        }
        for (const request of input.RequestItems.HelloState) {
          this.items.delete(this.coordinate(request.DeleteRequest.Key));
        }
        return { UnprocessedItems: {} };
      }
      default:
        throw new Error(`unsupported command ${command.constructor.name}`);
    }
  }
}

class MemorySecrets {
  constructor(current, previous) {
    this.current = current;
    this.previous = previous;
  }

  async send(command) {
    assert.equal(command.constructor.name, 'GetSecretValueCommand');
    assert.equal(command.input.SecretId, 's360/reference-slack/dev/runtime');
    return {
      SecretString: JSON.stringify({
        unrelatedRuntimeValue: 'preserved',
        helloStateEncryptionKeyCurrent: this.current,
        ...(this.previous === undefined ? {} : {
          helloStateEncryptionKeyPrevious: this.previous,
        }),
      }),
    };
  }
}

const keyA = Buffer.alloc(32, 0x11).toString('base64');
const keyB = Buffer.alloc(32, 0x22).toString('base64');
const now = { value: Date.UTC(2026, 8, 6, 12, 0, 0) };

const makeStore = () => {
  const dynamo = new MemoryDynamo();
  const secrets = new MemorySecrets(keyA);
  const store = new HelloStateStore({
    tableName: 'HelloState',
    runtimeSecretId: 's360/reference-slack/dev/runtime',
    dynamo,
    secrets,
    now: () => now.value,
  });
  return { store, dynamo, secrets };
};

const installationSimply360 = {
  teamIntegrationSimplyId: 'INST-0001-AAAA',
  scope: 'installation',
  grant: 'simply360',
  integrationInstallationGrantSimplyId: 'GRNT-0001-AAAA',
};
const installationProvider = {
  teamIntegrationSimplyId: 'INST-0001-AAAA',
  scope: 'installation',
  grant: 'provider',
  integrationProviderAccountLinkSimplyId: 'IPAL-0001-AAAA',
};
const memberProvider = (memberSimplyId, integrationProviderAccountLinkSimplyId = 'IPAL-0002-AAAA') => ({
  teamIntegrationSimplyId: 'INST-0001-AAAA',
  scope: 'member',
  memberSimplyId,
  grant: 'provider',
  integrationProviderAccountLinkSimplyId,
});
const memberSimply360 = (memberSimplyId, integrationInstallationGrantSimplyId = 'GRNT-0002-AAAA') => ({
  teamIntegrationSimplyId: 'INST-0001-AAAA',
  scope: 'member',
  memberSimplyId,
  grant: 'simply360',
  integrationInstallationGrantSimplyId,
});
const fingerprint = (value) => createHash('sha256').update(value).digest('hex');

test('credentials are encrypted, revision-checked, isolated, and readable across key rotation', async () => {
  now.value = Date.UTC(2026, 8, 6, 12, 0, 0);
  const { store, dynamo, secrets } = makeStore();
  const credential = { accessToken: 'top-secret-token', refreshToken: 'refresh-secret' };
  assert.deepEqual(await store.saveCredential(installationSimply360, credential, null), {
    revision: 1,
    value: credential,
  });
  assert.doesNotMatch(JSON.stringify([...dynamo.items.values()]), /top-secret-token|refresh-secret/u);
  assert.deepEqual(await store.loadCredential(installationSimply360), {
    revision: 1,
    value: credential,
  });
  assert.equal(await store.loadCredential({
    ...installationSimply360,
    teamIntegrationSimplyId: 'INST-0002-BBBB',
  }), undefined);
  await assert.rejects(
    store.saveCredential(installationSimply360, { accessToken: 'stale' }, null),
    ConcurrentHelloStateUpdateError,
  );

  secrets.current = keyB;
  secrets.previous = keyA;
  assert.deepEqual((await store.loadCredential(installationSimply360)).value, credential);
  await store.saveCredential(installationSimply360, { accessToken: 'rotated-token' }, 1);
  secrets.previous = undefined;
  assert.deepEqual(await store.loadCredential(installationSimply360), {
    revision: 2,
    value: { accessToken: 'rotated-token' },
  });
  await assert.rejects(
    store.deleteCredential(installationSimply360, 1),
    ConcurrentHelloStateUpdateError,
  );
  await store.deleteCredential(installationSimply360, 2);
  assert.equal(await store.loadCredential(installationSimply360), undefined);
});

test('OAuth state is exact-grant, short-lived, atomically single-use, and never stored in plaintext', async () => {
  now.value = Date.UTC(2026, 8, 6, 12, 0, 0);
  const { store, dynamo } = makeStore();
  const state = 'state_' + 'a'.repeat(40);
  const payload = { codeVerifier: 'verifier_' + 'v'.repeat(43) };
  await store.createOAuthState(
    installationSimply360,
    state,
    new Date(now.value + 10 * 60 * 1_000),
    payload,
  );
  assert.doesNotMatch(JSON.stringify([...dynamo.items.values()]), /state_|verifier_/u);
  await assert.rejects(
    store.createOAuthState(
      installationSimply360,
      state,
      new Date(now.value + 60_000),
      payload,
    ),
    ConcurrentHelloStateUpdateError,
  );
  await assert.rejects(store.consumeOAuthState(installationProvider, state), OAuthStateUnavailableError);
  assert.deepEqual(await store.consumeOAuthState(installationSimply360, state), payload);
  await assert.rejects(store.consumeOAuthState(installationSimply360, state), OAuthStateUnavailableError);

  const expiredState = 'state_' + 'b'.repeat(40);
  await store.createOAuthState(
    installationSimply360,
    expiredState,
    new Date(now.value + 1_000),
    payload,
  );
  now.value += 2_000;
  await assert.rejects(
    store.consumeOAuthState(installationSimply360, expiredState),
    OAuthStateUnavailableError,
  );
  await assert.rejects(
    store.createOAuthState(
      installationSimply360,
      'state_' + 'c'.repeat(40),
      new Date(now.value + 10 * 60 * 1_000 + 1_000),
      payload,
    ),
    /within the next 10 minutes/u,
  );
});

test('pending OAuth intent is anonymous, encrypted, browser-bound, short-lived, and single-use', async () => {
  now.value = Date.UTC(2026, 8, 6, 12, 0, 0);
  const { store, dynamo } = makeStore();
  const state = 'state_' + 'd'.repeat(40);
  const browserNonce = 'browser_' + 'n'.repeat(40);
  const wrongBrowserNonce = 'browser_' + 'x'.repeat(40);
  const payload = {
    codeVerifier: 'v'.repeat(43),
    redirectUri: 'https://reference-slack.dev.simply360.app/oauth/simply360/callback',
  };

  await store.createPendingOAuthIntent(
    state,
    browserNonce,
    new Date(now.value + 10 * 60 * 1_000),
    payload,
  );
  await assert.rejects(
    store.createPendingOAuthIntent(
      state,
      browserNonce,
      new Date(now.value + 60_000),
      payload,
    ),
    ConcurrentHelloStateUpdateError,
  );
  const serializedItems = JSON.stringify([...dynamo.items.values()]);
  assert.doesNotMatch(serializedItems, /state_|browser_|vvvv/u);
  assert.doesNotMatch(serializedItems, /INSTALLATION|MEMBER|GRANT/u);
  assert.match(serializedItems, /PENDING_OAUTH#[a-f0-9]{64}/u);

  await assert.rejects(
    store.consumePendingOAuthIntent(state, wrongBrowserNonce),
    OAuthStateUnavailableError,
  );
  assert.deepEqual(await store.consumePendingOAuthIntent(state, browserNonce), payload);
  await assert.rejects(
    store.consumePendingOAuthIntent(state, browserNonce),
    OAuthStateUnavailableError,
  );

  const expiredState = 'state_' + 'e'.repeat(40);
  await store.createPendingOAuthIntent(
    expiredState,
    browserNonce,
    new Date(now.value + 1_000),
    payload,
  );
  now.value += 2_000;
  await assert.rejects(
    store.consumePendingOAuthIntent(expiredState, browserNonce),
    OAuthStateUnavailableError,
  );
  await assert.rejects(
    store.createPendingOAuthIntent(
      'state_' + 'f'.repeat(40),
      browserNonce,
      new Date(now.value + 10 * 60 * 1_000 + 1_000),
      payload,
    ),
    /within the next 10 minutes/u,
  );
});

test('durable idempotency replays completed work, retries proven no-effect failures, and fences lost responses', async () => {
  now.value = Date.UTC(2026, 8, 6, 12, 0, 0);
  const { store, dynamo } = makeStore();
  let calls = 0;
  const requestFingerprint = fingerprint('request-one');
  const first = await store.runIdempotent(
    installationProvider,
    'send-message',
    'idempotency-key-one',
    requestFingerprint,
    async () => ({ providerId: `message-${++calls}` }),
  );
  assert.deepEqual(first, { replayed: false, value: { providerId: 'message-1' } });
  assert.deepEqual(
    await store.runIdempotent(
      installationProvider,
      'send-message',
      'idempotency-key-one',
      requestFingerprint,
      async () => ({ providerId: `message-${++calls}` }),
    ),
    { replayed: true, value: { providerId: 'message-1' } },
  );
  assert.equal(calls, 1);
  await assert.rejects(
    store.runIdempotent(
      installationProvider,
      'send-message',
      'idempotency-key-one',
      fingerprint('different-request'),
      async () => ({ providerId: 'must-not-run' }),
    ),
    IdempotencyConflictError,
  );

  let release;
  const pending = store.runIdempotent(
    installationProvider,
    'send-message',
    'idempotency-key-two',
    requestFingerprint,
    () => new Promise((resolve) => { release = resolve; }),
  );
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(
    store.runIdempotent(
      installationProvider,
      'send-message',
      'idempotency-key-two',
      requestFingerprint,
      async () => 'must-not-run',
    ),
    HelloOperationInProgressError,
  );
  release('finished');
  assert.deepEqual(await pending, { replayed: false, value: 'finished' });

  await assert.rejects(
    store.runIdempotent(
      installationProvider,
      'send-message',
      'idempotency-key-three',
      requestFingerprint,
      async () => {
        throw new HelloOperationNoEffectError('provider rejected before dispatch');
      },
    ),
    HelloOperationNoEffectError,
  );
  assert.deepEqual(
    await store.runIdempotent(
      installationProvider,
      'send-message',
      'idempotency-key-three',
      requestFingerprint,
      async () => 'retry succeeded',
    ),
    { replayed: false, value: 'retry succeeded' },
  );

  let lostResponseCalls = 0;
  await assert.rejects(
    store.runIdempotent(
      installationProvider,
      'send-message',
      'idempotency-key-lost-response',
      requestFingerprint,
      async () => {
        lostResponseCalls += 1;
        throw new Error('network timeout after provider accepted request');
      },
    ),
    HelloIdempotencyCompletionUnknownError,
  );
  const lostResponseClaim = [...dynamo.items.values()].find((item) =>
    item.sk.endsWith(createHash('sha256').update('idempotency-key-lost-response').digest('hex')),
  );
  assert.ok(lostResponseClaim);
  assert.equal(lostResponseClaim.status, 'IN_PROGRESS');
  assert.equal('expiresAtEpoch' in lostResponseClaim, false);
  await assert.rejects(
    store.runIdempotent(
      installationProvider,
      'send-message',
      'idempotency-key-lost-response',
      requestFingerprint,
      async () => {
        lostResponseCalls += 1;
        return 'must not duplicate';
      },
    ),
    HelloOperationInProgressError,
  );
  assert.equal(lostResponseCalls, 1);

  dynamo.failNextUpdate = true;
  await assert.rejects(
    store.runIdempotent(
      installationProvider,
      'send-message',
      'idempotency-key-four',
      requestFingerprint,
      async () => 'provider may have succeeded',
    ),
    HelloIdempotencyCompletionUnknownError,
  );
  await assert.rejects(
    store.runIdempotent(
      installationProvider,
      'send-message',
      'idempotency-key-four',
      requestFingerprint,
      async () => 'must not duplicate',
    ),
    HelloOperationInProgressError,
  );
});

test('exact grant and provider-link cleanup preserve same-member siblings', async () => {
  now.value = Date.UTC(2026, 8, 6, 12, 0, 0);
  const { store } = makeStore();
  const memberGrantA = memberSimply360('MEMB-0001-AAAA', 'GRNT-0002-AAAA');
  const memberGrantB = memberSimply360('MEMB-0001-AAAA', 'GRNT-0003-BBBB');
  const memberLinkA = memberProvider('MEMB-0001-AAAA', 'IPAL-0002-AAAA');
  const memberLinkB = memberProvider('MEMB-0001-AAAA', 'IPAL-0003-BBBB');
  const memberB = memberProvider('MEMB-0002-BBBB', 'IPAL-0004-CCCC');
  const otherInstallation = {
    ...installationProvider,
    teamIntegrationSimplyId: 'INST-0002-BBBB',
    integrationProviderAccountLinkSimplyId: 'IPAL-0005-DDDD',
  };
  for (const namespace of [
    installationSimply360,
    installationProvider,
    memberGrantA,
    memberGrantB,
    memberLinkA,
    memberLinkB,
    memberB,
    otherInstallation,
  ]) {
    await store.saveCredential(namespace, { marker: `${namespace.teamIntegrationSimplyId}:${namespace.scope}:${namespace.grant}` }, null);
  }

  const linkStateA = 'state_' + 'd'.repeat(40);
  const linkStateB = 'state_' + 'e'.repeat(40);
  await store.createOAuthState(memberLinkA, linkStateA, new Date(now.value + 60_000), { link: 'A' });
  await store.createOAuthState(memberLinkB, linkStateB, new Date(now.value + 60_000), { link: 'B' });
  const linkFingerprint = fingerprint('same-member-links');
  await store.runIdempotent(memberLinkA, 'connect', 'link-key', linkFingerprint, async () => 'A');
  await store.runIdempotent(memberLinkB, 'connect', 'link-key', linkFingerprint, async () => 'B');

  const grantStateA = 'state_' + 'f'.repeat(40);
  const grantStateB = 'state_' + 'g'.repeat(40);
  await store.createOAuthState(memberGrantA, grantStateA, new Date(now.value + 60_000), { grant: 'A' });
  await store.createOAuthState(memberGrantB, grantStateB, new Date(now.value + 60_000), { grant: 'B' });
  const grantFingerprint = fingerprint('same-member-grants');
  await store.runIdempotent(memberGrantA, 'authorize', 'grant-key', grantFingerprint, async () => 'A');
  await store.runIdempotent(memberGrantB, 'authorize', 'grant-key', grantFingerprint, async () => 'B');

  const linkCleanup = await store.fenceAndCleanupGrant(memberLinkA, {
    eventSimplyId: 'EVNT-0001-AAAA',
    bodySha256: fingerprint('link-a-revoked'),
  });
  assert.deepEqual(linkCleanup, { deleted: 3, replayed: false });
  await assert.rejects(store.loadCredential(memberLinkA), HelloLifecycleFencedError);
  await assert.rejects(store.consumeOAuthState(memberLinkA, linkStateA), OAuthStateUnavailableError);
  assert.notEqual(await store.loadCredential(memberLinkB), undefined);
  assert.deepEqual(await store.consumeOAuthState(memberLinkB, linkStateB), { link: 'B' });
  assert.deepEqual(
    await store.runIdempotent(memberLinkB, 'connect', 'link-key', linkFingerprint, async () => 'duplicate'),
    { replayed: true, value: 'B' },
  );
  assert.notEqual(await store.loadCredential(memberGrantA), undefined);
  assert.notEqual(await store.loadCredential(memberGrantB), undefined);
  assert.notEqual(await store.loadCredential(memberB), undefined);

  const grantCleanup = await store.fenceAndCleanupGrant(memberGrantA, {
    eventSimplyId: 'EVNT-0002-BBBB',
    bodySha256: fingerprint('grant-a-revoked'),
  });
  assert.deepEqual(grantCleanup, { deleted: 3, replayed: false });
  await assert.rejects(store.loadCredential(memberGrantA), HelloLifecycleFencedError);
  await assert.rejects(store.consumeOAuthState(memberGrantA, grantStateA), OAuthStateUnavailableError);
  assert.notEqual(await store.loadCredential(memberGrantB), undefined);
  assert.deepEqual(await store.consumeOAuthState(memberGrantB, grantStateB), { grant: 'B' });
  assert.deepEqual(
    await store.runIdempotent(memberGrantB, 'authorize', 'grant-key', grantFingerprint, async () => 'duplicate'),
    { replayed: true, value: 'B' },
  );

  assert.notEqual(await store.loadCredential(memberGrantB), undefined);
  assert.notEqual(await store.loadCredential(memberLinkB), undefined);
  assert.notEqual(await store.loadCredential(memberB), undefined);
  assert.notEqual(await store.loadCredential(installationProvider), undefined);

  const installationCleanup = await store.fenceAndCleanupInstallation('INST-0001-AAAA', {
    eventSimplyId: 'EVNT-0003-CCCC',
    bodySha256: fingerprint('installation-uninstalled'),
  });
  assert.equal(installationCleanup.replayed, false);
  assert.equal(installationCleanup.deleted, 7);
  await assert.rejects(store.loadCredential(installationSimply360), HelloLifecycleFencedError);
  await assert.rejects(store.loadCredential(installationProvider), HelloLifecycleFencedError);
  await assert.rejects(store.loadCredential(memberB), HelloLifecycleFencedError);
  assert.notEqual(await store.loadCredential(otherInstallation), undefined);
});

test('lifecycle fences survive cleanup, resume the same event, and reject late resurrection writes', async () => {
  now.value = Date.UTC(2026, 8, 6, 12, 0, 0);
  const { store, dynamo } = makeStore();
  const evidence = {
    eventSimplyId: 'EVNT-0004-DDDD',
    bodySha256: fingerprint('terminal-uninstall'),
  };
  await store.saveCredential(memberSimply360('MEMB-0001-AAAA'), { accessToken: 'before-cleanup' }, null);
  assert.deepEqual(await store.fenceAndCleanupInstallation('INST-0001-AAAA', evidence), {
    deleted: 1,
    replayed: false,
  });
  assert.deepEqual(await store.fenceAndCleanupInstallation('INST-0001-AAAA', evidence), {
    deleted: 0,
    replayed: true,
  });
  assert.match(JSON.stringify([...dynamo.items.values()]), /LIFECYCLE#INST-0001-AAAA/u);
  assert.match(JSON.stringify([...dynamo.items.values()]), /CLEANED/u);

  const lateState = 'state_' + 'z'.repeat(40);
  await assert.rejects(
    store.createOAuthState(memberSimply360('MEMB-0001-AAAA'), lateState, new Date(now.value + 60_000), { late: true }),
    HelloLifecycleFencedError,
  );
  await assert.rejects(
    store.saveCredential(memberSimply360('MEMB-0001-AAAA'), { accessToken: 'resurrected' }, null),
    HelloLifecycleFencedError,
  );
  await assert.rejects(
    store.runIdempotent(
      memberSimply360('MEMB-0001-AAAA'),
      'late-write',
      'late-idempotency-key',
      fingerprint('late-write'),
      async () => 'should-not-run',
    ),
    HelloLifecycleFencedError,
  );
  await assert.rejects(
    store.fenceAndCleanupInstallation('INST-0001-AAAA', {
      ...evidence,
      bodySha256: fingerprint('tampered-event'),
    }),
    HelloLifecycleFencedError,
  );
});

test('a cleanup fence hides credentials atomically before an interrupted delete completes', async () => {
  now.value = Date.UTC(2026, 8, 6, 12, 0, 0);
  const { store, dynamo } = makeStore();
  const namespace = memberSimply360('MEMB-0001-AAAA');
  const evidence = {
    eventSimplyId: 'EVNT-0006-FFFF',
    bodySha256: fingerprint('interrupted-uninstall'),
  };
  await store.saveCredential(namespace, { accessToken: 'must-not-escape-after-fence' }, null);
  dynamo.failNextBatchWrite = true;
  await assert.rejects(store.fenceAndCleanupInstallation('INST-0001-AAAA', evidence), /cleanup interruption/u);
  await assert.rejects(store.loadCredential(namespace), HelloLifecycleFencedError);
  assert.deepEqual(await store.fenceAndCleanupInstallation('INST-0001-AAAA', evidence), {
    deleted: 1,
    replayed: true,
  });
});

test('provider-link fence preserves sibling links and blocks callback storage after selective revoke', async () => {
  now.value = Date.UTC(2026, 8, 6, 12, 0, 0);
  const { store } = makeStore();
  const revoked = memberProvider('MEMB-0001-AAAA', 'IPAL-0002-AAAA');
  const sibling = memberProvider('MEMB-0001-AAAA', 'IPAL-0003-BBBB');
  await store.saveCredential(revoked, { marker: 'revoked' }, null);
  await store.saveCredential(sibling, { marker: 'sibling' }, null);
  const evidence = {
    eventSimplyId: 'EVNT-0005-EEEE',
    bodySha256: fingerprint('account-link-revoked'),
  };
  assert.deepEqual(await store.fenceAndCleanupGrant(revoked, evidence), { deleted: 1, replayed: false });
  await assert.rejects(store.saveCredential(revoked, { marker: 'late-callback' }, null), HelloLifecycleFencedError);
  assert.deepEqual((await store.loadCredential(sibling)).value, { marker: 'sibling' });
});
