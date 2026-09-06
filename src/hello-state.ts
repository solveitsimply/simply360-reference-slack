import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
} from 'node:crypto';

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  BatchWriteCommand,
  DeleteCommand,
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactGetCommand,
  TransactWriteCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager';

import { assertSimplyId, SHA256_HEX_PATTERN } from './contracts.js';
import { IdempotencyConflictError } from './runtime.js';

const MAX_SERIALIZED_VALUE_BYTES = 64 * 1024;
const MAX_OAUTH_STATE_LIFETIME_SECONDS = 10 * 60;
const DEFAULT_COMPLETED_LIFETIME_SECONDS = 7 * 24 * 60 * 60;
const IDEMPOTENCY_OPERATION_PATTERN = /^[a-z][a-z0-9.-]{0,63}$/u;

export type HelloGrant = 'simply360' | 'provider';

export type HelloGrantNamespace =
  | {
      readonly teamIntegrationSimplyId: string;
      readonly scope: 'installation';
      readonly grant: 'simply360';
      readonly integrationInstallationGrantSimplyId: string;
    }
  | {
      readonly teamIntegrationSimplyId: string;
      readonly scope: 'installation';
      readonly grant: 'provider';
      readonly integrationProviderAccountLinkSimplyId: string;
    }
  | {
      readonly teamIntegrationSimplyId: string;
      readonly scope: 'member';
      readonly memberSimplyId: string;
      readonly grant: 'simply360';
      readonly integrationInstallationGrantSimplyId: string;
    }
  | {
      readonly teamIntegrationSimplyId: string;
      readonly scope: 'member';
      readonly memberSimplyId: string;
      readonly grant: 'provider';
      readonly integrationProviderAccountLinkSimplyId: string;
    };

export interface StoredHelloCredential<T extends Readonly<Record<string, unknown>>> {
  readonly revision: number;
  readonly value: T;
}

export interface HelloStateStoreOptions {
  readonly tableName: string;
  readonly runtimeSecretId: string;
  readonly dynamo: DynamoDBDocumentClient;
  readonly secrets: SecretsManagerClient;
  readonly now?: () => number;
}

export interface CreateHelloStateStoreOptions {
  readonly tableName: string;
  readonly runtimeSecretId: string;
  readonly region?: string;
}

interface EncryptionEnvelope {
  readonly version: 1;
  readonly keyId: string;
  readonly iv: string;
  readonly ciphertext: string;
  readonly authenticationTag: string;
}

interface EncryptionKeyring {
  readonly current: Buffer;
  readonly byId: ReadonlyMap<string, Buffer>;
}

interface StoredItem {
  readonly pk: string;
  readonly sk: string;
  readonly recordType: string;
  readonly requestFingerprint?: string;
  readonly status?: string;
  readonly claimOwner?: string;
  readonly revision?: number;
  readonly expiresAtEpoch?: number;
  readonly browserNonceHash?: string;
  readonly encryptedValue?: EncryptionEnvelope;
  readonly eventSimplyId?: string;
  readonly bodySha256?: string;
}

export interface HelloLifecycleCleanupEvidence {
  readonly eventSimplyId: string;
  readonly bodySha256: string;
}

export interface HelloWebhookDeliveryEvidence extends HelloLifecycleCleanupEvidence {
  readonly deliverySimplyId: string;
}

export type HelloGrantAuthority =
  | { readonly grant: 'simply360'; readonly integrationInstallationGrantSimplyId: string }
  | { readonly grant: 'provider'; readonly integrationProviderAccountLinkSimplyId: string };

export class HelloLifecycleFencedError extends Error {
  public constructor() {
    super('the exact installation or grant has entered terminal lifecycle cleanup');
    this.name = 'HelloLifecycleFencedError';
  }
}

export class ConcurrentHelloStateUpdateError extends Error {
  public constructor() {
    super('hello state changed before the conditional write completed');
    this.name = 'ConcurrentHelloStateUpdateError';
  }
}

export class OAuthStateUnavailableError extends Error {
  public constructor() {
    super('OAuth state is absent, expired, already consumed, or belongs to another grant');
    this.name = 'OAuthStateUnavailableError';
  }
}

export class HelloOperationInProgressError extends Error {
  public constructor() {
    super('an operation with this idempotency key is already in progress');
    this.name = 'HelloOperationInProgressError';
  }
}

export class HelloIdempotencyCompletionUnknownError extends Error {
  public constructor(options?: ErrorOptions) {
    super('the durable idempotency outcome could not be confirmed', options);
    this.name = 'HelloIdempotencyCompletionUnknownError';
  }
}

/**
 * The operation caller may use this error only when it has authoritative proof
 * that no external side effect occurred. It is the sole failure that releases
 * an idempotency claim for retry.
 */
export class HelloOperationNoEffectError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'HelloOperationNoEffectError';
  }
}

const sha256 = (value: string | Uint8Array): string =>
  createHash('sha256').update(value).digest('hex');

const isConditionalFailure = (error: unknown): boolean =>
  typeof error === 'object' &&
  error !== null &&
  'name' in error &&
  error.name === 'ConditionalCheckFailedException';

const assertNonemptySetting = (value: string, label: string): void => {
  if (value.trim() !== value || value.length < 1 || value.length > 512) {
    throw new Error(`${label} is invalid`);
  }
};

const assertNamespace = (namespace: HelloGrantNamespace): void => {
  assertSimplyId(namespace.teamIntegrationSimplyId, 'teamIntegrationSimplyId');
  if (namespace.scope === 'member') {
    assertSimplyId(namespace.memberSimplyId, 'memberSimplyId');
  }
  if (namespace.grant === 'simply360') {
    assertSimplyId(
      namespace.integrationInstallationGrantSimplyId,
      'integrationInstallationGrantSimplyId',
    );
  } else if (namespace.grant === 'provider') {
    assertSimplyId(
      namespace.integrationProviderAccountLinkSimplyId,
      'integrationProviderAccountLinkSimplyId',
    );
  } else {
    throw new Error('grant provider is invalid');
  }
};

const partitionKey = (teamIntegrationSimplyId: string): string =>
  `INSTALLATION#${teamIntegrationSimplyId}`;

const grantPrefix = (namespace: HelloGrantNamespace): string => {
  assertNamespace(namespace);
  const scope = namespace.scope === 'installation'
    ? 'INSTALLATION'
    : `MEMBER#${namespace.memberSimplyId}`;
  const authority = namespace.grant === 'simply360'
      ? `GRANT#SIMPLY360#${namespace.integrationInstallationGrantSimplyId}`
    : `ACCOUNT_LINK#PROVIDER#${namespace.integrationProviderAccountLinkSimplyId}`;
  return `AUTH#${scope}#${authority}`;
};

const lifecyclePartitionKey = (teamIntegrationSimplyId: string): string => {
  assertSimplyId(teamIntegrationSimplyId, 'teamIntegrationSimplyId');
  return `LIFECYCLE#${teamIntegrationSimplyId}`;
};

const installationFenceKey = (teamIntegrationSimplyId: string) => ({
  pk: lifecyclePartitionKey(teamIntegrationSimplyId),
  sk: 'INSTALLATION',
});

const grantAuthoritySegment = (authority: HelloGrantAuthority): string => {
  if (authority.grant === 'simply360') {
    assertSimplyId(authority.integrationInstallationGrantSimplyId, 'integrationInstallationGrantSimplyId');
    return `GRANT#SIMPLY360#${authority.integrationInstallationGrantSimplyId}`;
  }
  assertSimplyId(authority.integrationProviderAccountLinkSimplyId, 'integrationProviderAccountLinkSimplyId');
  return `ACCOUNT_LINK#PROVIDER#${authority.integrationProviderAccountLinkSimplyId}`;
};

const authorityFromNamespace = (namespace: HelloGrantNamespace): HelloGrantAuthority =>
  namespace.grant === 'simply360'
    ? { grant: 'simply360', integrationInstallationGrantSimplyId: namespace.integrationInstallationGrantSimplyId }
    : { grant: 'provider', integrationProviderAccountLinkSimplyId: namespace.integrationProviderAccountLinkSimplyId };

const grantFenceKey = (teamIntegrationSimplyId: string, authority: HelloGrantAuthority) => ({
  pk: lifecyclePartitionKey(teamIntegrationSimplyId),
  sk: grantAuthoritySegment(authority),
});

const assertCleanupEvidence = (evidence: HelloLifecycleCleanupEvidence): void => {
  assertSimplyId(evidence.eventSimplyId, 'eventSimplyId');
  if (!SHA256_HEX_PATTERN.test(evidence.bodySha256)) {
    throw new Error('bodySha256 must be a lowercase SHA-256 hex digest');
  }
};

const assertOAuthState = (state: string): void => {
  if (
    state.length < 32 ||
    state.length > 512 ||
    !/^[A-Za-z0-9._~-]+$/u.test(state)
  ) {
    throw new Error('OAuth state is invalid');
  }
};

const assertBrowserNonce = (browserNonce: string): void => {
  if (
    browserNonce.length < 32 ||
    browserNonce.length > 512 ||
    !/^[A-Za-z0-9_-]+$/u.test(browserNonce)
  ) {
    throw new Error('browser nonce is invalid');
  }
};

const serialize = (value: unknown, label: string): Buffer => {
  let encoded: string | undefined;
  try {
    encoded = JSON.stringify(value);
  } catch (error) {
    throw new Error(`${label} must be JSON serializable`, { cause: error });
  }
  if (encoded === undefined) throw new Error(`${label} must be JSON serializable`);
  const bytes = Buffer.from(encoded, 'utf8');
  if (bytes.length < 1 || bytes.length > MAX_SERIALIZED_VALUE_BYTES) {
    throw new Error(`${label} exceeds the 64 KiB storage limit`);
  }
  return bytes;
};

function assertAggregate(
  value: unknown,
  label: string,
): asserts value is Readonly<Record<string, unknown>> {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new Error(`${label} must be a plain object`);
  }
}

const deserialize = <T>(bytes: Buffer, label: string): T => {
  try {
    return JSON.parse(bytes.toString('utf8')) as T;
  } catch (error) {
    throw new Error(`${label} is corrupt`, { cause: error });
  }
};

const parseKey = (value: unknown, label: string): Buffer => {
  if (typeof value !== 'string') throw new Error(`${label} is missing`);
  const key = Buffer.from(value, 'base64');
  if (key.length !== 32 || key.toString('base64') !== value) {
    throw new Error(`${label} must be the canonical base64 encoding of 32 bytes`);
  }
  return key;
};

const keyId = (key: Buffer): string => sha256(key);

const aad = (pk: string, sk: string, context: string): Buffer =>
  Buffer.from(`simply360-reference-slack:hello-state:v1:${pk}:${sk}:${context}`, 'utf8');

const parseEnvelope = (input: unknown): EncryptionEnvelope => {
  if (
    typeof input !== 'object' ||
    input === null ||
    Array.isArray(input) ||
    !('version' in input) ||
    input.version !== 1 ||
    !('keyId' in input) ||
    typeof input.keyId !== 'string' ||
    !SHA256_HEX_PATTERN.test(input.keyId) ||
    !('iv' in input) ||
    typeof input.iv !== 'string' ||
    !('ciphertext' in input) ||
    typeof input.ciphertext !== 'string' ||
    !('authenticationTag' in input) ||
    typeof input.authenticationTag !== 'string'
  ) {
    throw new Error('encrypted hello state is corrupt');
  }
  return {
    version: 1,
    keyId: input.keyId,
    iv: input.iv,
    ciphertext: input.ciphertext,
    authenticationTag: input.authenticationTag,
  };
};

export const createHelloStateStore = (
  options: CreateHelloStateStoreOptions,
): HelloStateStore => {
  const dynamo = DynamoDBDocumentClient.from(
    new DynamoDBClient({ region: options.region }),
    { marshallOptions: { removeUndefinedValues: true } },
  );
  return new HelloStateStore({
    ...options,
    dynamo,
    secrets: new SecretsManagerClient({ region: options.region }),
  });
};

/**
 * Durable state for the hosted hello runtime.
 *
 * Callers must complete authority checks before using this store. Cleanup is
 * deliberately namespace-scoped and must run only after new work for that
 * namespace has been fenced by the lifecycle handler.
 */
export class HelloStateStore {
  private readonly tableName: string;
  private readonly runtimeSecretId: string;
  private readonly dynamo: DynamoDBDocumentClient;
  private readonly secrets: SecretsManagerClient;
  private readonly now: () => number;

  public constructor(options: HelloStateStoreOptions) {
    assertNonemptySetting(options.tableName, 'tableName');
    assertNonemptySetting(options.runtimeSecretId, 'runtimeSecretId');
    this.tableName = options.tableName;
    this.runtimeSecretId = options.runtimeSecretId;
    this.dynamo = options.dynamo;
    this.secrets = options.secrets;
    this.now = options.now ?? Date.now;
  }

  private lifecycleGuardChecks(namespace: HelloGrantNamespace) {
    return [
      installationFenceKey(namespace.teamIntegrationSimplyId),
      grantFenceKey(namespace.teamIntegrationSimplyId, authorityFromNamespace(namespace)),
    ].map((Key) => ({
      ConditionCheck: {
        TableName: this.tableName,
        Key,
        ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
      },
    }));
  }

  private async guardedWrite(
    namespace: HelloGrantNamespace,
    write: Record<string, unknown>,
  ): Promise<void> {
    try {
      await this.dynamo.send(new TransactWriteCommand({
        TransactItems: [...this.lifecycleGuardChecks(namespace), write],
      }));
    } catch (error) {
      if (isConditionalFailure(error) || (typeof error === 'object' && error !== null && 'name' in error && error.name === 'TransactionCanceledException')) {
        const fences = await Promise.all(
          [
            installationFenceKey(namespace.teamIntegrationSimplyId),
            grantFenceKey(namespace.teamIntegrationSimplyId, authorityFromNamespace(namespace)),
          ].map((Key) =>
            this.dynamo.send(new GetCommand({ TableName: this.tableName, Key, ConsistentRead: true })),
          ),
        );
        if (fences.some((result) => result.Item !== undefined)) throw new HelloLifecycleFencedError();
        throw new ConcurrentHelloStateUpdateError();
      }
      throw error;
    }
  }

  /**
   * Store a browser-bound OAuth intent before Simply360 has selected an
   * installation. The partition contains only a digest of the opaque state;
   * no Team, member, installation, or grant coordinate can be guessed here.
   */
  public async createPendingOAuthIntent<T extends Readonly<Record<string, unknown>>>(
    state: string,
    browserNonce: string,
    expiresAt: Date,
    value: T,
  ): Promise<void> {
    assertOAuthState(state);
    assertBrowserNonce(browserNonce);
    assertAggregate(value, 'pending OAuth intent value');
    const nowEpoch = Math.floor(this.now() / 1_000);
    const expiresAtEpoch = Math.floor(expiresAt.getTime() / 1_000);
    if (
      !Number.isSafeInteger(expiresAtEpoch) ||
      expiresAtEpoch <= nowEpoch ||
      expiresAtEpoch > nowEpoch + MAX_OAUTH_STATE_LIFETIME_SECONDS
    ) {
      throw new Error('pending OAuth intent expiry must be within the next 10 minutes');
    }
    const pk = `PENDING_OAUTH#${sha256(state)}`;
    const sk = 'INTENT';
    const encryptedValue = await this.encrypt(pk, sk, 'pending-oauth', {
      browserNonce,
      value,
    });
    try {
      await this.dynamo.send(new PutCommand({
        TableName: this.tableName,
        Item: {
          pk,
          sk,
          recordType: 'PENDING_OAUTH_INTENT',
          expiresAtEpoch,
          browserNonceHash: sha256(browserNonce),
          encryptedValue,
        },
        ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
      }));
    } catch (error) {
      if (isConditionalFailure(error)) throw new ConcurrentHelloStateUpdateError();
      throw error;
    }
  }

  /** Atomically consume the exact pending intent from the same browser. */
  public async consumePendingOAuthIntent<T extends Readonly<Record<string, unknown>>>(
    state: string,
    browserNonce: string,
  ): Promise<T> {
    assertOAuthState(state);
    assertBrowserNonce(browserNonce);
    const pk = `PENDING_OAUTH#${sha256(state)}`;
    const sk = 'INTENT';
    let item: StoredItem | undefined;
    try {
      const result = await this.dynamo.send(new DeleteCommand({
        TableName: this.tableName,
        Key: { pk, sk },
        ConditionExpression: '#recordType = :recordType AND #expiresAtEpoch > :now AND #browserNonceHash = :browserNonceHash',
        ExpressionAttributeNames: {
          '#recordType': 'recordType',
          '#expiresAtEpoch': 'expiresAtEpoch',
          '#browserNonceHash': 'browserNonceHash',
        },
        ExpressionAttributeValues: {
          ':recordType': 'PENDING_OAUTH_INTENT',
          ':now': Math.floor(this.now() / 1_000),
          ':browserNonceHash': sha256(browserNonce),
        },
        ReturnValues: 'ALL_OLD',
      }));
      item = result.Attributes as StoredItem | undefined;
    } catch (error) {
      if (isConditionalFailure(error)) throw new OAuthStateUnavailableError();
      throw error;
    }
    if (item?.encryptedValue === undefined) throw new OAuthStateUnavailableError();
    const pending = await this.decrypt<{
      readonly browserNonce: string;
      readonly value: T;
    }>(pk, sk, 'pending-oauth', item.encryptedValue);
    if (pending.browserNonce !== browserNonce) throw new OAuthStateUnavailableError();
    assertAggregate(pending.value, 'pending OAuth intent value');
    return pending.value;
  }

  public async createOAuthState<T extends Readonly<Record<string, unknown>>>(
    namespace: HelloGrantNamespace,
    state: string,
    expiresAt: Date,
    value: T,
  ): Promise<void> {
    assertOAuthState(state);
    assertAggregate(value, 'OAuth state value');
    const nowEpoch = Math.floor(this.now() / 1_000);
    const expiresAtEpoch = Math.floor(expiresAt.getTime() / 1_000);
    if (
      !Number.isSafeInteger(expiresAtEpoch) ||
      expiresAtEpoch <= nowEpoch ||
      expiresAtEpoch > nowEpoch + MAX_OAUTH_STATE_LIFETIME_SECONDS
    ) {
      throw new Error('OAuth state expiry must be within the next 10 minutes');
    }
    const pk = partitionKey(namespace.teamIntegrationSimplyId);
    const sk = `${grantPrefix(namespace)}#OAUTH#${sha256(state)}`;
    const encryptedValue = await this.encrypt(pk, sk, 'oauth', value);
    try {
      await this.guardedWrite(namespace, {
        Put: {
          TableName: this.tableName,
          Item: { pk, sk, recordType: 'OAUTH_STATE', expiresAtEpoch, encryptedValue },
          ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
        },
      });
    } catch (error) {
      if (error instanceof HelloLifecycleFencedError) throw error;
      if (error instanceof ConcurrentHelloStateUpdateError) throw error;
      if (isConditionalFailure(error)) throw new ConcurrentHelloStateUpdateError();
      throw error;
    }
  }

  public async consumeOAuthState<T extends Readonly<Record<string, unknown>>>(
    namespace: HelloGrantNamespace,
    state: string,
  ): Promise<T> {
    assertOAuthState(state);
    const pk = partitionKey(namespace.teamIntegrationSimplyId);
    const sk = `${grantPrefix(namespace)}#OAUTH#${sha256(state)}`;
    const existing = await this.dynamo.send(new GetCommand({
      TableName: this.tableName,
      Key: { pk, sk },
      ConsistentRead: true,
    }));
    const item = existing.Item as StoredItem | undefined;
    if (item?.encryptedValue === undefined) throw new OAuthStateUnavailableError();
    try {
      await this.guardedWrite(namespace, {
        Delete: {
          TableName: this.tableName,
          Key: { pk, sk },
          ConditionExpression: '#recordType = :recordType AND #expiresAtEpoch > :now',
          ExpressionAttributeNames: {
            '#recordType': 'recordType',
            '#expiresAtEpoch': 'expiresAtEpoch',
          },
          ExpressionAttributeValues: {
            ':recordType': 'OAUTH_STATE',
            ':now': Math.floor(this.now() / 1_000),
          },
        },
      });
    } catch (error) {
      if (error instanceof HelloLifecycleFencedError) throw error;
      if (error instanceof ConcurrentHelloStateUpdateError) throw new OAuthStateUnavailableError();
      if (isConditionalFailure(error)) throw new OAuthStateUnavailableError();
      throw error;
    }
    return this.decrypt<T>(pk, sk, 'oauth', item.encryptedValue);
  }

  public async loadCredential<T extends Readonly<Record<string, unknown>>>(
    namespace: HelloGrantNamespace,
  ): Promise<StoredHelloCredential<T> | undefined> {
    const pk = partitionKey(namespace.teamIntegrationSimplyId);
    const sk = `${grantPrefix(namespace)}#CREDENTIAL`;
    const result = await this.dynamo.send(new TransactGetCommand({
      TransactItems: [
        { Get: { TableName: this.tableName, Key: installationFenceKey(namespace.teamIntegrationSimplyId) } },
        { Get: { TableName: this.tableName, Key: grantFenceKey(namespace.teamIntegrationSimplyId, authorityFromNamespace(namespace)) } },
        { Get: { TableName: this.tableName, Key: { pk, sk } } },
      ],
    }));
    if (result.Responses?.[0]?.Item !== undefined || result.Responses?.[1]?.Item !== undefined) {
      throw new HelloLifecycleFencedError();
    }
    const item = result.Responses?.[2]?.Item as StoredItem | undefined;
    if (item === undefined) return undefined;
    if (
      item.recordType !== 'CREDENTIAL' ||
      !Number.isSafeInteger(item.revision) ||
      (item.revision ?? 0) < 1 ||
      item.encryptedValue === undefined
    ) {
      throw new Error('stored hello credential is corrupt');
    }
    return {
      revision: item.revision as number,
      value: await this.decrypt<T>(pk, sk, 'credential', item.encryptedValue),
    };
  }

  public async saveCredential<T extends Readonly<Record<string, unknown>>>(
    namespace: HelloGrantNamespace,
    value: T,
    expectedRevision: number | null,
  ): Promise<StoredHelloCredential<T>> {
    assertAggregate(value, 'credential value');
    if (
      expectedRevision !== null &&
      (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1)
    ) {
      throw new Error('expectedRevision is invalid');
    }
    const pk = partitionKey(namespace.teamIntegrationSimplyId);
    const sk = `${grantPrefix(namespace)}#CREDENTIAL`;
    const revision = expectedRevision === null ? 1 : expectedRevision + 1;
    const encryptedValue = await this.encrypt(pk, sk, 'credential', value);
    const create = expectedRevision === null;
    try {
      await this.guardedWrite(namespace, {
        Put: {
          TableName: this.tableName,
          Item: { pk, sk, recordType: 'CREDENTIAL', revision, encryptedValue },
          ConditionExpression: create
            ? 'attribute_not_exists(pk) AND attribute_not_exists(sk)'
            : '#recordType = :recordType AND #revision = :expectedRevision',
          ...(create ? {} : {
            ExpressionAttributeNames: {
              '#recordType': 'recordType',
              '#revision': 'revision',
            },
            ExpressionAttributeValues: {
              ':recordType': 'CREDENTIAL',
              ':expectedRevision': expectedRevision,
            },
          }),
        },
      });
    } catch (error) {
      if (error instanceof HelloLifecycleFencedError) throw error;
      if (error instanceof ConcurrentHelloStateUpdateError) throw error;
      if (isConditionalFailure(error)) throw new ConcurrentHelloStateUpdateError();
      throw error;
    }
    return { revision, value };
  }

  public async deleteCredential(
    namespace: HelloGrantNamespace,
    expectedRevision: number,
  ): Promise<void> {
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1) {
      throw new Error('expectedRevision is invalid');
    }
    const pk = partitionKey(namespace.teamIntegrationSimplyId);
    const sk = `${grantPrefix(namespace)}#CREDENTIAL`;
    try {
      await this.guardedWrite(namespace, {
        Delete: {
          TableName: this.tableName,
          Key: { pk, sk },
          ConditionExpression: '#recordType = :recordType AND #revision = :expectedRevision',
          ExpressionAttributeNames: {
            '#recordType': 'recordType',
            '#revision': 'revision',
          },
          ExpressionAttributeValues: {
            ':recordType': 'CREDENTIAL',
            ':expectedRevision': expectedRevision,
          },
        },
      });
    } catch (error) {
      if (error instanceof HelloLifecycleFencedError) throw error;
      if (error instanceof ConcurrentHelloStateUpdateError) throw error;
      if (isConditionalFailure(error)) throw new ConcurrentHelloStateUpdateError();
      throw error;
    }
  }

  public async runIdempotent<T>(
    namespace: HelloGrantNamespace,
    operationName: string,
    idempotencyKey: string,
    requestFingerprint: string,
    operation: () => Promise<T>,
  ): Promise<{ readonly replayed: boolean; readonly value: T }> {
    if (!IDEMPOTENCY_OPERATION_PATTERN.test(operationName)) {
      throw new Error('operationName is invalid');
    }
    if (idempotencyKey.length < 1 || idempotencyKey.length > 512) {
      throw new Error('idempotencyKey is invalid');
    }
    if (!SHA256_HEX_PATTERN.test(requestFingerprint)) {
      throw new Error('requestFingerprint must be a SHA-256 hex digest');
    }
    const pk = partitionKey(namespace.teamIntegrationSimplyId);
    const sk = `${grantPrefix(namespace)}#IDEMPOTENCY#${operationName.toUpperCase()}#${sha256(idempotencyKey)}`;
    const claimOwner = randomUUID();
    const nowEpoch = Math.floor(this.now() / 1_000);
    try {
      await this.guardedWrite(namespace, {
        Put: {
          TableName: this.tableName,
          Item: {
            pk,
            sk,
            recordType: 'IDEMPOTENCY',
            requestFingerprint,
            status: 'IN_PROGRESS',
            claimOwner,
          },
          ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
        },
      });
    } catch (error) {
      if (error instanceof HelloLifecycleFencedError) throw error;
      if (!(error instanceof ConcurrentHelloStateUpdateError) && !isConditionalFailure(error)) throw error;
      const existing = await this.dynamo.send(new GetCommand({
        TableName: this.tableName,
        Key: { pk, sk },
        ConsistentRead: true,
      }));
      const item = existing.Item as StoredItem | undefined;
      if (item?.recordType !== 'IDEMPOTENCY') {
        throw new HelloOperationInProgressError();
      }
      if (item.requestFingerprint !== requestFingerprint) {
        throw new IdempotencyConflictError();
      }
      if (item.status !== 'COMPLETE' || item.encryptedValue === undefined) {
        throw new HelloOperationInProgressError();
      }
      return {
        replayed: true,
        value: await this.decrypt<T>(pk, sk, 'idempotency', item.encryptedValue),
      };
    }

    let value: T;
    try {
      value = await operation();
    } catch (operationError) {
      if (!(operationError instanceof HelloOperationNoEffectError)) {
        throw new HelloIdempotencyCompletionUnknownError({ cause: operationError });
      }
      try {
        await this.dynamo.send(new DeleteCommand({
          TableName: this.tableName,
          Key: { pk, sk },
          ConditionExpression: '#status = :inProgress AND #claimOwner = :claimOwner',
          ExpressionAttributeNames: {
            '#status': 'status',
            '#claimOwner': 'claimOwner',
          },
          ExpressionAttributeValues: {
            ':inProgress': 'IN_PROGRESS',
            ':claimOwner': claimOwner,
          },
        }));
      } catch (cleanupError) {
        throw new AggregateError(
          [operationError, cleanupError],
          'operation failed and its idempotency claim could not be released',
        );
      }
      throw operationError;
    }

    try {
      const encryptedValue = await this.encrypt(pk, sk, 'idempotency', value);
      await this.guardedWrite(namespace, {
        Update: {
          TableName: this.tableName,
          Key: { pk, sk },
          UpdateExpression: 'SET #status = :complete, #encryptedValue = :encryptedValue, #expiresAtEpoch = :expiresAt REMOVE #claimOwner',
          ConditionExpression: '#status = :inProgress AND #claimOwner = :claimOwner AND #requestFingerprint = :requestFingerprint',
          ExpressionAttributeNames: {
            '#status': 'status',
            '#encryptedValue': 'encryptedValue',
            '#expiresAtEpoch': 'expiresAtEpoch',
            '#claimOwner': 'claimOwner',
            '#requestFingerprint': 'requestFingerprint',
          },
          ExpressionAttributeValues: {
            ':complete': 'COMPLETE',
            ':encryptedValue': encryptedValue,
            ':expiresAt': nowEpoch + DEFAULT_COMPLETED_LIFETIME_SECONDS,
            ':inProgress': 'IN_PROGRESS',
            ':claimOwner': claimOwner,
            ':requestFingerprint': requestFingerprint,
          },
        },
      });
    } catch (error) {
      throw new HelloIdempotencyCompletionUnknownError({ cause: error });
    }
    return { replayed: false, value };
  }

  /**
   * Fence one exact grant before deleting its namespace. The fence lives in a
   * separate lifecycle partition, survives cleanup, and makes every later
   * OAuth, credential, refresh, or idempotency write fail closed.
   */
  public async fenceAndCleanupGrant(
    namespace: HelloGrantNamespace,
    evidence: HelloLifecycleCleanupEvidence,
  ): Promise<{ readonly deleted: number; readonly replayed: boolean }> {
    return this.fenceAndCleanupGrantAuthority(
      namespace.teamIntegrationSimplyId,
      authorityFromNamespace(namespace),
      evidence,
    );
  }

  public async fenceAndCleanupGrantAuthority(
    teamIntegrationSimplyId: string,
    authority: HelloGrantAuthority,
    evidence: HelloLifecycleCleanupEvidence,
  ): Promise<{ readonly deleted: number; readonly replayed: boolean }> {
    const key = grantFenceKey(teamIntegrationSimplyId, authority);
    const replayed = await this.beginCleanupFence(key, evidence);
    const deleted = await this.deleteByPrefix(
      partitionKey(teamIntegrationSimplyId),
      undefined,
      `#${grantAuthoritySegment(authority)}#`,
    );
    await this.completeCleanupFence(key, evidence);
    return { deleted, replayed };
  }

  /** Fence the installation before deleting every subordinate namespace. */
  public async fenceAndCleanupInstallation(
    teamIntegrationSimplyId: string,
    evidence: HelloLifecycleCleanupEvidence,
  ): Promise<{ readonly deleted: number; readonly replayed: boolean }> {
    const key = installationFenceKey(teamIntegrationSimplyId);
    const replayed = await this.beginCleanupFence(key, evidence);
    const deleted = await this.deleteByPrefix(partitionKey(teamIntegrationSimplyId));
    await this.completeCleanupFence(key, evidence);
    return { deleted, replayed };
  }

  /** Store only hash/identity evidence for a verified signed delivery. */
  public async recordWebhookDelivery(
    teamIntegrationSimplyId: string,
    evidence: HelloWebhookDeliveryEvidence,
  ): Promise<'RECORDED' | 'DUPLICATE'> {
    assertCleanupEvidence(evidence);
    assertSimplyId(evidence.deliverySimplyId, 'deliverySimplyId');
    const pk = partitionKey(teamIntegrationSimplyId);
    const sk = `DELIVERY#${sha256(`${evidence.eventSimplyId}:${evidence.deliverySimplyId}`)}`;
    try {
      await this.dynamo.send(new TransactWriteCommand({
        TransactItems: [
          {
            ConditionCheck: {
              TableName: this.tableName,
              Key: installationFenceKey(teamIntegrationSimplyId),
              ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
            },
          },
          {
            Put: {
              TableName: this.tableName,
              Item: {
                pk,
                sk,
                recordType: 'WEBHOOK_DELIVERY',
                eventSimplyId: evidence.eventSimplyId,
                bodySha256: evidence.bodySha256,
              },
              ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
            },
          },
        ],
      }));
      return 'RECORDED';
    } catch (error) {
      if (!(isConditionalFailure(error) || (typeof error === 'object' && error !== null && 'name' in error && error.name === 'TransactionCanceledException'))) {
        throw error;
      }
      const [fence, existing] = await Promise.all([
        this.dynamo.send(new GetCommand({
          TableName: this.tableName,
          Key: installationFenceKey(teamIntegrationSimplyId),
          ConsistentRead: true,
        })),
        this.dynamo.send(new GetCommand({ TableName: this.tableName, Key: { pk, sk }, ConsistentRead: true })),
      ]);
      if (fence.Item !== undefined) throw new HelloLifecycleFencedError();
      const item = existing.Item as StoredItem | undefined;
      if (
        item?.recordType !== 'WEBHOOK_DELIVERY' ||
        item.eventSimplyId !== evidence.eventSimplyId ||
        item.bodySha256 !== evidence.bodySha256
      ) {
        throw new ConcurrentHelloStateUpdateError();
      }
      return 'DUPLICATE';
    }
  }

  private async beginCleanupFence(
    key: { readonly pk: string; readonly sk: string },
    evidence: HelloLifecycleCleanupEvidence,
  ): Promise<boolean> {
    assertCleanupEvidence(evidence);
    try {
      await this.dynamo.send(new PutCommand({
        TableName: this.tableName,
        Item: {
          ...key,
          recordType: 'LIFECYCLE_FENCE',
          status: 'CLEANUP_IN_PROGRESS',
          eventSimplyId: evidence.eventSimplyId,
          bodySha256: evidence.bodySha256,
        },
        ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
      }));
      return false;
    } catch (error) {
      if (!isConditionalFailure(error)) throw error;
      const result = await this.dynamo.send(new GetCommand({
        TableName: this.tableName,
        Key: key,
        ConsistentRead: true,
      }));
      const item = result.Item as StoredItem | undefined;
      if (
        item?.recordType !== 'LIFECYCLE_FENCE' ||
        (item.status !== 'CLEANUP_IN_PROGRESS' && item.status !== 'CLEANED') ||
        item.eventSimplyId !== evidence.eventSimplyId ||
        item.bodySha256 !== evidence.bodySha256
      ) {
        throw new HelloLifecycleFencedError();
      }
      return true;
    }
  }

  private async completeCleanupFence(
    key: { readonly pk: string; readonly sk: string },
    evidence: HelloLifecycleCleanupEvidence,
  ): Promise<void> {
    const result = await this.dynamo.send(new GetCommand({
      TableName: this.tableName,
      Key: key,
      ConsistentRead: true,
    }));
    const item = result.Item as StoredItem | undefined;
    if (
      item?.recordType === 'LIFECYCLE_FENCE' &&
      item.status === 'CLEANED' &&
      item.eventSimplyId === evidence.eventSimplyId &&
      item.bodySha256 === evidence.bodySha256
    ) {
      return;
    }
    try {
      await this.dynamo.send(new UpdateCommand({
        TableName: this.tableName,
        Key: key,
        UpdateExpression: 'SET #status = :cleaned',
        ConditionExpression:
          '#recordType = :recordType AND #status = :inProgress AND #eventSimplyId = :eventSimplyId AND #bodySha256 = :bodySha256',
        ExpressionAttributeNames: {
          '#recordType': 'recordType',
          '#status': 'status',
          '#eventSimplyId': 'eventSimplyId',
          '#bodySha256': 'bodySha256',
        },
        ExpressionAttributeValues: {
          ':recordType': 'LIFECYCLE_FENCE',
          ':inProgress': 'CLEANUP_IN_PROGRESS',
          ':cleaned': 'CLEANED',
          ':eventSimplyId': evidence.eventSimplyId,
          ':bodySha256': evidence.bodySha256,
        },
      }));
    } catch (error) {
      if (isConditionalFailure(error)) throw new HelloLifecycleFencedError();
      throw error;
    }
  }

  private async loadKeyring(): Promise<EncryptionKeyring> {
    const response = await this.secrets.send(new GetSecretValueCommand({
      SecretId: this.runtimeSecretId,
    }));
    if (response.SecretString === undefined || response.SecretBinary !== undefined) {
      throw new Error('runtime secret must be a JSON SecretString');
    }
    if (Buffer.byteLength(response.SecretString, 'utf8') > MAX_SERIALIZED_VALUE_BYTES) {
      throw new Error('runtime secret exceeds the 64 KiB limit');
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(response.SecretString) as unknown;
    } catch (error) {
      throw new Error('runtime secret is not valid JSON', { cause: error });
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('runtime secret must be a JSON object');
    }
    const current = parseKey(
      'helloStateEncryptionKeyCurrent' in parsed
        ? parsed.helloStateEncryptionKeyCurrent
        : undefined,
      'helloStateEncryptionKeyCurrent',
    );
    const keys = [current];
    if ('helloStateEncryptionKeyPrevious' in parsed && parsed.helloStateEncryptionKeyPrevious !== undefined) {
      keys.push(parseKey(parsed.helloStateEncryptionKeyPrevious, 'helloStateEncryptionKeyPrevious'));
    }
    return { current, byId: new Map(keys.map((key) => [keyId(key), key])) };
  }

  private async encrypt(
    pk: string,
    sk: string,
    context: string,
    value: unknown,
  ): Promise<EncryptionEnvelope> {
    const plaintext = serialize(value, `${context} value`);
    const keyring = await this.loadKeyring();
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', keyring.current, iv);
    cipher.setAAD(aad(pk, sk, context));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return {
      version: 1,
      keyId: keyId(keyring.current),
      iv: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      authenticationTag: cipher.getAuthTag().toString('base64'),
    };
  }

  private async decrypt<T>(
    pk: string,
    sk: string,
    context: string,
    untrustedEnvelope: unknown,
  ): Promise<T> {
    const envelope = parseEnvelope(untrustedEnvelope);
    const keyring = await this.loadKeyring();
    const key = keyring.byId.get(envelope.keyId);
    if (key === undefined) throw new Error('encrypted hello state uses an unavailable key');
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
      decipher.setAAD(aad(pk, sk, context));
      decipher.setAuthTag(Buffer.from(envelope.authenticationTag, 'base64'));
      return deserialize<T>(
        Buffer.concat([
          decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
          decipher.final(),
        ]),
        `${context} value`,
      );
    } catch (error) {
      throw new Error('encrypted hello state failed authentication', { cause: error });
    }
  }

  private async deleteByPrefix(pk: string, prefix?: string, contains?: string): Promise<number> {
    const keys: Array<{ readonly pk: string; readonly sk: string }> = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;
    do {
      const result = await this.dynamo.send(new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: prefix === undefined
          ? 'pk = :pk'
          : 'pk = :pk AND begins_with(sk, :prefix)',
        ExpressionAttributeValues: prefix === undefined
          ? { ':pk': pk }
          : { ':pk': pk, ':prefix': prefix },
        ProjectionExpression: 'pk, sk',
        ConsistentRead: true,
        ExclusiveStartKey: exclusiveStartKey,
      }));
      for (const item of result.Items ?? []) {
        if (typeof item.pk !== 'string' || typeof item.sk !== 'string') {
          throw new Error('hello state cleanup query returned an invalid key');
        }
        if (contains === undefined || item.sk.includes(contains)) keys.push({ pk: item.pk, sk: item.sk });
      }
      exclusiveStartKey = result.LastEvaluatedKey;
    } while (exclusiveStartKey !== undefined);

    for (let offset = 0; offset < keys.length; offset += 25) {
      const requests = keys.slice(offset, offset + 25).map((Key) => ({
        DeleteRequest: { Key },
      }));
      const result = await this.dynamo.send(new BatchWriteCommand({
        RequestItems: { [this.tableName]: requests },
      }));
      if ((result.UnprocessedItems?.[this.tableName]?.length ?? 0) > 0) {
        throw new Error('hello state cleanup was incomplete');
      }
    }
    return keys.length;
  }
}
