import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmod, mkdir, open, readFile, rename } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

import {
  SIMPLY_ID_PATTERN,
  parseCreateRecordFromMessageInput,
  type CreateRecordFromMessageInput,
  type OAuthScope,
  type OAuthTokenSet,
  type RemoteTriggerPublisher,
} from './contracts.js';
import {
  IdempotencyConflictError,
  type IdempotencyStore,
} from './runtime.js';
import type { SlackOAuthGrant } from './slack-oauth.js';

export type ReferenceInstallationStatus =
  | 'PENDING_SETUP'
  | 'ACTIVE'
  | 'UNINSTALLING'
  | 'UNINSTALLED';

interface PersistedOAuthAttempt {
  readonly state: string;
  readonly codeVerifier?: string;
}

export interface PersistedUserLink {
  readonly linkSimplyId: string;
  readonly userSimplyId: string;
  active: boolean;
}

export interface PersistedReferenceInstallation {
  readonly teamIntegrationSimplyId: string;
  readonly teamSimplyId: string;
  readonly expectedSlackTeamId: string;
  readonly eventChannel: string;
  status: ReferenceInstallationStatus;
  simply360OAuth?: PersistedOAuthAttempt;
  slackOAuth?: PersistedOAuthAttempt;
  simply360Credential?: OAuthTokenSet;
  slackCredential?: SlackOAuthGrant;
  readonly userLinks: Record<string, PersistedUserLink>;
  readonly blueprintPackageKeys: string[];
  slackRevocationOutcome?: 'NOT_REQUIRED' | 'SUCCEEDED' | 'FAILED';
}

interface PersistedSharedBlueprint {
  readonly teamBlueprintSimplyId: string;
  readonly teamSimplyId: string;
  readonly packageKey: string;
  installationSimplyIds: string[];
}

interface PersistedIdempotencyResult {
  readonly requestFingerprint: string;
  readonly value: unknown;
}

export interface ReferenceState {
  readonly schemaVersion: 1;
  nextUserLinkSequence: number;
  readonly installations: Record<string, PersistedReferenceInstallation>;
  readonly sharedBlueprints: Record<string, PersistedSharedBlueprint>;
  readonly idempotency: Record<string, PersistedIdempotencyResult>;
  readonly remoteTriggers: Record<
    string,
    {
      readonly teamIntegrationSimplyId: string;
      readonly requestFingerprint: string;
      readonly input: CreateRecordFromMessageInput;
    }
  >;
}

const initialState = (): ReferenceState => ({
  schemaVersion: 1,
  nextUserLinkSequence: 0,
  installations: {},
  sharedBlueprints: {},
  idempotency: {},
  remoteTriggers: {},
});

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

const secretsMatch = (expectedValue: string, receivedValue: string): boolean => {
  const expected = Buffer.from(expectedValue);
  const received = Buffer.from(receivedValue);
  return (
    expected.length === received.length &&
    timingSafeEqual(expected, received)
  );
};

const isRecord = (input: unknown): input is Record<string, unknown> =>
  typeof input === 'object' &&
  input !== null &&
  !Array.isArray(input) &&
  Object.getPrototypeOf(input) === Object.prototype;

const assertExactStateKeys = (
  value: Record<string, unknown>,
  keys: readonly string[],
  label: string,
): void => {
  const allowed = new Set(keys);
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new Error(`${label} contains an unknown property`);
  }
};

const assertStringArray: (
  input: unknown,
  label: string,
) => asserts input is string[] = (input, label) => {
  if (!Array.isArray(input) || input.some((value) => typeof value !== 'string')) {
    throw new Error(`${label} must be a string array`);
  }
};

const assertOAuthAttempt = (input: unknown, label: string): void => {
  if (!isRecord(input)) throw new Error(`${label} is invalid`);
  assertExactStateKeys(input, ['state', 'codeVerifier'], label);
  if (
    typeof input.state !== 'string' ||
    input.state.length < 32 ||
    input.state.length > 512 ||
    (input.codeVerifier !== undefined &&
      (typeof input.codeVerifier !== 'string' ||
        !/^[A-Za-z0-9\-._~]{43,128}$/u.test(input.codeVerifier)))
  ) {
    throw new Error(`${label} is invalid`);
  }
};

const assertSimply360Credential = (input: unknown, label: string): void => {
  if (!isRecord(input)) throw new Error(`${label} is invalid`);
  assertExactStateKeys(
    input,
    ['accessToken', 'refreshToken', 'tokenType', 'expiresIn', 'scope'],
    label,
  );
  const scopes = input.scope;
  assertStringArray(scopes, `${label}.scope`);
  const allowedScopes = new Set<OAuthScope>([
    'schema:read',
    'records:read',
    'records:write',
    'offline_access',
  ]);
  if (
    typeof input.accessToken !== 'string' ||
    input.accessToken.length < 1 ||
    input.accessToken.length > 4096 ||
    (input.refreshToken !== undefined &&
      (typeof input.refreshToken !== 'string' || input.refreshToken.length < 1)) ||
    input.tokenType !== 'Bearer' ||
    (input.expiresIn !== undefined &&
      (!Number.isSafeInteger(input.expiresIn) ||
        (input.expiresIn as number) < 1 ||
        (input.expiresIn as number) > 86_400)) ||
    scopes.length < 1 ||
    new Set(scopes).size !== scopes.length ||
    scopes.some((scope) => !allowedScopes.has(scope as OAuthScope))
  ) {
    throw new Error(`${label} is invalid`);
  }
};

const assertSlackCredential = (
  input: unknown,
  expectedSlackTeamId: string,
  label: string,
): void => {
  if (!isRecord(input)) throw new Error(`${label} is invalid`);
  assertExactStateKeys(
    input,
    [
      'accessToken',
      'teamId',
      'teamName',
      'botUserId',
      'scope',
      'refreshToken',
      'expiresIn',
    ],
    label,
  );
  if (
    typeof input.accessToken !== 'string' ||
    !/^xoxe\.xoxb-[A-Za-z0-9-]{10,}$/u.test(input.accessToken) ||
    input.teamId !== expectedSlackTeamId ||
    typeof input.teamName !== 'string' ||
    input.teamName.length < 1 ||
    typeof input.botUserId !== 'string' ||
    !/^[UW][A-Z0-9]{8,20}$/u.test(input.botUserId) ||
    !Array.isArray(input.scope) ||
    input.scope.length !== 1 ||
    input.scope[0] !== 'chat:write' ||
    typeof input.refreshToken !== 'string' ||
    !/^xoxe-[A-Za-z0-9-]{10,}$/u.test(input.refreshToken) ||
    !Number.isSafeInteger(input.expiresIn) ||
    (input.expiresIn as number) < 60 ||
    (input.expiresIn as number) > 86_400
  ) {
    throw new Error(`${label} is invalid`);
  }
};

const assertState = (input: unknown): ReferenceState => {
  if (!isRecord(input)) {
    throw new Error('reference state file is corrupt or has an unsupported schema');
  }
  assertExactStateKeys(
    input,
    [
      'schemaVersion',
      'nextUserLinkSequence',
      'installations',
      'sharedBlueprints',
      'idempotency',
      'remoteTriggers',
    ],
    'reference state',
  );
  if (
    input.schemaVersion !== 1 ||
    !Number.isSafeInteger(input.nextUserLinkSequence) ||
    (input.nextUserLinkSequence as number) < 0 ||
    !isRecord(input.installations) ||
    !isRecord(input.sharedBlueprints) ||
    !isRecord(input.idempotency) ||
    !isRecord(input.remoteTriggers)
  ) {
    throw new Error('reference state file is corrupt or has an unsupported schema');
  }
  for (const [teamIntegrationSimplyId, untrusted] of Object.entries(
    input.installations,
  )) {
    if (!isRecord(untrusted)) throw new Error('reference installation is invalid');
    assertExactStateKeys(
      untrusted,
      [
        'teamIntegrationSimplyId',
        'teamSimplyId',
        'expectedSlackTeamId',
        'eventChannel',
        'status',
        'simply360OAuth',
        'slackOAuth',
        'simply360Credential',
        'slackCredential',
        'userLinks',
        'blueprintPackageKeys',
        'slackRevocationOutcome',
      ],
      'reference installation',
    );
    if (
      untrusted.teamIntegrationSimplyId !== teamIntegrationSimplyId ||
      typeof untrusted.teamSimplyId !== 'string' ||
      typeof untrusted.expectedSlackTeamId !== 'string' ||
      typeof untrusted.eventChannel !== 'string' ||
      !['PENDING_SETUP', 'ACTIVE', 'UNINSTALLING', 'UNINSTALLED'].includes(
        untrusted.status as string,
      ) ||
      !isRecord(untrusted.userLinks)
    ) {
      throw new Error('reference installation authority is invalid');
    }
    assertSimplyId(teamIntegrationSimplyId, 'teamIntegrationSimplyId');
    assertSimplyId(untrusted.teamSimplyId, 'teamSimplyId');
    assertSlackTeamId(untrusted.expectedSlackTeamId);
    assertSlackChannelId(untrusted.eventChannel);
    const blueprintPackageKeys = untrusted.blueprintPackageKeys;
    assertStringArray(
      blueprintPackageKeys,
      'installation.blueprintPackageKeys',
    );
    if (
      new Set(blueprintPackageKeys).size !== blueprintPackageKeys.length ||
      blueprintPackageKeys.some((packageKey) => {
        try {
          assertPackageKey(packageKey);
          return false;
        } catch {
          return true;
        }
      })
    ) {
      throw new Error('installation Blueprint package keys are invalid');
    }
    if (untrusted.simply360OAuth !== undefined) {
      assertOAuthAttempt(untrusted.simply360OAuth, 'Simply360 OAuth attempt');
    }
    if (untrusted.slackOAuth !== undefined) {
      assertOAuthAttempt(untrusted.slackOAuth, 'Slack OAuth attempt');
    }
    if (untrusted.simply360Credential !== undefined) {
      assertSimply360Credential(
        untrusted.simply360Credential,
        'Simply360 credential',
      );
    }
    if (untrusted.slackCredential !== undefined) {
      assertSlackCredential(
        untrusted.slackCredential,
        untrusted.expectedSlackTeamId,
        'Slack credential',
      );
    }
    if (
      untrusted.slackRevocationOutcome !== undefined &&
      !['NOT_REQUIRED', 'SUCCEEDED', 'FAILED'].includes(
        untrusted.slackRevocationOutcome as string,
      )
    ) {
      throw new Error('Slack revocation outcome is invalid');
    }
    for (const [linkSimplyId, link] of Object.entries(untrusted.userLinks)) {
      if (!isRecord(link)) throw new Error('user link is invalid');
      assertExactStateKeys(
        link,
        ['linkSimplyId', 'userSimplyId', 'active'],
        'user link',
      );
      if (
        link.linkSimplyId !== linkSimplyId ||
        typeof link.userSimplyId !== 'string' ||
        typeof link.active !== 'boolean'
      ) {
        throw new Error('user link is invalid');
      }
      assertSimplyId(linkSimplyId, 'linkSimplyId');
      assertSimplyId(link.userSimplyId, 'userSimplyId');
    }
  }
  for (const [coordinate, untrusted] of Object.entries(input.sharedBlueprints)) {
    if (!/^[a-f0-9]{64}$/u.test(coordinate) || !isRecord(untrusted)) {
      throw new Error('shared Blueprint is invalid');
    }
    assertExactStateKeys(
      untrusted,
      [
        'teamBlueprintSimplyId',
        'teamSimplyId',
        'packageKey',
        'installationSimplyIds',
      ],
      'shared Blueprint',
    );
    if (
      typeof untrusted.teamBlueprintSimplyId !== 'string' ||
      typeof untrusted.teamSimplyId !== 'string' ||
      typeof untrusted.packageKey !== 'string'
    ) {
      throw new Error('shared Blueprint is invalid');
    }
    assertSimplyId(
      untrusted.teamBlueprintSimplyId,
      'teamBlueprintSimplyId',
    );
    assertSimplyId(untrusted.teamSimplyId, 'teamSimplyId');
    assertPackageKey(untrusted.packageKey);
    const installationSimplyIds = untrusted.installationSimplyIds;
    assertStringArray(
      installationSimplyIds,
      'shared Blueprint installationSimplyIds',
    );
    if (
      coordinate !==
        sharedBlueprintCoordinate(
          untrusted.teamSimplyId,
          untrusted.packageKey,
        ) ||
      untrusted.teamBlueprintSimplyId !== sharedBlueprintSimplyId(coordinate) ||
      new Set(installationSimplyIds).size !== installationSimplyIds.length
    ) {
      throw new Error('shared Blueprint authority is invalid');
    }
  }
  for (const [coordinate, untrusted] of Object.entries(input.idempotency)) {
    if (
      !/^[a-z][a-z0-9-]{0,63}:[a-f0-9]{64}$/u.test(coordinate) ||
      !isRecord(untrusted)
    ) {
      throw new Error('idempotency result is invalid');
    }
    assertExactStateKeys(
      untrusted,
      ['requestFingerprint', 'value'],
      'idempotency result',
    );
    if (
      typeof untrusted.requestFingerprint !== 'string' ||
      !/^[a-f0-9]{64}$/u.test(untrusted.requestFingerprint) ||
      !('value' in untrusted)
    ) {
      throw new Error('idempotency result is invalid');
    }
  }
  for (const [coordinate, untrusted] of Object.entries(input.remoteTriggers)) {
    if (!/^[a-f0-9]{64}$/u.test(coordinate) || !isRecord(untrusted)) {
      throw new Error('remote trigger is invalid');
    }
    assertExactStateKeys(
      untrusted,
      ['teamIntegrationSimplyId', 'requestFingerprint', 'input'],
      'remote trigger',
    );
    if (
      typeof untrusted.teamIntegrationSimplyId !== 'string' ||
      typeof untrusted.requestFingerprint !== 'string' ||
      !/^[a-f0-9]{64}$/u.test(untrusted.requestFingerprint)
    ) {
      throw new Error('remote trigger is invalid');
    }
    assertSimplyId(
      untrusted.teamIntegrationSimplyId,
      'teamIntegrationSimplyId',
    );
    parseCreateRecordFromMessageInput(untrusted.input);
  }
  return input as unknown as ReferenceState;
};

export class JsonFileReferenceStore {
  private queue: Promise<void> = Promise.resolve();
  private initialization?: Promise<void>;

  public constructor(public readonly path: string) {}

  public async initialize(): Promise<void> {
    this.initialization ??= this.initializeOnce();
    return this.initialization;
  }

  public async read(): Promise<ReferenceState> {
    await this.initialize();
    return clone(assertState(JSON.parse(await readFile(resolve(this.path), 'utf8')) as unknown));
  }

  public async update<T>(mutate: (state: ReferenceState) => T | Promise<T>): Promise<T> {
    let release: () => void = () => undefined;
    const prior = this.queue;
    this.queue = new Promise<void>((resolveQueue) => {
      release = resolveQueue;
    });
    await prior;
    try {
      const state = await this.read();
      const result = await mutate(state);
      await this.writeState(state);
      return result;
    } finally {
      release();
    }
  }

  private async writeState(state: ReferenceState): Promise<void> {
    const absolute = resolve(this.path);
    const temporary = `${absolute}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`;
    const handle = await open(temporary, 'wx', 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(state, null, 2)}\n`, 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, absolute);
    await chmod(absolute, 0o600);
    const directory = await open(dirname(absolute), 'r');
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }

  private async initializeOnce(): Promise<void> {
    const absolute = resolve(this.path);
    await mkdir(dirname(absolute), { recursive: true, mode: 0o700 });
    try {
      await readFile(absolute);
      await chmod(absolute, 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      await this.writeState(initialState());
    }
  }
}

export class FileRemoteTriggerPublisher implements RemoteTriggerPublisher {
  public constructor(
    private readonly store: JsonFileReferenceStore,
    private readonly teamIntegrationSimplyId: string,
  ) {
    assertSimplyId(teamIntegrationSimplyId, 'teamIntegrationSimplyId');
  }

  public async publishCreateRecordFromMessage(
    input: CreateRecordFromMessageInput,
    idempotencyKey: string,
  ): Promise<void> {
    const parsed = parseCreateRecordFromMessageInput(input);
    const requestFingerprint = createHash('sha256')
      .update(JSON.stringify(parsed))
      .digest('hex');
    const coordinate = createHash('sha256')
      .update(`${this.teamIntegrationSimplyId}\n${idempotencyKey}`)
      .digest('hex');
    await this.store.update((state) => {
      const installation = state.installations[this.teamIntegrationSimplyId];
      if (!installation || installation.status !== 'ACTIVE') {
        throw new Error('installation is not active');
      }
      const existing = state.remoteTriggers[coordinate];
      if (existing) {
        if (existing.requestFingerprint !== requestFingerprint) {
          throw new IdempotencyConflictError();
        }
        return;
      }
      state.remoteTriggers[coordinate] = {
        teamIntegrationSimplyId: this.teamIntegrationSimplyId,
        requestFingerprint,
        input: parsed,
      };
    });
  }
}

const idempotencyCoordinate = (namespace: string, key: string): string =>
  `${namespace}:${createHash('sha256').update(key).digest('hex')}`;

export class FileIdempotencyStore<T> implements IdempotencyStore<T> {
  private readonly pending = new Map<
    string,
    {
      readonly requestFingerprint: string;
      readonly value: Promise<{ readonly replayed: boolean; readonly value: T }>;
    }
  >();

  public constructor(
    private readonly store: JsonFileReferenceStore,
    private readonly namespace: string,
  ) {
    if (!/^[a-z][a-z0-9-]{0,63}$/u.test(namespace)) {
      throw new Error('idempotency namespace must be lowercase kebab-case');
    }
  }

  public async run(
    key: string,
    requestFingerprint: string,
    operation: () => Promise<T>,
  ): Promise<{ readonly replayed: boolean; readonly value: T }> {
    if (!/^[a-f0-9]{64}$/u.test(requestFingerprint)) {
      throw new Error('requestFingerprint must be a lowercase SHA-256 digest');
    }
    const coordinate = idempotencyCoordinate(this.namespace, key);
    const inFlight = this.pending.get(coordinate);
    if (inFlight) {
      if (inFlight.requestFingerprint !== requestFingerprint) throw new IdempotencyConflictError();
      return { replayed: true, value: (await inFlight.value).value };
    }

    const value = this.execute(coordinate, requestFingerprint, operation);
    const pending = { requestFingerprint, value };
    this.pending.set(coordinate, pending);
    try {
      return await value;
    } finally {
      if (this.pending.get(coordinate) === pending) this.pending.delete(coordinate);
    }
  }

  private async execute(
    coordinate: string,
    requestFingerprint: string,
    operation: () => Promise<T>,
  ): Promise<{ readonly replayed: boolean; readonly value: T }> {
    const persisted = (await this.store.read()).idempotency[coordinate];
    if (persisted) {
      if (persisted.requestFingerprint !== requestFingerprint) {
        throw new IdempotencyConflictError();
      }
      return { replayed: true, value: clone(persisted.value as T) };
    }
    const resolved = await operation();
    await this.store.update((state) => {
      const existing = state.idempotency[coordinate];
      if (existing && existing.requestFingerprint !== requestFingerprint) {
        throw new IdempotencyConflictError();
      }
      state.idempotency[coordinate] = {
        requestFingerprint,
        value: clone(resolved),
      };
    });
    return { replayed: false, value: resolved };
  }
}

const assertSimplyId = (value: string, label: string): void => {
  if (!SIMPLY_ID_PATTERN.test(value)) throw new Error(`${label} must be a canonical Simply ID`);
};

const assertSlackTeamId = (value: string): void => {
  if (!/^[ET][A-Z0-9]{8,20}$/u.test(value)) throw new Error('expectedSlackTeamId is invalid');
};

const assertSlackChannelId = (value: string): void => {
  if (!/^[CG][A-Z0-9]{8,20}$/u.test(value)) throw new Error('eventChannel is invalid');
};

const assertPackageKey = (value: string): void => {
  if (!/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u.test(value)) throw new Error('packageKey is invalid');
};

const sharedBlueprintCoordinate = (teamSimplyId: string, packageKey: string): string =>
  createHash('sha256').update(`${teamSimplyId}\n${packageKey}`).digest('hex');

const sharedBlueprintSimplyId = (coordinate: string): string =>
  `TBPL-${coordinate.slice(0, 4).toUpperCase()}-${coordinate.slice(4, 8).toUpperCase()}`;

export class ReferenceInstallationState {
  public constructor(private readonly store: JsonFileReferenceStore) {}

  public async create(input: {
    readonly teamIntegrationSimplyId: string;
    readonly teamSimplyId: string;
    readonly expectedSlackTeamId: string;
    readonly eventChannel: string;
  }): Promise<PersistedReferenceInstallation> {
    assertSimplyId(input.teamIntegrationSimplyId, 'teamIntegrationSimplyId');
    assertSimplyId(input.teamSimplyId, 'teamSimplyId');
    assertSlackTeamId(input.expectedSlackTeamId);
    assertSlackChannelId(input.eventChannel);
    return this.store.update((state) => {
      const existing = state.installations[input.teamIntegrationSimplyId];
      if (existing) {
        if (
          existing.teamSimplyId !== input.teamSimplyId ||
          existing.expectedSlackTeamId !== input.expectedSlackTeamId ||
          existing.eventChannel !== input.eventChannel
        ) {
          throw new Error('installation Simply ID is already bound to different authority');
        }
        return clone(existing);
      }
      const installation: PersistedReferenceInstallation = {
        ...input,
        status: 'PENDING_SETUP',
        userLinks: {},
        blueprintPackageKeys: [],
      };
      state.installations[input.teamIntegrationSimplyId] = installation;
      return clone(installation);
    });
  }

  public async get(teamIntegrationSimplyId: string): Promise<PersistedReferenceInstallation> {
    assertSimplyId(teamIntegrationSimplyId, 'teamIntegrationSimplyId');
    const installation = (await this.store.read()).installations[teamIntegrationSimplyId];
    if (!installation) throw new Error('unknown installation');
    return clone(installation);
  }

  public async requireActive(
    teamIntegrationSimplyId: string,
  ): Promise<PersistedReferenceInstallation> {
    const installation = await this.get(teamIntegrationSimplyId);
    if (installation.status !== 'ACTIVE') throw new Error('installation is not active');
    if (!installation.slackCredential || !installation.simply360Credential) {
      throw new Error('active installation is missing credentials');
    }
    return installation;
  }

  public async beginOAuth(
    teamIntegrationSimplyId: string,
    provider: 'simply360' | 'slack',
    attempt: PersistedOAuthAttempt,
  ): Promise<void> {
    if (!attempt.state) throw new Error('OAuth state is required');
    await this.store.update((state) => {
      const installation = this.mutableInstallation(state, teamIntegrationSimplyId);
      if (installation.status === 'UNINSTALLED' || installation.status === 'UNINSTALLING') {
        throw new Error('installation is terminal');
      }
      if (provider === 'simply360') installation.simply360OAuth = clone(attempt);
      else installation.slackOAuth = clone(attempt);
    });
  }

  public async consumeOAuth(
    teamIntegrationSimplyId: string,
    provider: 'simply360' | 'slack',
    stateValue: string,
  ): Promise<PersistedOAuthAttempt> {
    return this.store.update((state) => {
      const installation = this.mutableInstallation(state, teamIntegrationSimplyId);
      const attempt =
        provider === 'simply360' ? installation.simply360OAuth : installation.slackOAuth;
      if (!attempt) throw new Error(`${provider} OAuth state mismatch`);
      if (!secretsMatch(attempt.state, stateValue)) {
        throw new Error(`${provider} OAuth state mismatch`);
      }
      if (provider === 'simply360') delete installation.simply360OAuth;
      else delete installation.slackOAuth;
      return clone(attempt);
    });
  }

  public async getOAuth(
    teamIntegrationSimplyId: string,
    provider: 'simply360' | 'slack',
  ): Promise<PersistedOAuthAttempt> {
    const installation = await this.get(teamIntegrationSimplyId);
    const attempt =
      provider === 'simply360' ? installation.simply360OAuth : installation.slackOAuth;
    if (!attempt) throw new Error(`${provider} OAuth attempt is missing`);
    return clone(attempt);
  }

  public async installationForOAuthState(
    provider: 'simply360' | 'slack',
    stateValue: string,
  ): Promise<PersistedReferenceInstallation> {
    if (!stateValue) throw new Error(`${provider} OAuth state is required`);
    const matches = Object.values((await this.store.read()).installations).filter(
      (installation) => {
        if (
          installation.status !== 'PENDING_SETUP' &&
          installation.status !== 'ACTIVE'
        ) {
          return false;
        }
        const attempt =
          provider === 'simply360'
            ? installation.simply360OAuth
            : installation.slackOAuth;
        return attempt ? secretsMatch(attempt.state, stateValue) : false;
      },
    );
    if (matches.length !== 1) {
      throw new Error(
        matches.length === 0
          ? `${provider} OAuth state is unknown`
          : `${provider} OAuth state is ambiguously bound`,
      );
    }
    return clone(matches[0] as PersistedReferenceInstallation);
  }

  public async bindSimply360Credential(
    teamIntegrationSimplyId: string,
    credential: OAuthTokenSet,
  ): Promise<void> {
    await this.store.update((state) => {
      const installation = this.mutablePendingOrActiveInstallation(state, teamIntegrationSimplyId);
      installation.simply360Credential = clone(credential);
    });
  }

  public async bindSlackCredential(
    teamIntegrationSimplyId: string,
    credential: SlackOAuthGrant,
  ): Promise<void> {
    await this.store.update((state) => {
      const installation = this.mutablePendingOrActiveInstallation(state, teamIntegrationSimplyId);
      if (credential.teamId !== installation.expectedSlackTeamId) {
        throw new Error('Slack grant does not belong to the installation workspace');
      }
      installation.slackCredential = clone(credential);
    });
  }

  public async activate(teamIntegrationSimplyId: string): Promise<void> {
    await this.store.update((state) => {
      const installation = this.mutableInstallation(state, teamIntegrationSimplyId);
      if (installation.status === 'ACTIVE') {
        if (!installation.slackCredential || !installation.simply360Credential) {
          throw new Error('active installation is missing credentials');
        }
        return;
      }
      if (installation.status !== 'PENDING_SETUP') {
        throw new Error('installation is not pending setup');
      }
      if (!installation.slackCredential || !installation.simply360Credential) {
        throw new Error('setup requires both Simply360 and Slack credentials');
      }
      installation.status = 'ACTIVE';
    });
  }

  public async linkUser(
    teamIntegrationSimplyId: string,
    userSimplyId: string,
  ): Promise<{ readonly linkSimplyId: string; readonly replayed: boolean }> {
    assertSimplyId(userSimplyId, 'userSimplyId');
    return this.store.update((state) => {
      const installation = this.mutableActiveInstallation(state, teamIntegrationSimplyId);
      const active = Object.values(installation.userLinks).find(
        (link) => link.userSimplyId === userSimplyId && link.active,
      );
      if (active) return { linkSimplyId: active.linkSimplyId, replayed: true };
      state.nextUserLinkSequence += 1;
      const sequence = state.nextUserLinkSequence.toString(36).toUpperCase().padStart(8, '0');
      const linkSimplyId = `ULNK-${sequence.slice(0, 4)}-${sequence.slice(4, 8)}`;
      installation.userLinks[linkSimplyId] = {
        linkSimplyId,
        userSimplyId,
        active: true,
      };
      return { linkSimplyId, replayed: false };
    });
  }

  public async revokeUserLink(
    teamIntegrationSimplyId: string,
    linkSimplyId: string,
  ): Promise<void> {
    assertSimplyId(linkSimplyId, 'linkSimplyId');
    await this.store.update((state) => {
      const installation = this.mutableActiveInstallation(state, teamIntegrationSimplyId);
      const link = installation.userLinks[linkSimplyId];
      if (!link) throw new Error('user link does not belong to the installation');
      link.active = false;
    });
  }

  public async installSharedBlueprint(
    teamIntegrationSimplyId: string,
    packageKey: string,
  ): Promise<string> {
    assertPackageKey(packageKey);
    return this.store.update((state) => {
      const installation = this.mutableActiveInstallation(state, teamIntegrationSimplyId);
      const coordinate = sharedBlueprintCoordinate(installation.teamSimplyId, packageKey);
      const existing = state.sharedBlueprints[coordinate];
      if (existing) {
        if (
          existing.teamSimplyId !== installation.teamSimplyId ||
          existing.packageKey !== packageKey
        ) {
          throw new Error('shared Blueprint coordinate collision');
        }
        if (!existing.installationSimplyIds.includes(teamIntegrationSimplyId)) {
          existing.installationSimplyIds.push(teamIntegrationSimplyId);
          existing.installationSimplyIds.sort();
        }
      } else {
        state.sharedBlueprints[coordinate] = {
          teamBlueprintSimplyId: sharedBlueprintSimplyId(coordinate),
          teamSimplyId: installation.teamSimplyId,
          packageKey,
          installationSimplyIds: [teamIntegrationSimplyId],
        };
      }
      if (!installation.blueprintPackageKeys.includes(packageKey)) {
        installation.blueprintPackageKeys.push(packageKey);
        installation.blueprintPackageKeys.sort();
      }
      return state.sharedBlueprints[coordinate]?.teamBlueprintSimplyId as string;
    });
  }

  public async activeInstallationsForSlackTeam(
    slackTeamId: string,
  ): Promise<PersistedReferenceInstallation[]> {
    assertSlackTeamId(slackTeamId);
    return Object.values((await this.store.read()).installations)
      .filter(
        (installation) =>
          installation.status === 'ACTIVE' &&
          installation.expectedSlackTeamId === slackTeamId &&
          installation.slackCredential?.teamId === slackTeamId,
      )
      .map(clone);
  }

  public async beginUninstall(
    teamIntegrationSimplyId: string,
  ): Promise<PersistedReferenceInstallation> {
    return this.store.update((state) => {
      const installation = this.mutableInstallation(state, teamIntegrationSimplyId);
      if (installation.status === 'UNINSTALLED') return clone(installation);
      installation.status = 'UNINSTALLING';
      return clone(installation);
    });
  }

  public async completeUninstall(
    teamIntegrationSimplyId: string,
    slackRevocationOutcome: 'NOT_REQUIRED' | 'SUCCEEDED' | 'FAILED',
  ): Promise<void> {
    await this.store.update((state) => {
      const installation = this.mutableInstallation(state, teamIntegrationSimplyId);
      if (installation.status !== 'UNINSTALLING' && installation.status !== 'UNINSTALLED') {
        throw new Error('uninstall must be fenced before completion');
      }
      installation.status = 'UNINSTALLED';
      installation.slackRevocationOutcome = slackRevocationOutcome;
      delete installation.slackCredential;
      delete installation.simply360Credential;
      delete installation.slackOAuth;
      delete installation.simply360OAuth;
      for (const link of Object.values(installation.userLinks)) link.active = false;
      for (const packageKey of installation.blueprintPackageKeys) {
        const coordinate = sharedBlueprintCoordinate(installation.teamSimplyId, packageKey);
        const blueprint = state.sharedBlueprints[coordinate];
        if (blueprint) {
          blueprint.installationSimplyIds = blueprint.installationSimplyIds.filter(
            (simplyId) => simplyId !== teamIntegrationSimplyId,
          );
        }
      }
      installation.blueprintPackageKeys.splice(0);
      for (const [coordinate, trigger] of Object.entries(
        state.remoteTriggers,
      )) {
        if (trigger.teamIntegrationSimplyId === teamIntegrationSimplyId) {
          delete state.remoteTriggers[coordinate];
        }
      }
      const idempotencyPrefixes = [
        'event',
        'action',
        'trigger',
      ].map(
        (kind) =>
          `${kind}-${teamIntegrationSimplyId.toLowerCase()}:`,
      );
      for (const coordinate of Object.keys(state.idempotency)) {
        if (idempotencyPrefixes.some((prefix) => coordinate.startsWith(prefix))) {
          delete state.idempotency[coordinate];
        }
      }
    });
  }

  private mutableInstallation(
    state: ReferenceState,
    teamIntegrationSimplyId: string,
  ): PersistedReferenceInstallation {
    assertSimplyId(teamIntegrationSimplyId, 'teamIntegrationSimplyId');
    const installation = state.installations[teamIntegrationSimplyId];
    if (!installation) throw new Error('unknown installation');
    return installation;
  }

  private mutablePendingInstallation(
    state: ReferenceState,
    teamIntegrationSimplyId: string,
  ): PersistedReferenceInstallation {
    const installation = this.mutableInstallation(state, teamIntegrationSimplyId);
    if (installation.status !== 'PENDING_SETUP') throw new Error('installation is not pending setup');
    return installation;
  }

  private mutablePendingOrActiveInstallation(
    state: ReferenceState,
    teamIntegrationSimplyId: string,
  ): PersistedReferenceInstallation {
    const installation = this.mutableInstallation(state, teamIntegrationSimplyId);
    if (installation.status !== 'PENDING_SETUP' && installation.status !== 'ACTIVE') {
      throw new Error('installation is terminal');
    }
    return installation;
  }

  private mutableActiveInstallation(
    state: ReferenceState,
    teamIntegrationSimplyId: string,
  ): PersistedReferenceInstallation {
    const installation = this.mutableInstallation(state, teamIntegrationSimplyId);
    if (installation.status !== 'ACTIVE') throw new Error('installation is not active');
    return installation;
  }
}
