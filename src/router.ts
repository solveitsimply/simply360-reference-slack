import {
  SLACK_LIFECYCLE_EVENT_TYPES,
  parseEventOccurrence,
  type EventOccurrence,
  type OAuthScope,
  type RemoteTriggerPublisher,
} from './contracts.js';
import { Simply360OAuthClient } from './oauth.js';
import {
  IdempotencyConflictError,
  SlackReferenceRuntime,
} from './runtime.js';
import type { SlackClient } from './slack.js';
import { SlackOAuthClient } from './slack-oauth.js';
import {
  FileIdempotencyStore,
  JsonFileReferenceStore,
  ReferenceInstallationState,
  type PersistedReferenceInstallation,
} from './state.js';
import {
  verifyWebhookV2,
  type WebhookSigningKey,
} from './webhook-v2.js';

const INSTALLATION_HEADER = 'X-S360-Team-Integration-Id';
const MAXIMUM_REQUEST_BYTES = 512 * 1024;
const DEFAULT_SCOPES: readonly OAuthScope[] = [
  'schema:read',
  'records:read',
  'records:write',
  'offline_access',
];
const OAUTH_SCOPES = new Set<OAuthScope>(DEFAULT_SCOPES);

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const json = (status: number, value: unknown): Response =>
  new Response(`${JSON.stringify(value)}\n`, {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });

const readJson = async (request: Request): Promise<Record<string, unknown>> => {
  const mediaType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (mediaType !== 'application/json') throw new Error('request content type must be application/json');
  const text = await request.text();
  if (Buffer.byteLength(text) > MAXIMUM_REQUEST_BYTES) throw new Error('request exceeds the byte limit');
  const parsed = JSON.parse(text) as unknown;
  if (!isPlainRecord(parsed)) throw new Error('request body must be a plain JSON object');
  return parsed;
};

const requiredString = (
  value: Record<string, unknown>,
  key: string,
): string => {
  const result = value[key];
  if (typeof result !== 'string' || result.length === 0) {
    throw new Error(`${key} is required`);
  }
  return result;
};

const requiredInstallationHeader = (request: Request): string => {
  const value = request.headers.get(INSTALLATION_HEADER);
  if (!value) throw new Error(`${INSTALLATION_HEADER} is required`);
  return value;
};

const requestedOAuthScopes = (input: unknown): readonly OAuthScope[] => {
  if (input === undefined) return DEFAULT_SCOPES;
  if (
    !Array.isArray(input) ||
    input.length < 1 ||
    new Set(input).size !== input.length ||
    input.some(
      (scope) => typeof scope !== 'string' || !OAUTH_SCOPES.has(scope as OAuthScope),
    )
  ) {
    throw new Error('scopes must be a unique nonempty array of supported OAuth scopes');
  }
  return input as OAuthScope[];
};

const occurrenceBody = async (
  request: Request,
): Promise<{ readonly rawBody: string; readonly occurrence: EventOccurrence }> => {
  const mediaType = request.headers
    .get('content-type')
    ?.split(';', 1)[0]
    ?.trim()
    .toLowerCase();
  if (mediaType !== 'application/json') {
    throw new Error('Simply360 webhook content type must be application/json');
  }
  const rawBody = await request.text();
  if (Buffer.byteLength(rawBody) > MAXIMUM_REQUEST_BYTES) {
    throw new Error('request exceeds the byte limit');
  }
  return {
    rawBody,
    occurrence: parseEventOccurrence(JSON.parse(rawBody) as unknown),
  };
};

const peekSlackTeamId = (rawBody: string): string => {
  if (Buffer.byteLength(rawBody) > 256 * 1024) throw new Error('Slack request exceeds the byte limit');
  const form = new URLSearchParams(rawBody);
  const payloads = form.getAll('payload');
  if (payloads.length !== 1 || [...form.keys()].some((key) => key !== 'payload')) {
    throw new Error('Slack request form is invalid');
  }
  const parsed = JSON.parse(payloads[0] as string) as unknown;
  if (!isPlainRecord(parsed) || !isPlainRecord(parsed.team) || typeof parsed.team.id !== 'string') {
    throw new Error('Slack request has no workspace identity');
  }
  return parsed.team.id;
};

export interface ReferenceRouterDependencies {
  readonly stateFile: string;
  readonly store?: JsonFileReferenceStore;
  readonly simply360OAuth: Simply360OAuthClient;
  readonly slackOAuthForInstallation: (
    installation: PersistedReferenceInstallation,
  ) => SlackOAuthClient;
  readonly slackClientForInstallation: (
    installation: PersistedReferenceInstallation,
  ) => SlackClient;
  readonly triggerPublisherForInstallation: (
    installation: PersistedReferenceInstallation,
    store: JsonFileReferenceStore,
  ) => RemoteTriggerPublisher;
  readonly eventSigningKeysForInstallation: (
    installation: PersistedReferenceInstallation,
  ) => readonly WebhookSigningKey[];
  readonly slackSigningSecretsForWorkspace: (
    slackTeamId: string,
  ) => readonly string[];
}

export class SlackReferenceRouter {
  private readonly store: JsonFileReferenceStore;
  private readonly installations: ReferenceInstallationState;
  private readonly runtimes = new Map<
    string,
    { readonly slackAccessToken: string; readonly runtime: SlackReferenceRuntime }
  >();
  private readonly uninstalls = new Map<
    string,
    Promise<{
      readonly outcome: 'UNINSTALLED';
      readonly slackRevocationOutcome: 'NOT_REQUIRED' | 'SUCCEEDED' | 'FAILED';
    }>
  >();

  public constructor(private readonly dependencies: ReferenceRouterDependencies) {
    this.store = dependencies.store ?? new JsonFileReferenceStore(dependencies.stateFile);
    this.installations = new ReferenceInstallationState(this.store);
  }

  public async handle(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      if (request.method === 'GET' && path === '/health') {
        await this.store.read();
        return json(200, { status: 'ok' });
      }
      if (request.method === 'POST' && path === '/installations') {
        const body = await readJson(request);
        const installation = await this.installations.create({
          teamIntegrationSimplyId: requiredString(body, 'teamIntegrationSimplyId'),
          teamSimplyId: requiredString(body, 'teamSimplyId'),
          expectedSlackTeamId: requiredString(body, 'expectedSlackTeamId'),
          eventChannel: requiredString(body, 'eventChannel'),
        });
        return json(201, { installation: this.publicInstallation(installation) });
      }
      if (request.method === 'GET' && path === '/setup/status') {
        const teamIntegrationSimplyId = url.searchParams.get('teamIntegrationSimplyId');
        if (!teamIntegrationSimplyId) throw new Error('teamIntegrationSimplyId is required');
        const installation = await this.installations.get(teamIntegrationSimplyId);
        return json(200, { installation: this.publicInstallation(installation) });
      }
      if (request.method === 'GET' && path === '/setup') {
        const teamIntegrationSimplyId = url.searchParams.get(
          'teamIntegrationSimplyId',
        );
        if (!teamIntegrationSimplyId) {
          throw new Error('teamIntegrationSimplyId is required');
        }
        const installation = await this.installations.get(
          teamIntegrationSimplyId,
        );
        return json(200, {
          installation: this.publicInstallation(installation),
          setupReady:
            installation.simply360Credential !== undefined &&
            installation.slackCredential !== undefined,
        });
      }
      if (request.method === 'POST' && path === '/oauth/simply360/start') {
        const body = await readJson(request);
        const teamIntegrationSimplyId = requiredString(body, 'teamIntegrationSimplyId');
        const requestedScopes = requestedOAuthScopes(body.scopes);
        await this.installations.get(teamIntegrationSimplyId);
        const started = this.dependencies.simply360OAuth.start(requestedScopes);
        await this.installations.beginOAuth(teamIntegrationSimplyId, 'simply360', {
          state: started.state,
          codeVerifier: started.codeVerifier,
        });
        return json(200, { authorizationUrl: started.url, state: started.state });
      }
      if (request.method === 'POST' && path === '/oauth/simply360/callback') {
        const body = await readJson(request);
        return this.completeSimply360OAuth(
          requiredString(body, 'teamIntegrationSimplyId'),
          requiredString(body, 'state'),
          requiredString(body, 'code'),
        );
      }
      if (request.method === 'GET' && path === '/oauth/simply360/callback') {
        const state = url.searchParams.get('state') ?? '';
        const code = url.searchParams.get('code') ?? '';
        if (!state || !code) throw new Error('state and code are required');
        const installation =
          await this.installations.installationForOAuthState(
            'simply360',
            state,
          );
        return this.completeSimply360OAuth(
          installation.teamIntegrationSimplyId,
          state,
          code,
        );
      }
      if (request.method === 'POST' && path === '/oauth/simply360/refresh') {
        const body = await readJson(request);
        const teamIntegrationSimplyId = requiredString(body, 'teamIntegrationSimplyId');
        const installation = await this.installations.get(teamIntegrationSimplyId);
        const refreshToken = installation.simply360Credential?.refreshToken;
        if (!refreshToken) throw new Error('installation has no Simply360 refresh token');
        const credential = await this.dependencies.simply360OAuth.refresh(refreshToken);
        await this.installations.bindSimply360Credential(
          teamIntegrationSimplyId,
          credential,
        );
        return json(200, { outcome: 'SIMPLY360_REFRESHED', scope: credential.scope });
      }
      if (request.method === 'POST' && path === '/oauth/slack/start') {
        const body = await readJson(request);
        const teamIntegrationSimplyId = requiredString(body, 'teamIntegrationSimplyId');
        const installation = await this.installations.get(teamIntegrationSimplyId);
        const started = this.dependencies.slackOAuthForInstallation(installation).start();
        await this.installations.beginOAuth(teamIntegrationSimplyId, 'slack', {
          state: started.state,
        });
        return json(200, { authorizationUrl: started.url, state: started.state });
      }
      if (request.method === 'POST' && path === '/oauth/slack/callback') {
        const body = await readJson(request);
        return this.completeSlackOAuth(
          requiredString(body, 'teamIntegrationSimplyId'),
          requiredString(body, 'state'),
          requiredString(body, 'code'),
        );
      }
      if (request.method === 'GET' && path === '/oauth/slack/callback') {
        const state = url.searchParams.get('state') ?? '';
        const code = url.searchParams.get('code') ?? '';
        if (!state || !code) throw new Error('state and code are required');
        const installation =
          await this.installations.installationForOAuthState('slack', state);
        return this.completeSlackOAuth(
          installation.teamIntegrationSimplyId,
          state,
          code,
        );
      }
      if (request.method === 'POST' && path === '/oauth/slack/refresh') {
        const body = await readJson(request);
        const teamIntegrationSimplyId = requiredString(body, 'teamIntegrationSimplyId');
        const installation = await this.installations.get(teamIntegrationSimplyId);
        const refreshToken = installation.slackCredential?.refreshToken;
        if (!refreshToken) throw new Error('installation has no Slack refresh token');
        const credential = await this.dependencies
          .slackOAuthForInstallation(installation)
          .refresh(refreshToken);
        await this.installations.bindSlackCredential(
          teamIntegrationSimplyId,
          credential,
        );
        this.runtimes.delete(teamIntegrationSimplyId);
        return json(200, {
          outcome: 'SLACK_REFRESHED',
          slackTeamId: credential.teamId,
          scope: credential.scope,
        });
      }
      if (request.method === 'POST' && path === '/setup') {
        const body = await readJson(request);
        const teamIntegrationSimplyId = requiredString(body, 'teamIntegrationSimplyId');
        await this.installations.activate(teamIntegrationSimplyId);
        return json(200, { outcome: 'ACTIVE', teamIntegrationSimplyId });
      }
      if (request.method === 'POST' && path === '/account-links') {
        const body = await readJson(request);
        const result = await this.installations.linkUser(
          requiredString(body, 'teamIntegrationSimplyId'),
          requiredString(body, 'userSimplyId'),
        );
        return json(result.replayed ? 200 : 201, result);
      }
      if (request.method === 'DELETE' && path.startsWith('/account-links/')) {
        const linkSimplyId = decodeURIComponent(path.slice('/account-links/'.length));
        await this.installations.revokeUserLink(
          requiredInstallationHeader(request),
          linkSimplyId,
        );
        return json(200, { outcome: 'REVOKED', linkSimplyId });
      }
      if (request.method === 'POST' && path === '/blueprints/install') {
        const body = await readJson(request);
        const teamBlueprintSimplyId = await this.installations.installSharedBlueprint(
          requiredString(body, 'teamIntegrationSimplyId'),
          requiredString(body, 'packageKey'),
        );
        return json(200, { teamBlueprintSimplyId });
      }
      if (request.method === 'POST' && path === '/actions/send-to-channel') {
        const installation = await this.installations.requireActive(
          requiredInstallationHeader(request),
        );
        const body = await readJson(request);
        const result = await (
          await this.runtimeForInstallation(installation)
        ).sendToChannel(body.input, requiredString(body, 'idempotencyKey'));
        return json(200, result);
      }
      if (request.method === 'POST' && path === '/events/simply360') {
        const { rawBody, occurrence } = await occurrenceBody(request);
        const installation = await this.installations.requireActive(
          occurrence.teamIntegrationSimplyId,
        );
        const outcome = await (
          await this.runtimeForInstallation(installation)
        ).receiveEvent({
          rawBody,
          signatureHeader: request.headers.get('X-S360-Signature') ?? '',
          identityHeaders: {
            eventId: request.headers.get('X-Simply360-Event-Id') ?? undefined,
            deliveryId: request.headers.get('X-Simply360-Delivery-Id') ?? undefined,
            attemptId: request.headers.get('X-Simply360-Attempt-Id') ?? undefined,
            timestampUnixSeconds: this.optionalIntegerHeader(
              request,
              'X-Simply360-Timestamp',
            ),
          },
        });
        return json(200, { outcome });
      }
      if (request.method === 'POST' && path === '/events/slack') {
        const mediaType = request.headers
          .get('content-type')
          ?.split(';', 1)[0]
          ?.trim()
          .toLowerCase();
        if (mediaType !== 'application/x-www-form-urlencoded') {
          throw new Error(
            'Slack request content type must be application/x-www-form-urlencoded',
          );
        }
        const rawBody = await request.text();
        const slackTeamId = peekSlackTeamId(rawBody);
        const candidates =
          await this.installations.activeInstallationsForSlackTeam(slackTeamId);
        if (candidates.length !== 1) {
          throw new Error(
            candidates.length === 0
              ? 'no active installation is bound to this Slack workspace'
              : 'Slack workspace is ambiguously bound to multiple active installations',
          );
        }
        const installation = candidates[0] as PersistedReferenceInstallation;
        const outcome = await (
          await this.runtimeForInstallation(installation)
        ).receiveSlackRequest({
          rawBody,
          signature: request.headers.get('X-Slack-Signature') ?? '',
          timestamp: request.headers.get('X-Slack-Request-Timestamp') ?? '',
        });
        return json(200, outcome);
      }
      if (request.method === 'POST' && path === '/lifecycle') {
        const { rawBody, occurrence } = await occurrenceBody(request);
        if (
          !SLACK_LIFECYCLE_EVENT_TYPES.some(
            (eventType) => eventType === occurrence.eventType,
          ) ||
          occurrence.protocolVersion !== 1
        ) {
          throw new Error('lifecycle endpoint accepts declared protocol-v1 lifecycle events only');
        }
        const installation = await this.installations.get(
          occurrence.teamIntegrationSimplyId,
        );
        if (installation.teamSimplyId !== occurrence.teamSimplyId) {
          throw new Error('lifecycle event does not belong to this installation');
        }
        const verified = verifyWebhookV2({
          rawBody,
          signatureHeader: request.headers.get('X-S360-Signature') ?? '',
          keys: this.dependencies.eventSigningKeysForInstallation(installation),
        });
        if (!verified.ok || verified.delivery.eventId !== occurrence.eventSimplyId) {
          throw new Error(
            `Simply360 lifecycle webhook rejected: ${verified.ok ? 'EVENT_ID_MISMATCH' : verified.code}`,
          );
        }
        const lifecycleDedupe = new FileIdempotencyStore<Record<string, unknown>>(
          this.store,
          `lifecycle-${installation.teamIntegrationSimplyId.toLowerCase()}`,
        );
        const deduped = await lifecycleDedupe.run(
          `${verified.delivery.eventId}:${verified.delivery.deliveryId}`,
          verified.delivery.bodySha256Hex,
          async () => {
            if (occurrence.eventType === 'app.setup.completed') {
              await this.installations.activate(occurrence.teamIntegrationSimplyId);
              return { outcome: 'ACTIVE' };
            }
            if (occurrence.eventType === 'app.uninstalled') {
              return this.uninstall(occurrence.teamIntegrationSimplyId);
            }
            return { outcome: 'ACCEPTED' };
          },
        );
        const lifecycleResult = deduped.value;
        return json(
          lifecycleResult.slackRevocationOutcome === 'FAILED' ? 202 : 200,
          { ...lifecycleResult, replayed: deduped.replayed },
        );
      }
      if (request.method === 'DELETE' && path.startsWith('/installations/')) {
        const teamIntegrationSimplyId = decodeURIComponent(
          path.slice('/installations/'.length),
        );
        const result = await this.uninstall(teamIntegrationSimplyId);
        return json(result.slackRevocationOutcome === 'FAILED' ? 202 : 200, result);
      }
      return json(404, { error: 'NOT_FOUND' });
    } catch (error) {
      if (error instanceof IdempotencyConflictError) {
        return json(409, { error: 'IDEMPOTENCY_CONFLICT', message: error.message });
      }
      const message = error instanceof Error ? error.message : 'request failed';
      return json(400, { error: 'REQUEST_REJECTED', message });
    }
  }

  private async runtimeForInstallation(
    installation: PersistedReferenceInstallation,
  ): Promise<SlackReferenceRuntime> {
    const accessToken = installation.slackCredential?.accessToken;
    if (!accessToken) throw new Error('installation has no Slack credential');
    const existing = this.runtimes.get(installation.teamIntegrationSimplyId);
    if (existing?.slackAccessToken === accessToken) return existing.runtime;
    const runtime = new SlackReferenceRuntime(
      {
        teamSimplyId: installation.teamSimplyId,
        teamIntegrationSimplyId: installation.teamIntegrationSimplyId,
        slackTeamId: installation.expectedSlackTeamId,
        eventSigningKeys:
          this.dependencies.eventSigningKeysForInstallation(installation),
        slackSigningSecrets:
          this.dependencies.slackSigningSecretsForWorkspace(
            installation.expectedSlackTeamId,
          ),
        eventChannel: installation.eventChannel,
      },
      this.dependencies.slackClientForInstallation(installation),
      this.dependencies.triggerPublisherForInstallation(installation, this.store),
      new FileIdempotencyStore(
        this.store,
        `event-${installation.teamIntegrationSimplyId.toLowerCase()}`,
      ),
      new FileIdempotencyStore(
        this.store,
        `action-${installation.teamIntegrationSimplyId.toLowerCase()}`,
      ),
      new FileIdempotencyStore(
        this.store,
        `trigger-${installation.teamIntegrationSimplyId.toLowerCase()}`,
      ),
    );
    this.runtimes.set(installation.teamIntegrationSimplyId, {
      slackAccessToken: accessToken,
      runtime,
    });
    return runtime;
  }

  private async completeSimply360OAuth(
    teamIntegrationSimplyId: string,
    state: string,
    code: string,
  ): Promise<Response> {
    const attempt = await this.installations.consumeOAuth(
      teamIntegrationSimplyId,
      'simply360',
      state,
    );
    if (!attempt.codeVerifier) {
      throw new Error('Simply360 OAuth attempt has no PKCE verifier');
    }
    const credential = await this.dependencies.simply360OAuth.exchange(
      code,
      attempt.codeVerifier,
    );
    await this.installations.bindSimply360Credential(
      teamIntegrationSimplyId,
      credential,
    );
    return json(200, {
      outcome: 'SIMPLY360_CONNECTED',
      scope: credential.scope,
    });
  }

  private async completeSlackOAuth(
    teamIntegrationSimplyId: string,
    state: string,
    code: string,
  ): Promise<Response> {
    const installation = await this.installations.get(teamIntegrationSimplyId);
    const slackOAuth =
      this.dependencies.slackOAuthForInstallation(installation);
    const attempt = await this.installations.getOAuth(
      teamIntegrationSimplyId,
      'slack',
    );
    slackOAuth.verifyState(attempt.state, state);
    await this.installations.consumeOAuth(
      teamIntegrationSimplyId,
      'slack',
      state,
    );
    const credential = await slackOAuth.exchange(code);
    await this.installations.bindSlackCredential(
      teamIntegrationSimplyId,
      credential,
    );
    this.runtimes.delete(teamIntegrationSimplyId);
    return json(200, {
      outcome: 'SLACK_CONNECTED',
      slackTeamId: credential.teamId,
      scope: credential.scope,
    });
  }

  private async uninstall(
    teamIntegrationSimplyId: string,
  ): Promise<{
    readonly outcome: 'UNINSTALLED';
    readonly slackRevocationOutcome: 'NOT_REQUIRED' | 'SUCCEEDED' | 'FAILED';
  }> {
    const pending = this.uninstalls.get(teamIntegrationSimplyId);
    if (pending) return pending;
    const operation = this.performUninstall(teamIntegrationSimplyId);
    this.uninstalls.set(teamIntegrationSimplyId, operation);
    try {
      return await operation;
    } finally {
      if (this.uninstalls.get(teamIntegrationSimplyId) === operation) {
        this.uninstalls.delete(teamIntegrationSimplyId);
      }
    }
  }

  private async performUninstall(
    teamIntegrationSimplyId: string,
  ): Promise<{
    readonly outcome: 'UNINSTALLED';
    readonly slackRevocationOutcome: 'NOT_REQUIRED' | 'SUCCEEDED' | 'FAILED';
  }> {
    const before = await this.installations.beginUninstall(teamIntegrationSimplyId);
    if (before.status === 'UNINSTALLED') {
      return {
        outcome: 'UNINSTALLED',
        slackRevocationOutcome: before.slackRevocationOutcome ?? 'NOT_REQUIRED',
      };
    }
    let slackRevocationOutcome: 'NOT_REQUIRED' | 'SUCCEEDED' | 'FAILED' =
      'NOT_REQUIRED';
    if (before.slackCredential) {
      try {
        await this.dependencies
          .slackOAuthForInstallation(before)
          .revoke(before.slackCredential.accessToken);
        slackRevocationOutcome = 'SUCCEEDED';
      } catch {
        slackRevocationOutcome = 'FAILED';
      }
    }
    await this.installations.completeUninstall(
      teamIntegrationSimplyId,
      slackRevocationOutcome,
    );
    this.runtimes.delete(teamIntegrationSimplyId);
    return { outcome: 'UNINSTALLED', slackRevocationOutcome };
  }

  private publicInstallation(
    installation: PersistedReferenceInstallation,
  ): Record<string, unknown> {
    return {
      teamIntegrationSimplyId: installation.teamIntegrationSimplyId,
      teamSimplyId: installation.teamSimplyId,
      expectedSlackTeamId: installation.expectedSlackTeamId,
      eventChannel: installation.eventChannel,
      status: installation.status,
      simply360Connected: installation.simply360Credential !== undefined,
      slackConnected: installation.slackCredential !== undefined,
      activeUserLinkSimplyIds: Object.values(installation.userLinks)
        .filter((link) => link.active)
        .map((link) => link.linkSimplyId)
        .sort(),
      blueprintPackageKeys: [...installation.blueprintPackageKeys],
      slackRevocationOutcome: installation.slackRevocationOutcome ?? null,
    };
  }

  private optionalIntegerHeader(
    request: Request,
    name: string,
  ): number | undefined {
    const value = request.headers.get(name);
    if (value === null) return undefined;
    if (!/^(0|[1-9][0-9]{0,18})$/u.test(value) || !Number.isSafeInteger(Number(value))) {
      throw new Error(`${name} must be canonical integer Unix seconds`);
    }
    return Number(value);
  }
}
