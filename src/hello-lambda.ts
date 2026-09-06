import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import {
  AppPlatformLifecycleEventTypeSchema,
  AppPlatformSubscriptionEventTypeSchema,
} from '@simply360/integration-sdk';
import { z } from 'zod';

import { assertSimplyId } from './contracts.js';
import { HelloOAuthClient, createHardenedHelloOAuthFetch, type HelloOAuthConfiguration } from './hello-oauth.js';
import { HelloHostedRouter, type HelloHostedRequest, type HelloWebhookKeyBinding } from './hello-router.js';
import { createHelloStateStore } from './hello-state.js';

interface ApiGatewayV2Event {
  readonly rawPath?: string;
  readonly rawQueryString?: string;
  readonly headers?: Readonly<Record<string, string | undefined>>;
  readonly cookies?: readonly string[];
  readonly requestContext?: { readonly http?: { readonly method?: string } };
  readonly body?: string | null;
  readonly isBase64Encoded?: boolean;
}

interface ApiGatewayV2Result {
  readonly statusCode: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  readonly isBase64Encoded: false;
}

const PublicSimplyIdSchema = z.string().regex(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/u);
const WebhookKeySchema = z.object({
  kid: z.string().regex(/^whk_[A-Za-z0-9_-]{24}$/u),
  secret: z.string().regex(/^[A-Za-z0-9_-]{43}$/u),
}).strict();
const RuntimeSecretSchema = z.object({
  helloStateEncryptionKeyCurrent: z.string().min(1),
  helloStateEncryptionKeyPrevious: z.string().min(1).optional(),
  simply360WebhookKeyBindings: z.array(z.object({
    teamSimplyId: PublicSimplyIdSchema,
    teamIntegrationSimplyId: PublicSimplyIdSchema,
    current: WebhookKeySchema,
    previous: WebhookKeySchema.extend({ validUntil: z.string().datetime({ offset: true }) }).optional(),
  }).strict()).max(8),
}).passthrough();

type RuntimeSecret = z.infer<typeof RuntimeSecretSchema>;
const MAX_WEBHOOK_PREVIOUS_KEY_OVERLAP_MS = 7 * 24 * 60 * 60 * 1_000;

/** Parse one runtime-secret snapshot without projecting secret material. */
export const resolveHelloWebhookKeyBinding = (
  secretString: string,
  kid: string,
  now: number,
): HelloWebhookKeyBinding | null => {
  if (Buffer.byteLength(secretString) > 64 * 1024) throw new Error('runtime secret is unavailable');
  let untrusted: unknown;
  try {
    untrusted = JSON.parse(secretString) as unknown;
  } catch {
    throw new Error('runtime secret is unavailable');
  }
  const secret = RuntimeSecretSchema.parse(untrusted) as RuntimeSecret;
  const allKids = secret.simply360WebhookKeyBindings.flatMap((entry) => [entry.current.kid, ...(entry.previous ? [entry.previous.kid] : [])]);
  if (new Set(allKids).size !== allKids.length) throw new Error('webhook key ids must be globally unique');
  const installationSimplyIds = secret.simply360WebhookKeyBindings.map((entry) => entry.teamIntegrationSimplyId);
  if (new Set(installationSimplyIds).size !== installationSimplyIds.length) {
    throw new Error('webhook installation bindings must be unique');
  }
  if (secret.simply360WebhookKeyBindings.some((entry) =>
    entry.previous && Date.parse(entry.previous.validUntil) > now + MAX_WEBHOOK_PREVIOUS_KEY_OVERLAP_MS
  )) {
    throw new Error('webhook previous-key overlap exceeds seven days');
  }
  const candidates = secret.simply360WebhookKeyBindings.filter((entry) =>
    entry.current.kid === kid || (entry.previous?.kid === kid && Date.parse(entry.previous.validUntil) > now),
  );
  if (candidates.length !== 1) return null;
  const candidate = candidates[0]!;
  assertSimplyId(candidate.teamSimplyId, 'teamSimplyId');
  assertSimplyId(candidate.teamIntegrationSimplyId, 'teamIntegrationSimplyId');
  return {
    teamSimplyId: candidate.teamSimplyId,
    teamIntegrationSimplyId: candidate.teamIntegrationSimplyId,
    keys: [
      candidate.current,
      ...(candidate.previous && Date.parse(candidate.previous.validUntil) > now
        ? [{ kid: candidate.previous.kid, secret: candidate.previous.secret }]
        : []),
    ],
  };
};

export interface HelloLambdaEnvironment {
  readonly AWS_REGION?: string;
  readonly HELLO_STATE_TABLE_NAME?: string;
  readonly HELLO_RUNTIME_SECRET_ID?: string;
  readonly S360_AUTHORIZATION_ENDPOINT?: string;
  readonly S360_TOKEN_ENDPOINT?: string;
  readonly S360_CLIENT_ID?: string;
  readonly S360_REDIRECT_URI?: string;
  readonly S360_INTEGRATION_PUBLISHER_SIMPLY_ID?: string;
  readonly S360_INTEGRATION_APP_SIMPLY_ID?: string;
  readonly S360_INTEGRATION_APP_VERSION_SIMPLY_ID?: string;
  readonly S360_INTEGRATION_APP_RELEASE_SIMPLY_ID?: string;
  readonly S360_INTEGRATION_APP_OAUTH_CLIENT_SIMPLY_ID?: string;
  readonly S360_OAUTH_SCOPES?: string;
  readonly S360_EVENT_TYPES?: string;
  readonly S360_LIFECYCLE_EVENT_TYPES?: string;
}

const required = (environment: HelloLambdaEnvironment, key: keyof HelloLambdaEnvironment): string => {
  const value = environment[key];
  if (!value || value.trim() !== value || value.length > 1_024) throw new Error(`${key} is missing or invalid`);
  return value;
};

const exactList = (raw: string, label: string): string[] => {
  const values = raw.split(',');
  if (values.length === 0 || values.length > 30 || values.some((value) => !value || value.trim() !== value)) {
    throw new Error(`${label} is invalid`);
  }
  if (new Set(values).size !== values.length) throw new Error(`${label} contains duplicates`);
  return values;
};

const eventTypes = (raw: string) => exactList(raw, 'S360_EVENT_TYPES').map((value) => AppPlatformSubscriptionEventTypeSchema.parse(value));
const lifecycleEventTypes = (raw: string) =>
  exactList(raw, 'S360_LIFECYCLE_EVENT_TYPES').map((value) => AppPlatformLifecycleEventTypeSchema.parse(value));

const oauthConfiguration = (environment: HelloLambdaEnvironment): HelloOAuthConfiguration => ({
  authorizationEndpoint: required(environment, 'S360_AUTHORIZATION_ENDPOINT'),
  tokenEndpoint: required(environment, 'S360_TOKEN_ENDPOINT'),
  clientId: required(environment, 'S360_CLIENT_ID'),
  redirectUri: required(environment, 'S360_REDIRECT_URI'),
  allowedRedirectUris: [required(environment, 'S360_REDIRECT_URI')],
  environment: 'dev',
  integrationPublisherSimplyId: required(environment, 'S360_INTEGRATION_PUBLISHER_SIMPLY_ID'),
  integrationAppSimplyId: required(environment, 'S360_INTEGRATION_APP_SIMPLY_ID'),
  integrationAppVersionSimplyId: required(environment, 'S360_INTEGRATION_APP_VERSION_SIMPLY_ID'),
  integrationAppReleaseSimplyId: required(environment, 'S360_INTEGRATION_APP_RELEASE_SIMPLY_ID'),
  integrationAppOAuthClientSimplyId: required(environment, 'S360_INTEGRATION_APP_OAUTH_CLIENT_SIMPLY_ID'),
  scopes: exactList(required(environment, 'S360_OAUTH_SCOPES'), 'S360_OAUTH_SCOPES') as HelloOAuthConfiguration['scopes'],
});

const requestFromEvent = (event: ApiGatewayV2Event): HelloHostedRequest => {
  const method = event.requestContext?.http?.method;
  const path = event.rawPath;
  if (!method || !path) throw new Error('API Gateway request context is incomplete');
  const headers: Record<string, string | undefined> = Object.create(null) as Record<string, string | undefined>;
  for (const [key, value] of Object.entries(event.headers ?? {})) {
    const normalized = key.toLowerCase();
    if (Object.hasOwn(headers, normalized)) throw new Error('duplicate normalized header');
    headers[normalized] = value;
  }
  if (event.cookies && event.cookies.length > 0) {
    if (Object.hasOwn(headers, 'cookie')) throw new Error('duplicate cookie input');
    headers.cookie = event.cookies.join('; ');
  }
  const queryParameters = new URLSearchParams(event.rawQueryString ?? '');
  const query: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const [key, value] of queryParameters) {
    if (Object.hasOwn(query, key)) throw new Error('duplicate query parameter');
    query[key] = value;
  }
  const body = event.body
    ? Buffer.from(event.body, event.isBase64Encoded === true ? 'base64' : 'utf8')
    : Buffer.alloc(0);
  return { method: method.toUpperCase(), path, query, headers, body };
};

class RuntimeSecretLoader {
  public constructor(
    private readonly secretId: string,
    private readonly secrets: SecretsManagerClient,
    private readonly now: () => number,
  ) {}

  public async resolveWebhookKey(kid: string): Promise<HelloWebhookKeyBinding | null> {
    const response = await this.secrets.send(new GetSecretValueCommand({ SecretId: this.secretId }));
    if (response.SecretString === undefined || response.SecretBinary !== undefined) {
      throw new Error('runtime secret is unavailable');
    }
    return resolveHelloWebhookKeyBinding(response.SecretString, kid, this.now());
  }
}

export const adaptHelloRouterToApiGateway = (router: HelloHostedRouter) =>
  async (event: ApiGatewayV2Event): Promise<ApiGatewayV2Result> => {
    const response = await router.handle(requestFromEvent(event));
    return { ...response, isBase64Encoded: false };
  };

export const createHelloLambdaHandler = (input: {
  readonly environment?: HelloLambdaEnvironment;
  readonly secrets?: SecretsManagerClient;
  readonly now?: () => number;
  readonly fetchImpl?: typeof fetch;
} = {}) => {
  const environment = input.environment ?? process.env;
  const region = required(environment, 'AWS_REGION');
  const tableName = required(environment, 'HELLO_STATE_TABLE_NAME');
  const secretId = required(environment, 'HELLO_RUNTIME_SECRET_ID');
  const now = input.now ?? Date.now;
  const secrets = input.secrets ?? new SecretsManagerClient({ region });
  const state = createHelloStateStore({ tableName, runtimeSecretId: secretId, region });
  const oauth = new HelloOAuthClient({
    configuration: oauthConfiguration(environment),
    store: state,
    fetchImpl: createHardenedHelloOAuthFetch(input.fetchImpl),
    now,
  });
  const secretLoader = new RuntimeSecretLoader(secretId, secrets, now);
  const router = new HelloHostedRouter({
    oauth,
    state,
    resolveWebhookKey: (kid) => secretLoader.resolveWebhookKey(kid),
    eventTypes: eventTypes(required(environment, 'S360_EVENT_TYPES')),
    lifecycleEventTypes: lifecycleEventTypes(required(environment, 'S360_LIFECYCLE_EVENT_TYPES')),
    now,
  });
  return adaptHelloRouterToApiGateway(router);
};

let cachedHandler: ReturnType<typeof createHelloLambdaHandler> | undefined;
export const handler = async (event: ApiGatewayV2Event): Promise<ApiGatewayV2Result> => {
  cachedHandler ??= createHelloLambdaHandler();
  return cachedHandler(event);
};
