import {
  buildAuthorizationRequestUrl,
  exchangeAuthorizationCode,
  generateOAuthState,
  generatePkcePair,
  isValidCodeVerifier,
  OAuthScopeSchema,
  refreshAccessToken,
  type FetchLike,
  type MarketplaceUserDelegatedAuthorizationIdentity,
  type OAuthScope,
  type OAuthTokenResponse,
} from '@simply360/integration-sdk/oauth';

import { assertSimplyId } from './contracts.js';
import { assertJsonResponse, readBoundedResponseText } from './http.js';
import {
  ConcurrentHelloStateUpdateError,
  type HelloGrantNamespace,
  type StoredHelloCredential,
} from './hello-state.js';

export const HELLO_OAUTH_AUDIENCE = 'urn:simply360:public-api' as const;
export const HELLO_OAUTH_RESOURCE = 'urn:simply360:team-api' as const;
const PENDING_OAUTH_LIFETIME_MS = 10 * 60 * 1_000;
const TOKEN_ENDPOINT_TIMEOUT_MS = 10_000;
const TOKEN_RESPONSE_MAX_BYTES = 64 * 1_024;

type PublicAuthorizationBinding = MarketplaceUserDelegatedAuthorizationIdentity;

export interface HelloOAuthStateStore {
  createPendingOAuthIntent<T extends Readonly<Record<string, unknown>>>(
    state: string,
    browserNonce: string,
    expiresAt: Date,
    value: T,
  ): Promise<void>;
  consumePendingOAuthIntent<T extends Readonly<Record<string, unknown>>>(
    state: string,
    browserNonce: string,
  ): Promise<T>;
  loadCredential<T extends Readonly<Record<string, unknown>>>(
    namespace: HelloGrantNamespace,
  ): Promise<StoredHelloCredential<T> | undefined>;
  saveCredential<T extends Readonly<Record<string, unknown>>>(
    namespace: HelloGrantNamespace,
    value: T,
    expectedRevision: number | null,
  ): Promise<StoredHelloCredential<T>>;
}

export interface HelloOAuthConfiguration {
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly allowedRedirectUris: readonly string[];
  readonly environment: 'dev';
  readonly integrationPublisherSimplyId: string;
  readonly integrationAppSimplyId: string;
  readonly integrationAppVersionSimplyId: string;
  readonly integrationAppReleaseSimplyId: string;
  readonly integrationAppOAuthClientSimplyId: string;
  /** Exact scopes declared by the reviewed NATIVE/NONE manifest client. */
  readonly scopes: readonly OAuthScope[];
}

type PendingHelloOAuthIntent = Readonly<Record<string, unknown>> & {
  readonly kind: 'SIMPLY360_NATIVE_OAUTH';
  readonly codeVerifier: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly audience: typeof HELLO_OAUTH_AUDIENCE;
  readonly resource: typeof HELLO_OAUTH_RESOURCE;
  readonly environment: 'dev';
  readonly integrationPublisherSimplyId: string;
  readonly integrationAppSimplyId: string;
  readonly integrationAppVersionSimplyId: string;
  readonly integrationAppReleaseSimplyId: string;
  readonly integrationAppOAuthClientSimplyId: string;
  readonly scopes: readonly OAuthScope[];
};

export type StoredHelloOAuthCredential = Readonly<Record<string, unknown>> & {
  readonly kind: 'SIMPLY360_NATIVE_OAUTH';
  readonly status: 'ACTIVE' | 'REFRESH_IN_PROGRESS';
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly tokenType: 'Bearer';
  readonly expiresAt?: string;
  readonly binding: PublicAuthorizationBinding;
};

export interface BeginHelloOAuthResult {
  readonly authorizationUrl: string;
  readonly state: string;
  /** Set this in a Secure, HttpOnly, SameSite=Lax callback cookie. */
  readonly browserNonce: string;
  readonly expiresAt: string;
}

export interface CompleteHelloOAuthResult {
  readonly binding: PublicAuthorizationBinding;
  readonly namespace: HelloGrantNamespace;
}

export type CompleteHelloOAuthInput =
  | {
      readonly state: string;
      readonly browserNonce: string;
      readonly code: string;
    }
  | {
      readonly state: string;
      readonly browserNonce: string;
      readonly error: string;
    };

export class HelloOAuthDeniedError extends Error {
  public constructor() {
    super('Simply360 authorization was denied');
    this.name = 'HelloOAuthDeniedError';
  }
}

export class HelloOAuthCompletionUnknownError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'HelloOAuthCompletionUnknownError';
  }
}

export class HelloOAuthRefreshUnavailableError extends Error {
  public constructor(message = 'the exact Simply360 OAuth grant is not refreshable') {
    super(message);
    this.name = 'HelloOAuthRefreshUnavailableError';
  }
}

/**
 * Adapt the platform fetch API to the SDK while retaining this provider's
 * redirect, timeout, content-type, and response-size controls.
 */
export const createHardenedHelloOAuthFetch = (
  fetchImpl: typeof fetch = fetch,
): FetchLike => async (input, init) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TOKEN_ENDPOINT_TIMEOUT_MS);
  try {
    const response = await fetchImpl(input, {
      ...init,
      redirect: 'error',
      signal: controller.signal,
    });
    if (!response.ok) {
      await readBoundedResponseText(response, TOKEN_RESPONSE_MAX_BYTES);
      return {
        ok: false,
        status: response.status,
        json: async () => ({}),
        text: async () => '',
      };
    }
    assertJsonResponse(response);
    const text = await readBoundedResponseText(response, TOKEN_RESPONSE_MAX_BYTES);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch (error) {
      throw new Error('Simply360 token endpoint returned invalid JSON', { cause: error });
    }
    return {
      ok: true,
      status: response.status,
      json: async () => parsed,
      text: async () => '',
    };
  } finally {
    clearTimeout(timeout);
  }
};

const exactSet = (left: readonly string[], right: readonly string[]): boolean => {
  if (left.length !== right.length) return false;
  const rightSet = new Set(right);
  return rightSet.size === right.length && left.every((value) => rightSet.has(value));
};

const assertHttpsEndpoint = (value: string, label: string): void => {
  const url = new URL(value);
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== '' ||
    url.search !== ''
  ) {
    throw new Error(`${label} must be an exact HTTPS URL without credentials, query, or fragment`);
  }
};

const assertConfiguration = (configuration: HelloOAuthConfiguration): void => {
  assertHttpsEndpoint(configuration.authorizationEndpoint, 'authorizationEndpoint');
  assertHttpsEndpoint(configuration.tokenEndpoint, 'tokenEndpoint');
  assertHttpsEndpoint(configuration.redirectUri, 'redirectUri');
  if (
    configuration.allowedRedirectUris.length === 0 ||
    !configuration.allowedRedirectUris.includes(configuration.redirectUri)
  ) {
    throw new Error('redirectUri must be present in the exact redirect allowlist');
  }
  for (const redirectUri of configuration.allowedRedirectUris) {
    assertHttpsEndpoint(redirectUri, 'allowed redirect URI');
  }
  if (new Set(configuration.allowedRedirectUris).size !== configuration.allowedRedirectUris.length) {
    throw new Error('allowed redirect URIs must be unique');
  }
  if (configuration.clientId.trim() !== configuration.clientId || configuration.clientId.length === 0) {
    throw new Error('clientId is invalid');
  }
  if (configuration.scopes.length === 0 || new Set(configuration.scopes).size !== configuration.scopes.length) {
    throw new Error('manifest scopes must be nonempty and unique');
  }
  for (const scope of configuration.scopes) OAuthScopeSchema.parse(scope);
  if (!configuration.scopes.includes('offline_access')) {
    throw new Error('the hosted hello acceptance client requires offline_access');
  }
  for (const [field, value] of [
    ['integrationPublisherSimplyId', configuration.integrationPublisherSimplyId],
    ['integrationAppSimplyId', configuration.integrationAppSimplyId],
    ['integrationAppVersionSimplyId', configuration.integrationAppVersionSimplyId],
    ['integrationAppReleaseSimplyId', configuration.integrationAppReleaseSimplyId],
    ['integrationAppOAuthClientSimplyId', configuration.integrationAppOAuthClientSimplyId],
  ] as const) {
    assertSimplyId(value, field);
  }
};

const createPendingIntent = (
  configuration: HelloOAuthConfiguration,
  codeVerifier: string,
): PendingHelloOAuthIntent => ({
  kind: 'SIMPLY360_NATIVE_OAUTH',
  codeVerifier,
  clientId: configuration.clientId,
  redirectUri: configuration.redirectUri,
  audience: HELLO_OAUTH_AUDIENCE,
  resource: HELLO_OAUTH_RESOURCE,
  environment: configuration.environment,
  integrationPublisherSimplyId: configuration.integrationPublisherSimplyId,
  integrationAppSimplyId: configuration.integrationAppSimplyId,
  integrationAppVersionSimplyId: configuration.integrationAppVersionSimplyId,
  integrationAppReleaseSimplyId: configuration.integrationAppReleaseSimplyId,
  integrationAppOAuthClientSimplyId: configuration.integrationAppOAuthClientSimplyId,
  scopes: Object.freeze([...configuration.scopes]),
});

const assertPendingIntent = (
  value: PendingHelloOAuthIntent,
  configuration: HelloOAuthConfiguration,
): void => {
  if (
    value.kind !== 'SIMPLY360_NATIVE_OAUTH' ||
    value.clientId !== configuration.clientId ||
    value.redirectUri !== configuration.redirectUri ||
    value.audience !== HELLO_OAUTH_AUDIENCE ||
    value.resource !== HELLO_OAUTH_RESOURCE ||
    value.environment !== configuration.environment ||
    value.integrationPublisherSimplyId !== configuration.integrationPublisherSimplyId ||
    value.integrationAppSimplyId !== configuration.integrationAppSimplyId ||
    value.integrationAppVersionSimplyId !== configuration.integrationAppVersionSimplyId ||
    value.integrationAppReleaseSimplyId !== configuration.integrationAppReleaseSimplyId ||
    value.integrationAppOAuthClientSimplyId !== configuration.integrationAppOAuthClientSimplyId ||
    !Array.isArray(value.scopes) ||
    !exactSet(value.scopes, configuration.scopes) ||
    typeof value.codeVerifier !== 'string' ||
    !isValidCodeVerifier(value.codeVerifier)
  ) {
    throw new Error('pending Simply360 OAuth intent does not match the reviewed client configuration');
  }
};

const assertBinding = (
  binding: PublicAuthorizationBinding,
  configuration: HelloOAuthConfiguration,
  expectedScopes: readonly OAuthScope[],
): void => {
  if (
    binding.principalType !== 'USER_DELEGATED' ||
    binding.clientId !== configuration.clientId ||
    binding.audience !== HELLO_OAUTH_AUDIENCE ||
    binding.resource !== HELLO_OAUTH_RESOURCE ||
    binding.environment !== configuration.environment ||
    binding.phase !== 'ACTIVE' ||
    binding.integrationPublisherSimplyId !== configuration.integrationPublisherSimplyId ||
    binding.integrationAppSimplyId !== configuration.integrationAppSimplyId ||
    binding.integrationAppVersionSimplyId !== configuration.integrationAppVersionSimplyId ||
    binding.integrationAppReleaseSimplyId !== configuration.integrationAppReleaseSimplyId ||
    binding.integrationAppOAuthClientSimplyId !== configuration.integrationAppOAuthClientSimplyId ||
    !exactSet(binding.scopes, expectedScopes)
  ) {
    throw new Error('Simply360 token binding does not match the reviewed client and manifest authority');
  }
};

const namespaceFromBinding = (binding: PublicAuthorizationBinding): HelloGrantNamespace => ({
  teamIntegrationSimplyId: binding.teamIntegrationSimplyId,
  scope: 'member',
  memberSimplyId: binding.teamUserLinkSimplyId,
  grant: 'simply360',
  integrationInstallationGrantSimplyId: binding.integrationInstallationGrantSimplyId,
});

const credentialFromResponse = (
  token: OAuthTokenResponse,
  binding: PublicAuthorizationBinding,
  now: number,
): StoredHelloOAuthCredential => {
  if (!token.refresh_token) {
    throw new Error('Simply360 did not return the rotating refresh token required by offline_access');
  }
  return {
    kind: 'SIMPLY360_NATIVE_OAUTH',
    status: 'ACTIVE',
    accessToken: token.access_token,
    refreshToken: token.refresh_token,
    tokenType: 'Bearer',
    ...(token.expires_in === undefined
      ? {}
      : { expiresAt: new Date(now + token.expires_in * 1_000).toISOString() }),
    binding,
  };
};

const exactBinding = (
  left: PublicAuthorizationBinding,
  right: PublicAuthorizationBinding,
): boolean =>
  left.principalType === right.principalType &&
  left.teamSimplyId === right.teamSimplyId &&
  left.teamIntegrationSimplyId === right.teamIntegrationSimplyId &&
  left.teamUserLinkSimplyId === right.teamUserLinkSimplyId &&
  left.integrationInstallationEpochSimplyId === right.integrationInstallationEpochSimplyId &&
  left.integrationPublisherSimplyId === right.integrationPublisherSimplyId &&
  left.integrationAppSimplyId === right.integrationAppSimplyId &&
  left.integrationAppVersionSimplyId === right.integrationAppVersionSimplyId &&
  left.integrationAppReleaseSimplyId === right.integrationAppReleaseSimplyId &&
  left.integrationAppOAuthClientSimplyId === right.integrationAppOAuthClientSimplyId &&
  left.integrationInstallationConsentSimplyId === right.integrationInstallationConsentSimplyId &&
  left.integrationInstallationGrantSimplyId === right.integrationInstallationGrantSimplyId &&
  left.clientId === right.clientId &&
  left.audience === right.audience &&
  left.resource === right.resource &&
  left.environment === right.environment &&
  left.phase === right.phase &&
  exactSet(left.scopes, right.scopes);

export class HelloOAuthClient {
  private readonly configuration: HelloOAuthConfiguration;
  private readonly store: HelloOAuthStateStore;
  private readonly fetchImpl?: FetchLike;
  private readonly now: () => number;

  public constructor(input: {
    readonly configuration: HelloOAuthConfiguration;
    readonly store: HelloOAuthStateStore;
    readonly fetchImpl?: FetchLike;
    readonly now?: () => number;
  }) {
    assertConfiguration(input.configuration);
    this.configuration = input.configuration;
    this.store = input.store;
    this.fetchImpl = input.fetchImpl ?? createHardenedHelloOAuthFetch();
    this.now = input.now ?? Date.now;
  }

  public async begin(): Promise<BeginHelloOAuthResult> {
    const state = generateOAuthState();
    const browserNonce = generateOAuthState();
    const pkce = await generatePkcePair();
    const expiresAt = new Date(this.now() + PENDING_OAUTH_LIFETIME_MS);
    await this.store.createPendingOAuthIntent(
      state,
      browserNonce,
      expiresAt,
      createPendingIntent(this.configuration, pkce.codeVerifier),
    );
    return {
      authorizationUrl: buildAuthorizationRequestUrl({
        authorizationEndpoint: this.configuration.authorizationEndpoint,
        clientId: this.configuration.clientId,
        redirectUri: this.configuration.redirectUri,
        scopes: this.configuration.scopes,
        state,
        codeChallenge: pkce.codeChallenge,
        codeChallengeMethod: 'S256',
        extraParams: { resource: HELLO_OAUTH_RESOURCE },
      }),
      state,
      browserNonce,
      expiresAt: expiresAt.toISOString(),
    };
  }

  public async complete(input: CompleteHelloOAuthInput): Promise<CompleteHelloOAuthResult> {
    const pending = await this.store.consumePendingOAuthIntent<PendingHelloOAuthIntent>(
      input.state,
      input.browserNonce,
    );
    assertPendingIntent(pending, this.configuration);
    if ('error' in input) throw new HelloOAuthDeniedError();
    if (input.code.trim() !== input.code || input.code.length === 0 || input.code.length > 2_048) {
      throw new Error('authorization code is invalid');
    }

    let token: OAuthTokenResponse;
    try {
      token = await exchangeAuthorizationCode({
        tokenEndpoint: this.configuration.tokenEndpoint,
        clientId: pending.clientId,
        redirectUri: pending.redirectUri,
        code: input.code,
        codeVerifier: pending.codeVerifier,
        fetchImpl: this.fetchImpl,
      });
    } catch (error) {
      throw new HelloOAuthCompletionUnknownError('Simply360 token exchange did not produce a durable credential', {
        cause: error,
      });
    }
    const binding = token.authorization_binding;
    if (!binding) {
      throw new HelloOAuthCompletionUnknownError('Simply360 token response omitted its public authorization binding');
    }
    try {
      assertBinding(binding, this.configuration, pending.scopes);
      const namespace = namespaceFromBinding(binding);
      await this.store.saveCredential(
        namespace,
        credentialFromResponse(token, binding, this.now()),
        null,
      );
      return { binding, namespace };
    } catch (error) {
      throw new HelloOAuthCompletionUnknownError('Simply360 issued a token that could not be bound to durable grant custody', {
        cause: error,
      });
    }
  }

  public async refresh(binding: PublicAuthorizationBinding): Promise<CompleteHelloOAuthResult> {
    assertBinding(binding, this.configuration, this.configuration.scopes);
    const namespace = namespaceFromBinding(binding);
    const stored = await this.store.loadCredential<StoredHelloOAuthCredential>(namespace);
    if (!stored || stored.value.kind !== 'SIMPLY360_NATIVE_OAUTH' || stored.value.status !== 'ACTIVE') {
      throw new HelloOAuthRefreshUnavailableError();
    }
    if (!exactBinding(stored.value.binding, binding)) {
      throw new HelloOAuthRefreshUnavailableError('stored credential identity does not match the requested grant');
    }

    const fenced: StoredHelloOAuthCredential = {
      ...stored.value,
      status: 'REFRESH_IN_PROGRESS',
    };
    let fence: StoredHelloCredential<StoredHelloOAuthCredential>;
    try {
      fence = await this.store.saveCredential(namespace, fenced, stored.revision);
    } catch (error) {
      if (error instanceof ConcurrentHelloStateUpdateError) throw new HelloOAuthRefreshUnavailableError();
      throw error;
    }

    let token: OAuthTokenResponse;
    try {
      token = await refreshAccessToken({
        tokenEndpoint: this.configuration.tokenEndpoint,
        clientId: this.configuration.clientId,
        refreshToken: stored.value.refreshToken,
        scopes: this.configuration.scopes,
        fetchImpl: this.fetchImpl,
      });
    } catch (error) {
      throw new HelloOAuthCompletionUnknownError(
        'Simply360 refresh outcome is unknown; this grant remains fenced from retry',
        { cause: error },
      );
    }

    const refreshedBinding = token.authorization_binding;
    if (!refreshedBinding) {
      throw new HelloOAuthCompletionUnknownError(
        'Simply360 refresh omitted its public authorization binding; this grant remains fenced from retry',
      );
    }
    try {
      assertBinding(refreshedBinding, this.configuration, this.configuration.scopes);
      if (!exactBinding(refreshedBinding, binding)) {
        throw new Error('refresh changed immutable grant identity');
      }
      await this.store.saveCredential(
        namespace,
        credentialFromResponse(token, refreshedBinding, this.now()),
        fence.revision,
      );
      return { binding: refreshedBinding, namespace };
    } catch (error) {
      throw new HelloOAuthCompletionUnknownError(
        'Simply360 refresh could not be committed to durable grant custody; this grant remains fenced from retry',
        { cause: error },
      );
    }
  }
}
