import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import type { OAuthScope, OAuthTokenSet } from './contracts.js';
import { assertJsonResponse, readBoundedResponseText } from './http.js';

const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/u;

const base64Url = (input: Uint8Array): string => Buffer.from(input).toString('base64url');

export const generatePkcePair = (): { readonly codeVerifier: string; readonly codeChallenge: string } => {
  const codeVerifier = base64Url(randomBytes(32));
  return { codeVerifier, codeChallenge: computeS256CodeChallenge(codeVerifier) };
};

export const computeS256CodeChallenge = (codeVerifier: string): string => {
  if (!CODE_VERIFIER_PATTERN.test(codeVerifier)) throw new Error('invalid PKCE code_verifier');
  return createHash('sha256').update(codeVerifier).digest('base64url');
};

export const generateOAuthState = (): string => base64Url(randomBytes(32));

export const matchesOAuthState = (expected: string, received: string): boolean => {
  const expectedBytes = Buffer.from(expected);
  const receivedBytes = Buffer.from(received);
  return expectedBytes.length === receivedBytes.length && timingSafeEqual(expectedBytes, receivedBytes);
};

export const buildAuthorizationUrl = (input: {
  readonly authorizationEndpoint: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scopes: readonly OAuthScope[];
  readonly state: string;
  readonly codeChallenge: string;
}): string => {
  if (!input.state || !input.codeChallenge) throw new Error('state and S256 PKCE challenge are required');
  const url = new URL(input.authorizationEndpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', input.clientId);
  url.searchParams.set('redirect_uri', input.redirectUri);
  url.searchParams.set('scope', input.scopes.join(' '));
  url.searchParams.set('state', input.state);
  url.searchParams.set('code_challenge', input.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.toString();
};

export const parseTokenResponse = (input: unknown): OAuthTokenSet => {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) throw new Error('token response must be an object');
  const value = input as Record<string, unknown>;
  if (typeof value.access_token !== 'string' || value.access_token.length < 1 || value.access_token.length > 4096) {
    throw new Error('access_token is invalid');
  }
  if (value.refresh_token !== undefined && (typeof value.refresh_token !== 'string' || value.refresh_token.length < 1)) {
    throw new Error('refresh_token is invalid');
  }
  if (typeof value.token_type !== 'string' || value.token_type.toLowerCase() !== 'bearer') {
    throw new Error('only Bearer token responses are accepted');
  }
  if (
    value.expires_in !== undefined &&
    (!Number.isSafeInteger(value.expires_in) || (value.expires_in as number) < 1 || (value.expires_in as number) > 86_400)
  ) {
    throw new Error('expires_in is invalid');
  }
  const scope = typeof value.scope === 'string' ? value.scope.split(' ').filter(Boolean) : [];
  const allowedScopes = new Set<OAuthScope>(['schema:read', 'records:read', 'records:write', 'offline_access']);
  if (scope.length < 1 || new Set(scope).size !== scope.length || scope.some((item) => !allowedScopes.has(item as OAuthScope))) {
    throw new Error('scope is invalid');
  }
  return {
    accessToken: value.access_token,
    ...(typeof value.refresh_token === 'string' ? { refreshToken: value.refresh_token } : {}),
    tokenType: 'Bearer',
    ...(typeof value.expires_in === 'number' ? { expiresIn: value.expires_in } : {}),
    scope: scope as OAuthScope[],
  };
};

export interface OAuthTransport {
  postForm(
    endpoint: string,
    body: URLSearchParams,
    basicCredentials: { readonly clientId: string; readonly clientSecret: string },
  ): Promise<unknown>;
}

export class FetchOAuthTransport implements OAuthTransport {
  public constructor(private readonly fetchImpl: typeof fetch = fetch) {}

  public async postForm(
    endpoint: string,
    body: URLSearchParams,
    basicCredentials: { readonly clientId: string; readonly clientSecret: string },
  ): Promise<unknown> {
    const url = new URL(endpoint);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
      throw new Error('OAuth token endpoint must be an exact HTTPS URL without userinfo or fragment');
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    try {
      const response = await this.fetchImpl(url, {
        method: 'POST',
        redirect: 'error',
        signal: controller.signal,
        headers: {
          Authorization: `Basic ${Buffer.from(`${basicCredentials.clientId}:${basicCredentials.clientSecret}`).toString('base64')}`,
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: body.toString(),
      });
      if (!response.ok) throw new Error(`OAuth token endpoint returned HTTP ${response.status}`);
      assertJsonResponse(response);
      const text = await readBoundedResponseText(response);
      return JSON.parse(text) as unknown;
    } finally {
      clearTimeout(timeout);
    }
  }
}

export class Simply360OAuthClient {
  public constructor(
    private readonly config: {
      readonly authorizationEndpoint: string;
      readonly tokenEndpoint: string;
      readonly clientId: string;
      readonly clientSecret: string;
      readonly redirectUri: string;
    },
    private readonly transport: OAuthTransport,
  ) {
    for (const [label, raw] of [
      ['authorizationEndpoint', config.authorizationEndpoint],
      ['tokenEndpoint', config.tokenEndpoint],
      ['redirectUri', config.redirectUri],
    ] as const) {
      const url = new URL(raw);
      if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
        throw new Error(`${label} must be an exact HTTPS URL without userinfo or fragment`);
      }
    }
    if (!config.clientId || !config.clientSecret) throw new Error('confidential OAuth client credentials are required');
  }

  public start(scopes: readonly OAuthScope[]): {
    readonly url: string;
    readonly state: string;
    readonly codeVerifier: string;
  } {
    const { codeVerifier, codeChallenge } = generatePkcePair();
    const state = generateOAuthState();
    return {
      state,
      codeVerifier,
      url: buildAuthorizationUrl({ ...this.config, scopes, state, codeChallenge }),
    };
  }

  public async exchange(code: string, codeVerifier: string): Promise<OAuthTokenSet> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.config.redirectUri,
      code_verifier: codeVerifier,
    });
    return parseTokenResponse(await this.transport.postForm(this.config.tokenEndpoint, body, this.config));
  }

  public async refresh(refreshToken: string, scopes?: readonly OAuthScope[]): Promise<OAuthTokenSet> {
    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken });
    if (scopes) body.set('scope', scopes.join(' '));
    return parseTokenResponse(await this.transport.postForm(this.config.tokenEndpoint, body, this.config));
  }
}
