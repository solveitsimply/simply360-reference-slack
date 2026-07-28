import { timingSafeEqual } from 'node:crypto';

import { generateOAuthState } from './oauth.js';
import { assertJsonResponse, readBoundedResponseText } from './http.js';

const ROTATING_SLACK_BOT_TOKEN_PATTERN = /^xoxe\.xoxb-[A-Za-z0-9-]{10,}$/u;
const SLACK_REFRESH_TOKEN_PATTERN = /^xoxe-[A-Za-z0-9-]{10,}$/u;

export interface SlackOAuthGrant {
  readonly accessToken: string;
  readonly teamId: string;
  readonly teamName: string;
  readonly botUserId: string;
  readonly scope: readonly ['chat:write'];
  readonly refreshToken: string;
  readonly expiresIn: number;
}

export interface SlackOAuthTransport {
  exchange(input: {
    readonly clientId: string;
    readonly clientSecret: string;
    readonly code: string;
    readonly redirectUri: string;
  }): Promise<unknown>;
  refresh(input: {
    readonly clientId: string;
    readonly clientSecret: string;
    readonly refreshToken: string;
  }): Promise<unknown>;
  revoke(accessToken: string): Promise<void>;
}

export class SlackOAuthClient {
  public constructor(
    private readonly config: {
      readonly clientId: string;
      readonly clientSecret: string;
      readonly redirectUri: string;
    },
    private readonly transport: SlackOAuthTransport,
  ) {
    const redirect = new URL(config.redirectUri);
    if (redirect.protocol !== 'https:' || redirect.username || redirect.password || redirect.hash) {
      throw new Error('Slack OAuth redirect URI must be an exact HTTPS URL');
    }
  }

  public start(): { readonly url: string; readonly state: string } {
    const state = generateOAuthState();
    const url = new URL('https://slack.com/oauth/v2/authorize');
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', this.config.redirectUri);
    url.searchParams.set('scope', 'chat:write');
    url.searchParams.set('state', state);
    return { url: url.toString(), state };
  }

  public verifyState(expected: string, received: string): void {
    const left = Buffer.from(expected);
    const right = Buffer.from(received);
    if (left.length !== right.length || !timingSafeEqual(left, right)) throw new Error('Slack OAuth state mismatch');
  }

  public async exchange(code: string): Promise<SlackOAuthGrant> {
    const parsed = await this.transport.exchange({ ...this.config, code });
    return this.parseGrant(parsed);
  }

  public async refresh(refreshToken: string): Promise<SlackOAuthGrant> {
    const parsed = await this.transport.refresh({ ...this.config, refreshToken });
    return this.parseGrant(parsed);
  }

  public revoke(accessToken: string): Promise<void> {
    return this.transport.revoke(accessToken);
  }

  private parseGrant(parsed: unknown): SlackOAuthGrant {
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('Slack OAuth response is invalid');
    const value = parsed as Record<string, unknown>;
    const team = value.team;
    if (
      value.ok !== true ||
      typeof value.access_token !== 'string' ||
      !ROTATING_SLACK_BOT_TOKEN_PATTERN.test(value.access_token) ||
      value.token_type !== 'bot' ||
      value.scope !== 'chat:write' ||
      typeof value.bot_user_id !== 'string' ||
      typeof value.refresh_token !== 'string' ||
      !SLACK_REFRESH_TOKEN_PATTERN.test(value.refresh_token) ||
      !Number.isSafeInteger(value.expires_in) ||
      (value.expires_in as number) < 60 ||
      (value.expires_in as number) > 86_400 ||
      typeof team !== 'object' ||
      team === null ||
      Array.isArray(team) ||
      typeof (team as Record<string, unknown>).id !== 'string' ||
      typeof (team as Record<string, unknown>).name !== 'string'
    ) {
      throw new Error('Slack OAuth response is not the reviewed rotating bot grant');
    }
    return {
      accessToken: value.access_token,
      teamId: (team as Record<string, unknown>).id as string,
      teamName: (team as Record<string, unknown>).name as string,
      botUserId: value.bot_user_id,
      scope: ['chat:write'],
      refreshToken: value.refresh_token,
      expiresIn: value.expires_in as number,
    };
  }
}

export class FetchSlackOAuthTransport implements SlackOAuthTransport {
  public constructor(private readonly fetchImpl: typeof fetch = fetch) {}

  public async exchange(input: {
    readonly clientId: string;
    readonly clientSecret: string;
    readonly code: string;
    readonly redirectUri: string;
  }): Promise<unknown> {
    return this.post('https://slack.com/api/oauth.v2.access', {
      code: input.code,
      redirect_uri: input.redirectUri,
    }, input);
  }

  public async refresh(input: {
    readonly clientId: string;
    readonly clientSecret: string;
    readonly refreshToken: string;
  }): Promise<unknown> {
    if (!SLACK_REFRESH_TOKEN_PATTERN.test(input.refreshToken)) throw new Error('Slack refresh token has an invalid shape');
    return this.post(
      'https://slack.com/api/oauth.v2.access',
      { grant_type: 'refresh_token', refresh_token: input.refreshToken },
      input,
    );
  }

  public async revoke(accessToken: string): Promise<void> {
    if (!ROTATING_SLACK_BOT_TOKEN_PATTERN.test(accessToken)) throw new Error('Slack rotating bot token has an invalid shape');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    try {
      const response = await this.fetchImpl('https://slack.com/api/auth.revoke', {
        method: 'POST',
        redirect: 'error',
        signal: controller.signal,
        headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
      });
      assertJsonResponse(response);
      const text = await readBoundedResponseText(response);
      const parsed = JSON.parse(text) as Record<string, unknown>;
      if (!response.ok || parsed.ok !== true) throw new Error(`Slack auth.revoke failed with HTTP ${response.status}`);
    } finally {
      clearTimeout(timeout);
    }
  }

  private async post(
    endpoint: string,
    form: Record<string, string>,
    credentials: { readonly clientId: string; readonly clientSecret: string },
  ): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    try {
      const response = await this.fetchImpl(endpoint, {
        method: 'POST',
        redirect: 'error',
        signal: controller.signal,
        headers: {
          Authorization: `Basic ${Buffer.from(`${credentials.clientId}:${credentials.clientSecret}`).toString('base64')}`,
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: new URLSearchParams(form).toString(),
      });
      if (!response.ok) throw new Error(`Slack OAuth endpoint returned HTTP ${response.status}`);
      assertJsonResponse(response);
      const text = await readBoundedResponseText(response);
      return JSON.parse(text) as unknown;
    } finally {
      clearTimeout(timeout);
    }
  }
}
