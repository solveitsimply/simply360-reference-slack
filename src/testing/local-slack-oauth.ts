import { randomBytes } from 'node:crypto';

import type { SlackOAuthTransport } from '../slack-oauth.js';

export class LocalSlackOAuthDouble implements SlackOAuthTransport {
  private readonly clientId = 'local-slack-client';
  private readonly clientSecret = randomBytes(24).toString('base64url');
  private readonly redirectUri = 'https://reference-slack.local/oauth/slack/callback';
  private readonly codes = new Set<string>();
  private readonly activeTokens = new Set<string>();
  private readonly refreshTokens = new Map<string, string>();

  public clientConfig(): {
    readonly clientId: string;
    readonly clientSecret: string;
    readonly redirectUri: string;
  } {
    return { clientId: this.clientId, clientSecret: this.clientSecret, redirectUri: this.redirectUri };
  }

  public authorize(): string {
    const code = `slack-code-${randomBytes(18).toString('base64url')}`;
    this.codes.add(code);
    return code;
  }

  public async exchange(input: {
    readonly clientId: string;
    readonly clientSecret: string;
    readonly code: string;
    readonly redirectUri: string;
  }): Promise<unknown> {
    if (
      input.clientId !== this.clientId ||
      input.clientSecret !== this.clientSecret ||
      input.redirectUri !== this.redirectUri ||
      !this.codes.delete(input.code)
    ) {
      return { ok: false, error: 'invalid_code' };
    }
    return this.issueRotatingGrant();
  }

  public async refresh(input: {
    readonly clientId: string;
    readonly clientSecret: string;
    readonly refreshToken: string;
  }): Promise<unknown> {
    const previousAccessToken = this.refreshTokens.get(input.refreshToken);
    if (input.clientId !== this.clientId || input.clientSecret !== this.clientSecret || !previousAccessToken) {
      return { ok: false, error: 'invalid_refresh_token' };
    }
    this.refreshTokens.delete(input.refreshToken);
    this.activeTokens.delete(previousAccessToken);
    return this.issueRotatingGrant();
  }

  private issueRotatingGrant(): Record<string, unknown> {
    const accessToken = `xoxe.xoxb-local-${randomBytes(18).toString('hex')}`;
    const refreshToken = `xoxe-local-${randomBytes(18).toString('hex')}`;
    this.activeTokens.add(accessToken);
    this.refreshTokens.set(refreshToken, accessToken);
    return {
      ok: true,
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 43_200,
      token_type: 'bot',
      scope: 'chat:write',
      bot_user_id: 'U0000BOT1',
      team: { id: 'T00000001', name: 'Simply360 Developer Test' },
    };
  }

  public async revoke(accessToken: string): Promise<void> {
    if (!this.activeTokens.delete(accessToken)) throw new Error('Slack token is unknown or already revoked');
  }

  public isActive(accessToken: string): boolean {
    return this.activeTokens.has(accessToken);
  }
}
