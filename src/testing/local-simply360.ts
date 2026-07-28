import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import type { OAuthScope, OAuthTokenSet, RemoteTriggerPublisher } from '../contracts.js';
import { computeS256CodeChallenge, type OAuthTransport } from '../oauth.js';

type InstallationState = 'PENDING_SETUP' | 'ACTIVE' | 'UNINSTALLED';
type FamilyPhase = 'PENDING_SETUP' | 'ACTIVE' | 'REVOKED';

interface Installation {
  readonly teamIntegrationSimplyId: string;
  readonly teamSimplyId: string;
  state: InstallationState;
  consentedScopes: OAuthScope[];
  consentRevision: number;
  readonly userLinks: Map<string, { readonly userSimplyId: string; active: boolean }>;
  readonly records: Array<{ readonly recordSimplyId: string; readonly name: string }>;
  blueprintPackageKey?: string;
}

interface AuthorizationCode {
  readonly code: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly installationId: string;
  readonly scopes: OAuthScope[];
  readonly consentRevision: number;
  used: boolean;
}

interface TokenFamily {
  readonly familyId: string;
  readonly installationId: string;
  readonly scopes: OAuthScope[];
  readonly consentRevision: number;
  phase: FamilyPhase;
  currentRefreshToken: string;
  readonly spentRefreshTokens: Set<string>;
}

interface AccessGrant {
  readonly familyId: string;
  readonly installationId: string;
  readonly phase: FamilyPhase;
  readonly scopes: readonly OAuthScope[];
}

const secret = (prefix: string): string => `${prefix}_${randomBytes(24).toString('base64url')}`;

const arraysEqual = <T>(left: readonly T[], right: readonly T[]): boolean =>
  left.length === right.length && left.every((value, index) => value === right[index]);

const sortedScopes = (scopes: readonly OAuthScope[]): OAuthScope[] => [...new Set(scopes)].sort();

const parseBasicCredentials = (credentials: {
  readonly clientId: string;
  readonly clientSecret: string;
}): { readonly clientId: string; readonly clientSecret: string } => credentials;

/**
 * Local provider double for the Direction-45 hello lifecycle.
 *
 * It deliberately models the security invariants, not the Simply360 database:
 * exact authorization-code binding, single use, S256 PKCE, PENDING_SETUP data
 * denial, activation on a later refresh, refresh-family replay revocation,
 * exact-instance isolation, explicit scope-widening consent, user-link
 * isolation, shared Blueprint identity and uninstall revocation.
 */
export class LocalSimply360Double implements OAuthTransport, RemoteTriggerPublisher {
  private readonly clientId = 'local-reference-slack-server';
  private readonly clientSecret = secret('client');
  private readonly redirectUri = 'https://reference-slack.local/oauth/callback';
  private installationSequence = 0;
  private userLinkSequence = 0;
  private recordSequence = 0;
  private readonly installations = new Map<string, Installation>();
  private readonly authorizationCodes = new Map<string, AuthorizationCode>();
  private readonly tokenFamilies = new Map<string, TokenFamily>();
  private readonly accessGrants = new Map<string, AccessGrant>();
  private readonly sharedBlueprintsByTeamAndPackage = new Map<string, string>();
  public readonly triggers: Array<{ readonly idempotencyKey: string; readonly input: unknown }> = [];

  public oauthClientConfig(): {
    readonly authorizationEndpoint: string;
    readonly tokenEndpoint: string;
    readonly clientId: string;
    readonly clientSecret: string;
    readonly redirectUri: string;
  } {
    return {
      authorizationEndpoint: 'https://simply360.local/oauth/authorize',
      tokenEndpoint: 'https://simply360.local/oauth/token',
      clientId: this.clientId,
      clientSecret: this.clientSecret,
      redirectUri: this.redirectUri,
    };
  }

  public createInstallation(teamSimplyId: string): string {
    this.installationSequence += 1;
    const suffix = String(this.installationSequence).padStart(4, '0');
    const teamIntegrationSimplyId = `TINT-0001-${suffix}`;
    this.installations.set(teamIntegrationSimplyId, {
      teamIntegrationSimplyId,
      teamSimplyId,
      state: 'PENDING_SETUP',
      consentedScopes: [],
      consentRevision: 0,
      userLinks: new Map(),
      records: [],
    });
    return teamIntegrationSimplyId;
  }

  public issueAuthorizationCode(input: {
    readonly teamIntegrationSimplyId: string;
    readonly clientId: string;
    readonly redirectUri: string;
    readonly codeChallenge: string;
    readonly requestedScopes: readonly OAuthScope[];
    readonly consentApproved: boolean;
  }): string {
    const installation = this.requireInstallation(input.teamIntegrationSimplyId);
    if (installation.state === 'UNINSTALLED') throw new Error('installation is terminal');
    if (input.clientId !== this.clientId || input.redirectUri !== this.redirectUri) throw new Error('OAuth client binding mismatch');
    const requestedScopes = sortedScopes(input.requestedScopes);
    const allowedScopes = new Set<OAuthScope>(['schema:read', 'records:read', 'records:write', 'offline_access']);
    if (requestedScopes.length < 1 || requestedScopes.some((scope) => !allowedScopes.has(scope))) throw new Error('invalid requested scope');
    const widens = requestedScopes.some((scope) => !installation.consentedScopes.includes(scope));
    if ((installation.consentRevision === 0 || widens) && !input.consentApproved) {
      throw new Error('scope widening requires explicit Team Admin re-consent');
    }
    if (input.consentApproved && (installation.consentRevision === 0 || widens)) {
      installation.consentedScopes = requestedScopes;
      installation.consentRevision += 1;
    } else if (!arraysEqual(requestedScopes, installation.consentedScopes)) {
      throw new Error('authorization scopes must match the immutable consent snapshot');
    }
    const code = secret('code');
    this.authorizationCodes.set(code, {
      code,
      clientId: input.clientId,
      redirectUri: input.redirectUri,
      codeChallenge: input.codeChallenge,
      installationId: installation.teamIntegrationSimplyId,
      scopes: requestedScopes,
      consentRevision: installation.consentRevision,
      used: false,
    });
    return code;
  }

  public async postForm(
    endpoint: string,
    body: URLSearchParams,
    credentials: { readonly clientId: string; readonly clientSecret: string },
  ): Promise<unknown> {
    if (endpoint !== 'https://simply360.local/oauth/token') throw new Error('unexpected token endpoint');
    const received = parseBasicCredentials(credentials);
    const expectedSecret = Buffer.from(this.clientSecret);
    const receivedSecret = Buffer.from(received.clientSecret);
    if (
      received.clientId !== this.clientId ||
      expectedSecret.length !== receivedSecret.length ||
      !timingSafeEqual(expectedSecret, receivedSecret)
    ) {
      throw new Error('invalid confidential client');
    }
    const grantType = body.get('grant_type');
    if (grantType === 'authorization_code') return this.toWireToken(this.exchangeAuthorizationCode(body));
    if (grantType === 'refresh_token') return this.toWireToken(this.rotateRefreshToken(body));
    throw new Error('unsupported_grant_type');
  }

  public setupStatus(accessToken: string): { readonly state: InstallationState; readonly teamIntegrationSimplyId: string } {
    const grant = this.requireAccess(accessToken, true);
    const installation = this.requireInstallation(grant.installationId);
    return { state: installation.state, teamIntegrationSimplyId: installation.teamIntegrationSimplyId };
  }

  public completeSetup(accessToken: string): void {
    const grant = this.requireAccess(accessToken, true);
    const installation = this.requireInstallation(grant.installationId);
    if (installation.state !== 'PENDING_SETUP') throw new Error('installation is not pending setup');
    installation.state = 'ACTIVE';
  }

  public readRecords(accessToken: string): readonly { readonly recordSimplyId: string; readonly name: string }[] {
    const grant = this.requireAccess(accessToken, false);
    if (!grant.scopes.includes('records:read')) throw new Error('records:read scope is required');
    return [...this.requireInstallation(grant.installationId).records];
  }

  public createRecord(accessToken: string, name: string): string {
    const grant = this.requireAccess(accessToken, false);
    if (!grant.scopes.includes('records:write')) throw new Error('records:write scope is required');
    if (name.length < 1 || name.length > 200) throw new Error('record name is invalid');
    this.recordSequence += 1;
    const recordSimplyId = `RECD-0001-${String(this.recordSequence).padStart(4, '0')}`;
    this.requireInstallation(grant.installationId).records.push({ recordSimplyId, name });
    return recordSimplyId;
  }

  public linkUser(teamIntegrationSimplyId: string, userSimplyId: string): string {
    const installation = this.requireInstallation(teamIntegrationSimplyId);
    if (installation.state !== 'ACTIVE') throw new Error('installation must be active');
    const active = [...installation.userLinks.entries()].find(
      ([, link]) => link.userSimplyId === userSimplyId && link.active,
    );
    if (active) return active[0];
    this.userLinkSequence += 1;
    const linkSimplyId = `ULNK-0001-${String(this.userLinkSequence).padStart(4, '0')}`;
    installation.userLinks.set(linkSimplyId, { userSimplyId, active: true });
    return linkSimplyId;
  }

  public revokeUserLink(teamIntegrationSimplyId: string, linkSimplyId: string): void {
    const link = this.requireInstallation(teamIntegrationSimplyId).userLinks.get(linkSimplyId);
    if (!link) throw new Error('user link does not belong to this installation');
    link.active = false;
  }

  public activeUserLinks(teamIntegrationSimplyId: string): readonly string[] {
    return [...this.requireInstallation(teamIntegrationSimplyId).userLinks.entries()]
      .filter(([, value]) => value.active)
      .map(([key]) => key);
  }

  public installSharedBlueprint(teamIntegrationSimplyId: string, packageKey: string): string {
    const installation = this.requireInstallation(teamIntegrationSimplyId);
    if (installation.state !== 'ACTIVE') throw new Error('installation must be active');
    installation.blueprintPackageKey = packageKey;
    const authority = `${installation.teamSimplyId}\n${packageKey}`;
    const existing = this.sharedBlueprintsByTeamAndPackage.get(authority);
    if (existing) return existing;
    const digest = createHash('sha256').update(authority).digest('hex').slice(0, 8).toUpperCase();
    const teamBlueprintSimplyId = `TBPL-${digest.slice(0, 4)}-${digest.slice(4, 8)}`;
    this.sharedBlueprintsByTeamAndPackage.set(authority, teamBlueprintSimplyId);
    return teamBlueprintSimplyId;
  }

  public uninstall(teamIntegrationSimplyId: string): void {
    const installation = this.requireInstallation(teamIntegrationSimplyId);
    installation.state = 'UNINSTALLED';
    installation.blueprintPackageKey = undefined;
    for (const link of installation.userLinks.values()) link.active = false;
    for (const family of this.tokenFamilies.values()) {
      if (family.installationId === teamIntegrationSimplyId) family.phase = 'REVOKED';
    }
  }

  public async publishCreateRecordFromMessage(input: unknown, idempotencyKey: string): Promise<void> {
    if (this.triggers.some((trigger) => trigger.idempotencyKey === idempotencyKey)) return;
    this.triggers.push({ idempotencyKey, input });
  }

  private exchangeAuthorizationCode(body: URLSearchParams): OAuthTokenSet {
    const codeValue = body.get('code');
    const redirectUri = body.get('redirect_uri');
    const codeVerifier = body.get('code_verifier');
    if (!codeValue || !redirectUri || !codeVerifier) throw new Error('authorization_code request is incomplete');
    const code = this.authorizationCodes.get(codeValue);
    if (!code || code.used) throw new Error('invalid_grant');
    code.used = true;
    if (
      code.clientId !== this.clientId ||
      code.redirectUri !== redirectUri ||
      computeS256CodeChallenge(codeVerifier) !== code.codeChallenge
    ) {
      throw new Error('invalid_grant');
    }
    const installation = this.requireInstallation(code.installationId);
    if (installation.consentRevision !== code.consentRevision || installation.state === 'UNINSTALLED') throw new Error('invalid_grant');
    const family: TokenFamily = {
      familyId: secret('family'),
      installationId: code.installationId,
      scopes: code.scopes,
      consentRevision: code.consentRevision,
      phase: 'PENDING_SETUP',
      currentRefreshToken: secret('refresh'),
      spentRefreshTokens: new Set(),
    };
    this.tokenFamilies.set(family.familyId, family);
    return this.issueToken(family);
  }

  private rotateRefreshToken(body: URLSearchParams): OAuthTokenSet {
    const refreshToken = body.get('refresh_token');
    if (!refreshToken) throw new Error('refresh_token is required');
    const family = [...this.tokenFamilies.values()].find(
      (candidate) => candidate.currentRefreshToken === refreshToken || candidate.spentRefreshTokens.has(refreshToken),
    );
    if (!family || family.phase === 'REVOKED') throw new Error('invalid_grant');
    if (family.spentRefreshTokens.has(refreshToken)) {
      family.phase = 'REVOKED';
      throw new Error('refresh token replay revoked the family');
    }
    const installation = this.requireInstallation(family.installationId);
    if (
      installation.state === 'UNINSTALLED' ||
      installation.consentRevision !== family.consentRevision ||
      body.has('scope') && !arraysEqual(sortedScopes((body.get('scope') as string).split(' ') as OAuthScope[]), family.scopes)
    ) {
      family.phase = 'REVOKED';
      throw new Error('invalid_grant');
    }
    family.spentRefreshTokens.add(refreshToken);
    family.currentRefreshToken = secret('refresh');
    if (installation.state === 'ACTIVE') family.phase = 'ACTIVE';
    return this.issueToken(family);
  }

  private issueToken(family: TokenFamily): OAuthTokenSet {
    const accessToken = secret('access');
    this.accessGrants.set(accessToken, {
      familyId: family.familyId,
      installationId: family.installationId,
      phase: family.phase,
      scopes: family.scopes,
    });
    return {
      accessToken,
      refreshToken: family.currentRefreshToken,
      tokenType: 'Bearer',
      expiresIn: 900,
      scope: family.scopes,
    };
  }

  private toWireToken(token: OAuthTokenSet): Record<string, unknown> {
    return {
      access_token: token.accessToken,
      ...(token.refreshToken ? { refresh_token: token.refreshToken } : {}),
      token_type: token.tokenType,
      expires_in: token.expiresIn,
      scope: token.scope.join(' '),
    };
  }

  private requireAccess(accessToken: string, setupOnly: boolean): AccessGrant {
    const grant = this.accessGrants.get(accessToken);
    if (!grant) throw new Error('invalid access token');
    const family = this.tokenFamilies.get(grant.familyId);
    if (!family || family.phase === 'REVOKED') throw new Error('token family is revoked');
    if (!setupOnly && grant.phase !== 'ACTIVE') throw new Error('PENDING_SETUP tokens cannot access ordinary Team data');
    return grant;
  }

  private requireInstallation(teamIntegrationSimplyId: string): Installation {
    const installation = this.installations.get(teamIntegrationSimplyId);
    if (!installation) throw new Error('unknown installation');
    return installation;
  }
}
