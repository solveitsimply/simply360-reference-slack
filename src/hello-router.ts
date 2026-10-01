import { createHash } from 'node:crypto';

import {
  APP_PLATFORM_EVENT_PAYLOAD_SCHEMA_BY_EVENT_TYPE,
  isLifecycleEvent,
  parseEventOccurrence,
  parseWebhookV2SignatureHeader,
  verifyWebhookV2,
  type AppPlatformLifecycleEventType,
  type AppPlatformSubscriptionEventType,
  type WebhookV2IdentityHeaders,
  type WebhookV2SigningKey,
} from '@simply360/integration-sdk';
import { z } from 'zod';

import { SIMPLY_ID_PATTERN } from './contracts.js';
import { HelloOAuthClient, HelloOAuthDeniedError } from './hello-oauth.js';
import { HelloLifecycleFencedError, HelloStateStore } from './hello-state.js';

const MAX_REQUEST_BODY_BYTES = 256 * 1024;
const CALLBACK_COOKIE = 's360_hello_nonce';
export const HELLO_INSTALLATION_CLEANUP_RECEIPT_SCHEMA_VERSION =
  'simply360.reference-slack.installation-cleanup-receipt/v1' as const;
export const HELLO_ACCOUNT_LINK_CLEANUP_RECEIPT_SCHEMA_VERSION =
  'simply360.reference-slack.account-link-cleanup-receipt/v1' as const;
export const HELLO_ENDPOINT_PATH_VERIFICATION_SCHEMA_VERSION = 'simply360.remote-endpoint-path-verification/v1' as const;
const MAX_ENDPOINT_PATH_VERIFICATION_TTL_MS = 10 * 60 * 1_000;
const MAX_ENDPOINT_PATH_VERIFICATION_CLOCK_SKEW_MS = 5 * 60 * 1_000;

const SimplyIdSchema = z.string().regex(SIMPLY_ID_PATTERN);
const UtcMillisecondTimestampSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u)
  .refine((value) => {
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
  });
// Exactly 32 bytes as canonical unpadded base64url.
const NonceSchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/u)
  .refine((value) => Buffer.from(value, 'base64url').toString('base64url') === value);
const EndpointPathVerificationRequestSchema = z.object({
  schemaVersion: z.literal(HELLO_ENDPOINT_PATH_VERIFICATION_SCHEMA_VERSION),
  integrationPublisherSimplyId: SimplyIdSchema,
  integrationAppSimplyId: SimplyIdSchema,
  integrationAppVersionSimplyId: SimplyIdSchema,
  integrationAppVersionEndpointSimplyId: SimplyIdSchema,
  nonce: NonceSchema,
  issuedAt: UtcMillisecondTimestampSchema,
  expiresAt: UtcMillisecondTimestampSchema,
}).strict();
type EndpointPathVerificationRequest = z.infer<typeof EndpointPathVerificationRequestSchema>;

/**
 * RFC 8785 (JCS) serialization of the flat, all-string challenge: keys sorted
 * by UTF-16 code unit and ECMAScript string escaping, matching Simply360's
 * canonical JSON for this shape.
 */
const canonicalFlatStringJson = (value: Readonly<Record<string, string>>): string =>
  `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${JSON.stringify(value[key])}`).join(',')}}`;

class HelloRequestBodyError extends Error {
  public constructor(public readonly statusCode: 400 | 413) {
    super('request body is invalid');
  }
}

export interface HelloWebhookKeyBinding {
  readonly teamSimplyId: string;
  readonly teamIntegrationSimplyId: string;
  readonly keys: readonly WebhookV2SigningKey[];
}

export interface HelloHostedRequest {
  readonly method: string;
  readonly path: string;
  readonly query: Readonly<Record<string, string | undefined>>;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body: Uint8Array;
}

export interface HelloHostedResponse {
  readonly statusCode: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

export interface HelloInstallationCleanupReceipt {
  readonly schemaVersion: typeof HELLO_INSTALLATION_CLEANUP_RECEIPT_SCHEMA_VERSION;
  readonly installationSimplyId: string;
  readonly integrationInstallationOperationSimplyId: string;
  readonly eventSimplyId: string;
  readonly verifiedBodySha256: string;
  readonly outcome: 'CLEANED' | 'REPLAYED';
}

export interface HelloAccountLinkCleanupReceipt {
  readonly schemaVersion: typeof HELLO_ACCOUNT_LINK_CLEANUP_RECEIPT_SCHEMA_VERSION;
  readonly installationSimplyId: string;
  readonly integrationProviderAccountLinkSimplyId: string;
  readonly integrationInstallationOperationSimplyId: string;
  readonly eventSimplyId: string;
  readonly verifiedBodySha256: string;
  readonly outcome: 'CLEANED' | 'REPLAYED';
}

export interface HelloEndpointPathVerificationResponse {
  readonly schemaVersion: typeof HELLO_ENDPOINT_PATH_VERIFICATION_SCHEMA_VERSION;
  readonly integrationAppVersionEndpointSimplyId: string;
  readonly nonce: string;
  readonly requestSha256: string;
}

/** The only publisher and App whose endpoint-path challenges this receiver answers. */
export interface HelloEndpointVerificationAuthority {
  readonly integrationPublisherSimplyId: string;
  readonly integrationAppSimplyId: string;
}

export interface HelloRouterDependencies {
  readonly oauth: HelloOAuthClient;
  readonly state: HelloStateStore;
  readonly resolveWebhookKey: (kid: string) => Promise<HelloWebhookKeyBinding | null>;
  readonly eventTypes: readonly AppPlatformSubscriptionEventType[];
  readonly lifecycleEventTypes: readonly AppPlatformLifecycleEventType[];
  readonly endpointVerificationAuthority: HelloEndpointVerificationAuthority;
  readonly now?: () => number;
}

const json = (statusCode: number, body: Readonly<Record<string, unknown>>, headers: Record<string, string> = {}): HelloHostedResponse => ({
  statusCode,
  headers: { 'Cache-Control': 'no-store', 'Content-Type': 'application/json; charset=utf-8', ...headers },
  body: JSON.stringify(body),
});

const noContent = (statusCode: number, headers: Record<string, string> = {}): HelloHostedResponse => ({
  statusCode,
  headers: { 'Cache-Control': 'no-store', ...headers },
  body: '',
});

const redirect = (location: string, cookie?: string): HelloHostedResponse => noContent(303, {
  Location: location,
  ...(cookie ? { 'Set-Cookie': cookie } : {}),
  'Referrer-Policy': 'no-referrer',
});

const parseCookie = (header: string | undefined, name: string): string | undefined => {
  if (!header) return undefined;
  const matches = header.split(';').map((part) => part.trim()).filter((part) => part.startsWith(`${name}=`));
  if (matches.length !== 1) return undefined;
  return decodeURIComponent(matches[0]!.slice(name.length + 1));
};

const callbackCookie = (nonce: string): string =>
  `${CALLBACK_COOKIE}=${encodeURIComponent(nonce)}; Max-Age=600; Path=/oauth/simply360/callback; HttpOnly; Secure; SameSite=Lax`;
const clearCallbackCookie = (): string =>
  `${CALLBACK_COOKIE}=; Max-Age=0; Path=/oauth/simply360/callback; HttpOnly; Secure; SameSite=Lax`;

const textBody = (request: HelloHostedRequest): string => {
  if (request.body.byteLength > MAX_REQUEST_BODY_BYTES) throw new HelloRequestBodyError(413);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(request.body);
  } catch {
    throw new HelloRequestBodyError(400);
  }
};

const identityHeaders = (headers: HelloHostedRequest['headers']): WebhookV2IdentityHeaders => {
  return {
    eventId: headers['x-s360-event-id'],
    deliveryId: headers['x-s360-delivery-id'],
    attemptId: headers['x-s360-attempt-id'],
  };
};

export class HelloHostedRouter {
  private readonly now: () => number;

  public constructor(private readonly dependencies: HelloRouterDependencies) {
    this.now = dependencies.now ?? Date.now;
  }

  public async handle(request: HelloHostedRequest): Promise<HelloHostedResponse> {
    try {
      if (request.method === 'GET' && request.path === '/healthz') {
        return json(200, { status: 'ok' });
      }
      if (request.method === 'GET' && request.path === '/oauth/simply360/start') {
        const begun = await this.dependencies.oauth.begin();
        return redirect(begun.authorizationUrl, callbackCookie(begun.browserNonce));
      }
      if (request.method === 'GET' && request.path === '/oauth/simply360/callback') {
        return await this.oauthCallback(request);
      }
      // Simply360 proves control of each declared callback path with one
      // unsigned challenge before any signing key exists; every delivery is signed.
      if (request.method === 'POST' && (request.path === '/events/simply360' || request.path === '/lifecycle') && request.headers['x-s360-signature'] === undefined) {
        return this.endpointPathVerification(request);
      }
      if (request.method === 'POST' && (request.path === '/events/simply360' || request.path === '/lifecycle')) {
        return await this.signedEvent(request, request.path === '/lifecycle');
      }
      return json(404, { error: 'NOT_FOUND' });
    } catch (error) {
      if (error instanceof HelloRequestBodyError) return json(error.statusCode, { error: 'INVALID_REQUEST_BODY' });
      if (error instanceof HelloLifecycleFencedError) return json(409, { error: 'LIFECYCLE_FENCED' });
      if (request.method === 'POST' && (request.path === '/events/simply360' || request.path === '/lifecycle')) {
        return json(503, { error: 'DELIVERY_RETRY_REQUIRED' });
      }
      return json(400, { error: 'REQUEST_REJECTED' });
    }
  }

  private async oauthCallback(request: HelloHostedRequest): Promise<HelloHostedResponse> {
    const state = request.query.state;
    const code = request.query.code;
    const error = request.query.error;
    const browserNonce = parseCookie(request.headers.cookie, CALLBACK_COOKIE);
    if (!state || !browserNonce || (code === undefined) === (error === undefined)) {
      return json(400, { error: 'OAUTH_CALLBACK_REJECTED' }, { 'Set-Cookie': clearCallbackCookie() });
    }
    try {
      const completed = await this.dependencies.oauth.complete({
        state,
        browserNonce,
        ...(code === undefined ? { error: error! } : { code }),
      });
      return json(200, {
        outcome: 'CONNECTED',
        teamIntegrationSimplyId: completed.binding.teamIntegrationSimplyId,
        teamUserLinkSimplyId: completed.binding.teamUserLinkSimplyId,
        integrationInstallationGrantSimplyId: completed.binding.integrationInstallationGrantSimplyId,
      }, { 'Set-Cookie': clearCallbackCookie() });
    } catch (callbackError) {
      return json(
        callbackError instanceof HelloOAuthDeniedError ? 400 : 503,
        { error: callbackError instanceof HelloOAuthDeniedError ? 'OAUTH_DENIED' : 'OAUTH_COMPLETION_UNKNOWN' },
        { 'Set-Cookie': clearCallbackCookie() },
      );
    }
  }

  /**
   * Echo one Simply360 endpoint-path challenge. The exchange reads no secret,
   * writes no state, and answers only this receiver's own publisher and App;
   * any other unsigned body is an unsigned delivery and stays rejected.
   */
  private endpointPathVerification(request: HelloHostedRequest): HelloHostedResponse {
    if (request.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') {
      return json(415, { error: 'UNSUPPORTED_MEDIA_TYPE' });
    }
    const rawBody = textBody(request);
    let untrusted: unknown;
    try {
      untrusted = JSON.parse(rawBody) as unknown;
    } catch {
      return json(401, { error: 'INVALID_SIGNATURE' });
    }
    if (
      !untrusted ||
      typeof untrusted !== 'object' ||
      Array.isArray(untrusted) ||
      (untrusted as { schemaVersion?: unknown }).schemaVersion !== HELLO_ENDPOINT_PATH_VERIFICATION_SCHEMA_VERSION
    ) {
      return json(401, { error: 'INVALID_SIGNATURE' });
    }
    const parsed = EndpointPathVerificationRequestSchema.safeParse(untrusted);
    if (!parsed.success) return json(400, { error: 'INVALID_ENDPOINT_VERIFICATION' });
    const challenge: EndpointPathVerificationRequest = parsed.data;
    const now = this.now();
    const issuedAt = Date.parse(challenge.issuedAt);
    const expiresAt = Date.parse(challenge.expiresAt);
    if (
      expiresAt <= issuedAt ||
      expiresAt - issuedAt > MAX_ENDPOINT_PATH_VERIFICATION_TTL_MS ||
      now >= expiresAt ||
      issuedAt > now + MAX_ENDPOINT_PATH_VERIFICATION_CLOCK_SKEW_MS
    ) {
      return json(400, { error: 'INVALID_ENDPOINT_VERIFICATION' });
    }
    const authority = this.dependencies.endpointVerificationAuthority;
    if (
      challenge.integrationPublisherSimplyId !== authority.integrationPublisherSimplyId ||
      challenge.integrationAppSimplyId !== authority.integrationAppSimplyId
    ) {
      return json(403, { error: 'ENDPOINT_VERIFICATION_AUTHORITY_MISMATCH' });
    }
    const response: HelloEndpointPathVerificationResponse = {
      schemaVersion: HELLO_ENDPOINT_PATH_VERIFICATION_SCHEMA_VERSION,
      integrationAppVersionEndpointSimplyId: challenge.integrationAppVersionEndpointSimplyId,
      nonce: challenge.nonce,
      requestSha256: createHash('sha256').update(canonicalFlatStringJson(challenge), 'utf8').digest('hex'),
    };
    return json(200, { ...response });
  }

  private async signedEvent(request: HelloHostedRequest, lifecycle: boolean): Promise<HelloHostedResponse> {
    if (request.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') {
      return json(415, { error: 'UNSUPPORTED_MEDIA_TYPE' });
    }
    const rawBody = textBody(request);
    const signatureHeader = request.headers['x-s360-signature'] ?? '';
    const parsedHeader = parseWebhookV2SignatureHeader(signatureHeader);
    if (!parsedHeader.success) return json(401, { error: 'INVALID_SIGNATURE' });
    const binding = await this.dependencies.resolveWebhookKey(parsedHeader.header.kid);
    if (!binding) return json(401, { error: 'INVALID_SIGNATURE' });
    const verified = await verifyWebhookV2({
      rawBody,
      signatureHeader,
      keys: binding.keys,
      identityHeaders: identityHeaders(request.headers),
      now: this.now(),
    });
    if (!verified.ok) return json(401, { error: 'INVALID_SIGNATURE' });

    let occurrence: ReturnType<typeof parseEventOccurrence>;
    try {
      occurrence = parseEventOccurrence(JSON.parse(rawBody) as unknown);
    } catch {
      return json(400, { error: 'INVALID_EVENT' });
    }
    if (
      occurrence.eventSimplyId !== verified.delivery.eventId ||
      occurrence.teamSimplyId !== binding.teamSimplyId ||
      occurrence.teamIntegrationSimplyId !== binding.teamIntegrationSimplyId ||
      (lifecycle ? occurrence.protocolVersion !== 1 || !isLifecycleEvent(occurrence) : occurrence.protocolVersion !== 2 || isLifecycleEvent(occurrence)) ||
      (lifecycle
        ? !this.dependencies.lifecycleEventTypes.includes(occurrence.eventType as AppPlatformLifecycleEventType)
        : !this.dependencies.eventTypes.includes(occurrence.eventType as AppPlatformSubscriptionEventType))
    ) {
      return json(403, { error: 'EVENT_AUTHORITY_MISMATCH' });
    }

    const evidence = {
      eventSimplyId: occurrence.eventSimplyId,
      deliverySimplyId: verified.delivery.deliveryId,
      bodySha256: verified.delivery.bodySha256Hex,
    };
    if (occurrence.eventType === 'app.uninstalled') {
      const payload = APP_PLATFORM_EVENT_PAYLOAD_SCHEMA_BY_EVENT_TYPE['app.uninstalled'].parse(occurrence.payload);
      const result = await this.dependencies.state.fenceAndCleanupInstallation(occurrence.teamIntegrationSimplyId, evidence);
      const cleanupReceipt: HelloInstallationCleanupReceipt = {
        schemaVersion: HELLO_INSTALLATION_CLEANUP_RECEIPT_SCHEMA_VERSION,
        installationSimplyId: occurrence.teamIntegrationSimplyId,
        integrationInstallationOperationSimplyId: payload.integrationInstallationOperationSimplyId,
        eventSimplyId: occurrence.eventSimplyId,
        verifiedBodySha256: verified.delivery.bodySha256Hex,
        outcome: result.replayed ? 'REPLAYED' : 'CLEANED',
      };
      return json(200, {
        outcome: result.replayed ? 'DUPLICATE' : 'CLEANED',
        cleanupReceipt,
      });
    }
    if (occurrence.eventType === 'app.grant.revoked') {
      const payload = APP_PLATFORM_EVENT_PAYLOAD_SCHEMA_BY_EVENT_TYPE['app.grant.revoked'].parse(occurrence.payload);
      const result = await this.dependencies.state.fenceAndCleanupGrantAuthority(
        occurrence.teamIntegrationSimplyId,
        {
        grant: 'simply360',
        integrationInstallationGrantSimplyId: payload.grantSimplyId,
        },
        evidence,
      );
      return json(200, { outcome: result.replayed ? 'DUPLICATE' : 'CLEANED' });
    }
    if (occurrence.eventType === 'app.account-link.revoked') {
      const payload = APP_PLATFORM_EVENT_PAYLOAD_SCHEMA_BY_EVENT_TYPE['app.account-link.revoked'].parse(occurrence.payload);
      const result = await this.dependencies.state.fenceAndCleanupGrantAuthority(
        occurrence.teamIntegrationSimplyId,
        { grant: 'provider', integrationProviderAccountLinkSimplyId: payload.integrationProviderAccountLinkSimplyId },
        evidence,
      );
      const cleanupReceipt: HelloAccountLinkCleanupReceipt = {
        schemaVersion: HELLO_ACCOUNT_LINK_CLEANUP_RECEIPT_SCHEMA_VERSION,
        installationSimplyId: occurrence.teamIntegrationSimplyId,
        integrationProviderAccountLinkSimplyId: payload.integrationProviderAccountLinkSimplyId,
        integrationInstallationOperationSimplyId: payload.integrationInstallationOperationSimplyId,
        eventSimplyId: occurrence.eventSimplyId,
        verifiedBodySha256: verified.delivery.bodySha256Hex,
        outcome: result.replayed ? 'REPLAYED' : 'CLEANED',
      };
      return json(200, {
        outcome: result.replayed ? 'DUPLICATE' : 'CLEANED',
        cleanupReceipt,
      });
    }

    const outcome = await this.dependencies.state.recordWebhookDelivery(occurrence.teamIntegrationSimplyId, evidence);
    return json(200, { outcome });
  }
}
