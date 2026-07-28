import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import { SHA256_HEX_PATTERN, SIMPLY_ID_PATTERN } from './contracts.js';

export const WEBHOOK_V2_SIGNATURE_HEADER_NAME = 'X-S360-Signature';
export const WEBHOOK_V2_DEFAULT_REPLAY_TOLERANCE_SECONDS = 300;

export interface WebhookSigningKey {
  readonly kid: string;
  readonly secret: string | Uint8Array;
}

export interface WebhookIdentityHeaders {
  readonly eventId?: string;
  readonly deliveryId?: string;
  readonly attemptId?: string;
  readonly timestampUnixSeconds?: number;
}

export interface VerifiedWebhookDelivery {
  readonly kid: string;
  readonly eventId: string;
  readonly deliveryId: string;
  readonly attemptId: string;
  readonly timestampUnixSeconds: number;
  readonly bodySha256Hex: string;
}

export type WebhookVerificationResult =
  | { readonly ok: true; readonly delivery: VerifiedWebhookDelivery }
  | {
      readonly ok: false;
      readonly code:
        | 'MALFORMED_SIGNATURE'
        | 'UNSUPPORTED_VERSION'
        | 'DUPLICATE_FIELD'
        | 'UNKNOWN_FIELD'
        | 'MISSING_FIELD'
        | 'INVALID_FIELD_VALUE'
        | 'INVALID_KEY_SET'
        | 'UNKNOWN_KEY'
        | 'SIGNATURE_MISMATCH'
        | 'TIMESTAMP_OUT_OF_WINDOW'
        | 'IDENTITY_HEADER_MISMATCH';
      readonly message: string;
    };

interface ParsedHeader {
  readonly kid: string;
  readonly timestampUnixSeconds: number;
  readonly eventId: string;
  readonly deliveryId: string;
  readonly attemptId: string;
  readonly hmacSha256Hex: string;
}

const KID_PATTERN = /^[A-Za-z0-9._:@+/=-]{1,200}$/u;
const HEADER_FIELDS = ['kid', 't', 'e', 'd', 'a', 'h'] as const;
type HeaderField = (typeof HEADER_FIELDS)[number];

const rejected = (
  code: Exclude<WebhookVerificationResult, { ok: true }>['code'],
  message: string,
): Exclude<WebhookVerificationResult, { ok: true }> => ({ ok: false, code, message });

const validKey = (key: WebhookSigningKey): boolean =>
  KID_PATTERN.test(key.kid) && !key.kid.includes(';') && Buffer.byteLength(key.secret) >= 32;

const parseHeader = (raw: string): ParsedHeader | Exclude<WebhookVerificationResult, { ok: true }> => {
  const segments = raw.split(';');
  if (segments.length < 2) return rejected('MALFORMED_SIGNATURE', 'signature must be semicolon-delimited');
  if (segments[0] !== 'v2') return rejected('UNSUPPORTED_VERSION', 'only signature version v2 is accepted');
  const fields = new Map<HeaderField, string>();
  for (const segment of segments.slice(1)) {
    const index = segment.indexOf('=');
    if (index <= 0) return rejected('MALFORMED_SIGNATURE', 'signature contains a malformed field');
    const key = segment.slice(0, index);
    if (!HEADER_FIELDS.includes(key as HeaderField)) return rejected('UNKNOWN_FIELD', `unknown signature field ${key}`);
    if (fields.has(key as HeaderField)) return rejected('DUPLICATE_FIELD', `duplicate signature field ${key}`);
    fields.set(key as HeaderField, segment.slice(index + 1));
  }
  for (const key of HEADER_FIELDS) {
    if (!fields.has(key)) return rejected('MISSING_FIELD', `missing signature field ${key}`);
  }
  const kid = fields.get('kid') as string;
  const timestamp = fields.get('t') as string;
  const eventId = fields.get('e') as string;
  const deliveryId = fields.get('d') as string;
  const attemptId = fields.get('a') as string;
  const hmacSha256Hex = fields.get('h') as string;
  if (
    !KID_PATTERN.test(kid) ||
    !/^(0|[1-9][0-9]{0,18})$/u.test(timestamp) ||
    !Number.isSafeInteger(Number(timestamp)) ||
    !SIMPLY_ID_PATTERN.test(eventId) ||
    !SIMPLY_ID_PATTERN.test(deliveryId) ||
    !SIMPLY_ID_PATTERN.test(attemptId) ||
    !SHA256_HEX_PATTERN.test(hmacSha256Hex)
  ) {
    return rejected('INVALID_FIELD_VALUE', 'signature contains an invalid field value');
  }
  return { kid, timestampUnixSeconds: Number(timestamp), eventId, deliveryId, attemptId, hmacSha256Hex };
};

export const sha256Hex = (rawBody: string | Uint8Array): string =>
  createHash('sha256').update(rawBody).digest('hex');

export const buildWebhookV2SigningInput = (input: {
  readonly timestampUnixSeconds: number;
  readonly eventId: string;
  readonly deliveryId: string;
  readonly attemptId: string;
  readonly bodySha256Hex: string;
}): string =>
  [
    'S360-HMAC-V2',
    String(input.timestampUnixSeconds),
    input.eventId,
    input.deliveryId,
    input.attemptId,
    input.bodySha256Hex,
  ].join('\n');

export const signWebhookV2 = (
  rawBody: string | Uint8Array,
  fields: Omit<ParsedHeader, 'hmacSha256Hex' | 'kid'>,
  key: WebhookSigningKey,
): string => {
  if (
    !validKey(key) ||
    !Number.isSafeInteger(fields.timestampUnixSeconds) ||
    fields.timestampUnixSeconds < 0 ||
    !SIMPLY_ID_PATTERN.test(fields.eventId) ||
    !SIMPLY_ID_PATTERN.test(fields.deliveryId) ||
    !SIMPLY_ID_PATTERN.test(fields.attemptId)
  ) {
    throw new Error('webhook signing fields or key are invalid');
  }
  const bodySha256Hex = sha256Hex(rawBody);
  const hmacSha256Hex = createHmac('sha256', key.secret)
    .update(buildWebhookV2SigningInput({ ...fields, bodySha256Hex }))
    .digest('hex');
  return `v2;kid=${key.kid};t=${fields.timestampUnixSeconds};e=${fields.eventId};d=${fields.deliveryId};a=${fields.attemptId};h=${hmacSha256Hex}`;
};

export const verifyWebhookV2 = (options: {
  readonly rawBody: string | Uint8Array;
  readonly signatureHeader: string;
  readonly keys: readonly WebhookSigningKey[];
  readonly now?: Date | number;
  readonly toleranceSeconds?: number;
  readonly identityHeaders?: WebhookIdentityHeaders;
}): WebhookVerificationResult => {
  const parsed = parseHeader(options.signatureHeader);
  if ('ok' in parsed) return parsed;
  if (
    options.keys.length < 1 ||
    options.keys.length > 2 ||
    new Set(options.keys.map((key) => key.kid)).size !== options.keys.length ||
    options.keys.some((key) => !validKey(key))
  ) {
    return rejected('INVALID_KEY_SET', 'accept exactly a current key and optional unique overlapping previous key');
  }
  const key = options.keys.find((candidate) => candidate.kid === parsed.kid);
  if (!key) return rejected('UNKNOWN_KEY', 'signature key is not accepted');
  const bodySha256Hex = sha256Hex(options.rawBody);
  const expected = createHmac('sha256', key.secret)
    .update(buildWebhookV2SigningInput({ ...parsed, bodySha256Hex }))
    .digest();
  const provided = Buffer.from(parsed.hmacSha256Hex, 'hex');
  if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
    return rejected('SIGNATURE_MISMATCH', 'HMAC signature does not match');
  }
  const nowMs = options.now instanceof Date ? options.now.getTime() : (options.now ?? Date.now());
  const tolerance = options.toleranceSeconds ?? WEBHOOK_V2_DEFAULT_REPLAY_TOLERANCE_SECONDS;
  if (Math.abs(Math.floor(nowMs / 1000) - parsed.timestampUnixSeconds) > tolerance) {
    return rejected('TIMESTAMP_OUT_OF_WINDOW', 'signature timestamp is outside the replay window');
  }
  const identity = options.identityHeaders;
  if (
    (identity?.eventId !== undefined && identity.eventId !== parsed.eventId) ||
    (identity?.deliveryId !== undefined && identity.deliveryId !== parsed.deliveryId) ||
    (identity?.attemptId !== undefined && identity.attemptId !== parsed.attemptId) ||
    (identity?.timestampUnixSeconds !== undefined && identity.timestampUnixSeconds !== parsed.timestampUnixSeconds)
  ) {
    return rejected('IDENTITY_HEADER_MISMATCH', 'plaintext identity headers disagree with the signed identity');
  }
  return { ok: true, delivery: { ...parsed, bodySha256Hex } };
};
