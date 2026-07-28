export const SIMPLY_ID_PATTERN = /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/u;
export const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/u;
export const DECLARATION_KEY_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u;

export type OAuthScope =
  | 'schema:read'
  | 'records:read'
  | 'records:write'
  | 'offline_access';

export interface OAuthTokenSet {
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly tokenType: 'Bearer';
  readonly expiresIn?: number;
  readonly scope: readonly OAuthScope[];
}

export interface EventOccurrence {
  readonly eventSimplyId: string;
  readonly teamSimplyId: string;
  readonly teamIntegrationSimplyId: string;
  readonly eventType: string;
  readonly protocolVersion: 1 | 2;
  readonly payloadSchemaId: string;
  readonly payloadSchemaVersion: 1;
  readonly occurredAt: string;
  readonly payload: Readonly<Record<string, unknown>>;
}

export interface SendToChannelInput {
  readonly channel: string;
  readonly text: string;
}

export interface SendToChannelOutput {
  readonly channel: string;
  readonly messageTimestamp: string;
}

export interface CreateRecordFromMessageInput {
  readonly slackTeam: string;
  readonly channel: string;
  readonly messageTimestamp: string;
  readonly sender: string;
  readonly text: string;
}

export interface RemoteTriggerPublisher {
  publishCreateRecordFromMessage(input: CreateRecordFromMessageInput, idempotencyKey: string): Promise<void>;
}

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;

const assertExactKeys = (value: Record<string, unknown>, allowed: readonly string[], label: string): void => {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) throw new Error(`${label} contains unknown property ${JSON.stringify(key)}`);
  }
  for (const key of allowed) {
    if (!(key in value)) throw new Error(`${label} is missing property ${JSON.stringify(key)}`);
  }
};

export function assertSimplyId(value: unknown, field: string): asserts value is string {
  if (typeof value !== 'string' || !SIMPLY_ID_PATTERN.test(value)) {
    throw new Error(`${field} must be a canonical uppercase Simply ID`);
  }
}

export const parseEventOccurrence = (input: unknown): EventOccurrence => {
  if (!isPlainRecord(input)) throw new Error('event occurrence must be a plain object');
  assertExactKeys(
    input,
    [
      'eventSimplyId',
      'teamSimplyId',
      'teamIntegrationSimplyId',
      'eventType',
      'protocolVersion',
      'payloadSchemaId',
      'payloadSchemaVersion',
      'occurredAt',
      'payload',
    ],
    'event occurrence',
  );
  assertSimplyId(input.eventSimplyId, 'eventSimplyId');
  assertSimplyId(input.teamSimplyId, 'teamSimplyId');
  assertSimplyId(input.teamIntegrationSimplyId, 'teamIntegrationSimplyId');
  if (typeof input.eventType !== 'string' || input.eventType.length < 1 || input.eventType.length > 120) {
    throw new Error('eventType is invalid');
  }
  if (input.protocolVersion !== 1 && input.protocolVersion !== 2) throw new Error('protocolVersion is invalid');
  if (typeof input.payloadSchemaId !== 'string' || !/^simply360\.[a-z0-9.-]+\/v[1-9]\d*$/u.test(input.payloadSchemaId)) {
    throw new Error('payloadSchemaId is invalid');
  }
  if (input.payloadSchemaVersion !== 1) throw new Error('payloadSchemaVersion is invalid');
  if (typeof input.occurredAt !== 'string' || !Number.isFinite(Date.parse(input.occurredAt))) {
    throw new Error('occurredAt is invalid');
  }
  if (!isPlainRecord(input.payload)) throw new Error('payload must be a plain object');
  if (input.payload.eventType !== input.eventType) throw new Error('payload eventType must match occurrence eventType');
  return input as unknown as EventOccurrence;
};

export const parseSendToChannelInput = (input: unknown): SendToChannelInput => {
  if (!isPlainRecord(input)) throw new Error('send-to-channel input must be a plain object');
  assertExactKeys(input, ['channel', 'text'], 'send-to-channel input');
  if (typeof input.channel !== 'string' || !/^[CG][A-Z0-9]{8,20}$/u.test(input.channel)) {
    throw new Error('channel must be a public or private Slack channel ID');
  }
  if (typeof input.text !== 'string' || input.text.length < 1 || input.text.length > 3_000) {
    throw new Error('text must contain 1 to 3000 characters');
  }
  if (/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(input.text)) {
    throw new Error('text contains a forbidden control or bidi character');
  }
  return { channel: input.channel, text: input.text };
};
