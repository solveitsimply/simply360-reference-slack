import { createHmac, timingSafeEqual } from 'node:crypto';

import { parseSendToChannelInput, type SendToChannelInput, type SendToChannelOutput } from './contracts.js';
import { assertJsonResponse, readBoundedResponseText } from './http.js';

const ROTATING_SLACK_BOT_TOKEN_PATTERN = /^xoxe\.xoxb-[A-Za-z0-9-]{10,}$/u;

export interface SlackClient {
  postMessage(input: SendToChannelInput, idempotencyKey: string): Promise<SendToChannelOutput>;
}

export interface SlackSignatureVerification {
  readonly ok: boolean;
  readonly code?: 'MALFORMED_SIGNATURE' | 'SIGNATURE_MISMATCH' | 'TIMESTAMP_OUT_OF_WINDOW';
}

export const verifySlackSignature = (input: {
  readonly rawBody: string | Uint8Array;
  readonly signature: string;
  readonly timestamp: string;
  readonly signingSecrets: readonly string[];
  readonly now?: Date | number;
}): SlackSignatureVerification => {
  if (!/^v0=[a-f0-9]{64}$/u.test(input.signature) || !/^(0|[1-9][0-9]{0,18})$/u.test(input.timestamp)) {
    return { ok: false, code: 'MALFORMED_SIGNATURE' };
  }
  const timestamp = Number(input.timestamp);
  if (!Number.isSafeInteger(timestamp)) return { ok: false, code: 'MALFORMED_SIGNATURE' };
  const nowMs = input.now instanceof Date ? input.now.getTime() : (input.now ?? Date.now());
  if (Math.abs(Math.floor(nowMs / 1000) - timestamp) > 300) return { ok: false, code: 'TIMESTAMP_OUT_OF_WINDOW' };
  if (
    input.signingSecrets.length < 1 ||
    input.signingSecrets.length > 2 ||
    new Set(input.signingSecrets).size !== input.signingSecrets.length ||
    input.signingSecrets.some((secret) => Buffer.byteLength(secret) < 16)
  ) {
    throw new Error('accept exactly one current Slack signing secret and an optional unique previous secret');
  }
  const raw = typeof input.rawBody === 'string' ? Buffer.from(input.rawBody) : Buffer.from(input.rawBody);
  const provided = Buffer.from(input.signature);
  const matches = input.signingSecrets
    .map((secret) =>
      Buffer.from(
        `v0=${createHmac('sha256', secret)
          .update(Buffer.concat([Buffer.from(`v0:${timestamp}:`), raw]))
          .digest('hex')}`,
      ),
    )
    .map((expected) => expected.length === provided.length && timingSafeEqual(expected, provided))
    .some(Boolean);
  if (!matches) {
    return { ok: false, code: 'SIGNATURE_MISMATCH' };
  }
  return { ok: true };
};

export class SlackWebApiClient implements SlackClient {
  public constructor(
    private readonly botToken: string,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    if (!ROTATING_SLACK_BOT_TOKEN_PATTERN.test(botToken)) throw new Error('Slack rotating bot token has an invalid shape');
  }

  public async postMessage(untrustedInput: SendToChannelInput, idempotencyKey: string): Promise<SendToChannelOutput> {
    const input = parseSendToChannelInput(untrustedInput);
    if (!/^[A-Za-z0-9._:-]{16,200}$/u.test(idempotencyKey)) throw new Error('Slack idempotency key is invalid');
    const digest = createHmac('sha256', 'simply360-reference-slack/client-msg-id').update(idempotencyKey).digest('hex');
    const clientMessageId = `${digest.slice(0, 8)}-${digest.slice(8, 12)}-4${digest.slice(13, 16)}-a${digest.slice(17, 20)}-${digest.slice(20, 32)}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    try {
      const response = await this.fetchImpl('https://slack.com/api/chat.postMessage', {
        method: 'POST',
        redirect: 'error',
        signal: controller.signal,
        headers: {
          Authorization: `Bearer ${this.botToken}`,
          'Content-Type': 'application/json; charset=utf-8',
          Accept: 'application/json',
        },
        body: JSON.stringify({ ...input, client_msg_id: clientMessageId }),
      });
      assertJsonResponse(response);
      const text = await readBoundedResponseText(response);
      const parsed = JSON.parse(text) as unknown;
      if (
        !response.ok ||
        typeof parsed !== 'object' ||
        parsed === null ||
        (parsed as Record<string, unknown>).ok !== true ||
        typeof (parsed as Record<string, unknown>).channel !== 'string' ||
        typeof (parsed as Record<string, unknown>).ts !== 'string'
      ) {
        throw new Error(`Slack chat.postMessage failed with HTTP ${response.status}`);
      }
      return {
        channel: (parsed as Record<string, unknown>).channel as string,
        messageTimestamp: (parsed as Record<string, unknown>).ts as string,
      };
    } finally {
      clearTimeout(timeout);
    }
  }
}
