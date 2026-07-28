import {
  parseEventOccurrence,
  parseSendToChannelInput,
  type RemoteTriggerPublisher,
  type SendToChannelInput,
  type SendToChannelOutput,
} from './contracts.js';
import type { SlackClient } from './slack.js';
import { verifySlackSignature } from './slack.js';
import { verifyWebhookV2, type WebhookIdentityHeaders, type WebhookSigningKey } from './webhook-v2.js';

export interface IdempotencyStore<T> {
  run(key: string, operation: () => Promise<T>): Promise<{ readonly replayed: boolean; readonly value: T }>;
}

export class MemoryIdempotencyStore<T> implements IdempotencyStore<T> {
  private readonly values = new Map<string, Promise<T>>();

  public async run(key: string, operation: () => Promise<T>): Promise<{ readonly replayed: boolean; readonly value: T }> {
    const existing = this.values.get(key);
    if (existing !== undefined) return { replayed: true, value: await existing };
    const pending = operation();
    this.values.set(key, pending);
    try {
      return { replayed: false, value: await pending };
    } catch (error) {
      if (this.values.get(key) === pending) this.values.delete(key);
      throw error;
    }
  }
}

export class SlackReferenceRuntime {
  public constructor(
    private readonly config: {
      readonly teamSimplyId: string;
      readonly teamIntegrationSimplyId: string;
      readonly slackTeamId: string;
      readonly eventSigningKeys: readonly WebhookSigningKey[];
      readonly slackSigningSecrets: readonly string[];
      readonly eventChannel: string;
    },
    private readonly slack: SlackClient,
    private readonly triggerPublisher: RemoteTriggerPublisher,
    private readonly deliveryDedupe: IdempotencyStore<string>,
    private readonly actionDedupe: IdempotencyStore<SendToChannelOutput>,
    private readonly triggerDedupe: IdempotencyStore<string>,
  ) {}

  public async receiveEvent(input: {
    readonly rawBody: string | Uint8Array;
    readonly signatureHeader: string;
    readonly identityHeaders?: WebhookIdentityHeaders;
    readonly now?: Date | number;
  }): Promise<'DELIVERED' | 'DUPLICATE'> {
    const verified = verifyWebhookV2({ ...input, keys: this.config.eventSigningKeys });
    if (!verified.ok) throw new Error(`Simply360 webhook rejected: ${verified.code}`);
    const occurrence = parseEventOccurrence(
      JSON.parse(typeof input.rawBody === 'string' ? input.rawBody : Buffer.from(input.rawBody).toString('utf8')) as unknown,
    );
    if (
      occurrence.eventSimplyId !== verified.delivery.eventId ||
      occurrence.teamSimplyId !== this.config.teamSimplyId ||
      occurrence.teamIntegrationSimplyId !== this.config.teamIntegrationSimplyId
    ) {
      throw new Error('Simply360 occurrence does not belong to this installation');
    }
    const dedupeKey = `${verified.delivery.eventId}:${verified.delivery.deliveryId}`;
    const result = await this.deliveryDedupe.run(dedupeKey, async () => {
      const message = [
        `Simply360 event: ${occurrence.eventType}`,
        `installation: ${occurrence.teamIntegrationSimplyId}`,
        `event: ${occurrence.eventSimplyId}`,
      ].join('\n');
      await this.slack.postMessage({ channel: this.config.eventChannel, text: message }, dedupeKey);
      return verified.delivery.attemptId;
    });
    return result.replayed ? 'DUPLICATE' : 'DELIVERED';
  }

  /**
   * Provider-side behavior for the reviewed `send-to-channel` action.
   *
   * The public platform currently publishes the declaration but not the
   * REMOTE_ACTION_V1 invocation/result wire schemas. Keep HTTP binding outside
   * this method until those public schemas exist; callers must authenticate and
   * bind the exact installation before invoking it.
   */
  public async sendToChannel(untrustedInput: unknown, idempotencyKey: string): Promise<SendToChannelOutput> {
    if (!/^[A-Za-z0-9._:-]{16,200}$/u.test(idempotencyKey)) throw new Error('idempotency key is invalid');
    const result = await this.actionDedupe.run(idempotencyKey, () =>
      this.slack.postMessage(parseSendToChannelInput(untrustedInput), idempotencyKey),
    );
    return result.value;
  }

  public async receiveSlackRequest(input: {
    readonly rawBody: string | Uint8Array;
    readonly signature: string;
    readonly timestamp: string;
    readonly now?: Date | number;
  }): Promise<{ readonly challenge?: string; readonly outcome?: 'IGNORED' | 'TRIGGERED' | 'DUPLICATE' }> {
    const verification = verifySlackSignature({ ...input, signingSecrets: this.config.slackSigningSecrets });
    if (!verification.ok) throw new Error(`Slack request rejected: ${verification.code}`);
    const raw = typeof input.rawBody === 'string' ? input.rawBody : Buffer.from(input.rawBody).toString('utf8');
    if (Buffer.byteLength(raw) > 256 * 1024) throw new Error('Slack request exceeds the byte limit');
    const form = new URLSearchParams(raw);
    if ([...form.keys()].some((key) => key !== 'payload') || !form.has('payload')) {
      throw new Error('Slack request form is invalid');
    }
    const payloadText = form.get('payload') as string;
    if (Buffer.byteLength(payloadText) > 128 * 1024) throw new Error('Slack interaction payload exceeds the byte limit');
    const parsed = JSON.parse(payloadText) as unknown;
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('Slack interaction body is invalid');
    const body = parsed as Record<string, unknown>;
    if (
      body.type !== 'message_action' ||
      body.callback_id !== 's360_create_record' ||
      typeof body.trigger_id !== 'string' ||
      typeof body.team !== 'object' ||
      body.team === null ||
      typeof body.channel !== 'object' ||
      body.channel === null ||
      typeof body.user !== 'object' ||
      body.user === null ||
      typeof body.message !== 'object' ||
      body.message === null
    ) {
      throw new Error('unsupported Slack interaction');
    }
    const team = body.team as Record<string, unknown>;
    const channel = body.channel as Record<string, unknown>;
    const user = body.user as Record<string, unknown>;
    const message = body.message as Record<string, unknown>;
    if (
      typeof team.id !== 'string' ||
      !/^[ET][A-Z0-9]{8,20}$/u.test(team.id) ||
      typeof channel.id !== 'string' ||
      typeof user.id !== 'string' ||
      typeof message.ts !== 'string' ||
      typeof message.text !== 'string' ||
      message.text.length < 1 ||
      message.text.length > 3_000
    ) {
      throw new Error('Slack message shortcut is invalid');
    }
    if (team.id !== this.config.slackTeamId) {
      throw new Error('Slack interaction does not belong to this installation');
    }
    const dedupeKey = `slack:${team.id}:${channel.id}:${message.ts}:s360_create_record`;
    const result = await this.triggerDedupe.run(dedupeKey, async () => {
      await this.triggerPublisher.publishCreateRecordFromMessage(
        {
          slackTeam: team.id as string,
          channel: channel.id as string,
          messageTimestamp: message.ts as string,
          sender: user.id as string,
          text: message.text as string,
        },
        dedupeKey,
      );
      return message.ts as string;
    });
    return { outcome: result.replayed ? 'DUPLICATE' : 'TRIGGERED' };
  }
}
