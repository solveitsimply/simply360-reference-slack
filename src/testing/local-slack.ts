import type { SlackClient } from '../slack.js';
import type { SendToChannelInput, SendToChannelOutput } from '../contracts.js';

export class LocalSlackDouble implements SlackClient {
  public readonly messages: Array<SendToChannelInput & { readonly messageTimestamp: string; readonly idempotencyKey: string }> = [];

  public async postMessage(input: SendToChannelInput, idempotencyKey: string): Promise<SendToChannelOutput> {
    const existing = this.messages.find((message) => message.idempotencyKey === idempotencyKey);
    if (existing) return { channel: existing.channel, messageTimestamp: existing.messageTimestamp };
    const messageTimestamp = `${1_800_000_000 + this.messages.length}.000001`;
    this.messages.push({ ...input, messageTimestamp, idempotencyKey });
    return { channel: input.channel, messageTimestamp };
  }
}
