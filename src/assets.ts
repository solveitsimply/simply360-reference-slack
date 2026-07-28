import { createHash } from 'node:crypto';

import {
  SLACK_EVENT_DESTINATION_EVENT_TYPES,
  SLACK_LIFECYCLE_EVENT_TYPES,
} from './contracts.js';

const REPOSITORY_URL = 'https://github.com/solveitsimply/simply360-reference-slack';
const RUNTIME_ORIGIN = 'https://reference-slack.dev.simply360.app';

const sortJson = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(sortJson);
  if (typeof value !== 'object' || value === null) return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, child]) => [key, sortJson(child)]),
  );
};

export const canonicalizeJson = (value: unknown): string => JSON.stringify(sortJson(value));
export const canonicalJsonSha256 = (value: unknown): string =>
  createHash('sha256').update(canonicalizeJson(value)).digest('hex');

export const assertExactAssetSource = (input: {
  readonly requestedCommit: string;
  readonly checkedOutCommit: string;
  readonly worktreeIsClean: boolean;
}): void => {
  if (!/^[a-f0-9]{40}$/u.test(input.requestedCommit)) {
    throw new Error('sourceCommit must be the exact lowercase 40-character Git SHA');
  }
  if (input.requestedCommit !== input.checkedOutCommit) {
    throw new Error('sourceCommit must match the checked-out Git commit');
  }
  if (!input.worktreeIsClean) {
    throw new Error('reference assets must be generated from a clean Git worktree');
  }
};

export const slackMessageLogBlueprintDefinition = Object.freeze({
  schemaVersion: 'simply360.external-blueprint/v1',
  collections: [
    {
      collectionKey: 'slack-message',
      label: { en: 'Slack message' },
      description: { en: 'A Slack message explicitly submitted through the installed remote trigger.' },
      lifecycleOwner: 'INTEGRATION',
      recordLifecycle: 'ACTIVE_ONLY',
      calculatedName: { kind: 'FIELD', fieldKey: 'message-text' },
      fields: [
        { fieldKey: 'channel', label: { en: 'Slack channel' }, required: true, kind: 'TEXT', maxLength: 32 },
        { fieldKey: 'message-text', label: { en: 'Message' }, required: true, kind: 'TEXT_AREA', maxLength: 3_000 },
        { fieldKey: 'message-timestamp', label: { en: 'Slack message timestamp' }, required: true, kind: 'TEXT', maxLength: 32 },
        { fieldKey: 'sender', label: { en: 'Slack sender' }, required: true, kind: 'TEXT', maxLength: 32 },
      ],
      sharedContractKeys: [],
    },
  ],
  smartCollections: [],
  dataViews: [
    {
      dataViewKey: 'recent-slack-messages',
      collectionKey: 'slack-message',
      label: { en: 'Slack messages' },
      visibility: 'INTERNAL',
      presentation: 'TABLE',
      fieldKeys: ['message-text', 'channel', 'sender', 'message-timestamp'],
      sort: [{ fieldKey: 'message-timestamp', direction: 'DESC' }],
    },
  ],
  reports: [],
  labels: [{ labelKey: 'install-title', text: { en: 'Install Slack message log' } }],
  sharedCollectionContracts: [],
  mappings: [],
  options: [],
  lifecycle: [
    {
      resourceType: 'COLLECTION',
      collectionKey: 'slack-message',
      owner: 'INTEGRATION',
      uninstallBehavior: 'PROMPT_SOFT_DELETE',
    },
    {
      resourceType: 'DATA_VIEW',
      dataViewKey: 'recent-slack-messages',
      owner: 'INTEGRATION',
      uninstallBehavior: 'PRESERVE',
    },
  ],
});

export const buildReferenceAssets = (sourceCommit: string): {
  readonly blueprintPackage: Readonly<Record<string, unknown>>;
  readonly appManifest: Readonly<Record<string, unknown>>;
} => {
  if (!/^[a-f0-9]{40}$/u.test(sourceCommit)) throw new Error('sourceCommit must be the exact lowercase 40-character Git SHA');
  const definitionSha256 = canonicalJsonSha256(slackMessageLogBlueprintDefinition);
  const blueprintPackage = {
    schemaVersion: 'simply360.external-blueprint-package/v1',
    publisherSlug: 'simply360-reference',
    packageKey: 'slack-message-log',
    semanticVersion: '0.1.0',
    displayName: 'Slack message log',
    summary: 'Structural schema for messages explicitly submitted from the Slack reference integration.',
    license: 'Apache-2.0',
    support: {
      supportUrl: `${REPOSITORY_URL}/blob/dev/README.md`,
      escalationEmail: 'support@simply360.app',
    },
    compatibility: { minimumPlatformVersion: '1.0.0' },
    dependencies: [],
    definition: slackMessageLogBlueprintDefinition,
    definitionSha256,
    provenance: { sourceRepository: REPOSITORY_URL, sourceCommit },
  };
  const blueprintPackageSha256 = canonicalJsonSha256(blueprintPackage);
  const appManifest = {
    schemaVersion: 'simply360.app-manifest/v1',
    app: {
      slug: 'simply360-reference-slack',
      semanticVersion: '0.1.0',
      displayName: 'Simply360 Reference for Slack',
      summary: 'Reference event destination, remote action and signed inbound trigger for Slack.',
      supportUrl: `${REPOSITORY_URL}/blob/dev/README.md`,
      privacyUrl: `${REPOSITORY_URL}/blob/dev/docs/privacy.md`,
      termsUrl: `${REPOSITORY_URL}/blob/dev/docs/terms.md`,
    },
    oauth: {
      accountBindingModes: ['team', 'user'],
      perUserLinkMultiplicity: 'ONE_PER_USER',
      clients: [
        {
          clientKey: 'server',
          clientType: 'SERVER',
          tokenEndpointAuthMethod: 'CLIENT_SECRET_BASIC',
          grantModes: ['teamInstallation', 'userDelegated'],
          redirectUris: [`${RUNTIME_ORIGIN}/oauth/simply360/callback`],
          scopes: ['schema:read', 'records:read', 'records:write', 'offline_access'],
          audience: 'urn:simply360:public-api',
          resource: 'urn:simply360:team-api',
        },
      ],
    },
    capabilities: [
      'RECORD_API',
      'EVENT_DESTINATION',
      'REMOTE_ACTION_PROVIDER',
      'REMOTE_TRIGGER_PROVIDER',
      'EXTERNAL_BLUEPRINT_PACKAGE',
    ].map((capabilityKey) => ({ capabilityKey, registryVersion: 1, configuration: {} })),
    eventDestinations: [
      {
        endpointKey: 'events',
        exactUrl: `${RUNTIME_ORIGIN}/events/simply360`,
        protocolVersion: 2,
        eventTypes: [...SLACK_EVENT_DESTINATION_EVENT_TYPES],
        filters: {},
      },
    ],
    remoteActions: [
      {
        actionKey: 'send-to-channel',
        endpointKey: 'send-to-channel-action',
        displayName: 'Send to Slack channel',
        description: 'Post bounded plain text to an explicitly selected Slack channel.',
        exactUrl: `${RUNTIME_ORIGIN}/actions/send-to-channel`,
        protocolVersion: 1,
        executionMode: 'SYNCHRONOUS',
        timeoutSeconds: 10,
        idempotency: 'REQUIRED',
        inputSchema: {
          type: 'object',
          properties: {
            channel: { type: 'string', title: 'Slack channel', minLength: 9, maxLength: 21 },
            text: { type: 'string', title: 'Message', minLength: 1, maxLength: 3_000 },
          },
          required: ['channel', 'text'],
          additionalProperties: false,
        },
        outputSchema: {
          type: 'object',
          properties: {
            channel: { type: 'string', minLength: 9, maxLength: 21 },
            messageTimestamp: { type: 'string', minLength: 12, maxLength: 32 },
          },
          required: ['channel', 'messageTimestamp'],
          additionalProperties: false,
        },
        secretReferences: [{ secretReferenceKey: 'slack-bot-token', purpose: 'Post approved messages to Slack.' }],
      },
    ],
    remoteTriggers: [
      {
        triggerKey: 'create-record-from-message',
        displayName: 'Create record from Slack message',
        description: 'Create one record from an explicitly submitted Slack message.',
        protocolVersion: 1,
        idempotency: 'REQUIRED',
        rateLimitPerMinute: 60,
        inputSchema: {
          type: 'object',
          properties: {
            slackTeam: { type: 'string', minLength: 9, maxLength: 21 },
            channel: { type: 'string', minLength: 9, maxLength: 21 },
            messageTimestamp: { type: 'string', minLength: 3, maxLength: 32 },
            sender: { type: 'string', minLength: 9, maxLength: 21 },
            text: { type: 'string', minLength: 1, maxLength: 3_000 },
          },
          required: ['slackTeam', 'channel', 'messageTimestamp', 'sender', 'text'],
          additionalProperties: false,
        },
      },
    ],
    blueprintPackages: [
      {
        packageKey: 'slack-message-log',
        version: '0.1.0',
        sha256: blueprintPackageSha256,
        required: false,
        installOrder: 0,
      },
    ],
    dataAccess: {
      classifications: ['TEAM_OPERATIONAL'],
      purpose: 'Post reference-only event summaries and create records only when explicitly triggered.',
      retention: 'UNTIL_UNINSTALL',
      exportBehavior: 'AVAILABLE_ON_REQUEST',
      deletionBehavior: 'AVAILABLE_ON_REQUEST',
    },
    lifecycle: {
      setupLaunchUrl: `${RUNTIME_ORIGIN}/setup`,
      notifications: {
        endpointKey: 'lifecycle',
        exactUrl: `${RUNTIME_ORIGIN}/lifecycle`,
        protocolVersion: 1,
        eventTypes: [...SLACK_LIFECYCLE_EVENT_TYPES],
      },
    },
    support: {
      owner: 'PUBLISHER',
      escalationEmail: 'support@simply360.app',
      documentationUrl: `${REPOSITORY_URL}/blob/dev/README.md`,
      incidentUrl: `${REPOSITORY_URL}/security`,
      deprecationPolicyUrl: `${REPOSITORY_URL}/blob/dev/docs/deprecation.md`,
    },
    provenance: { sourceRepository: REPOSITORY_URL, sourceCommit },
  };
  return { blueprintPackage, appManifest };
};
