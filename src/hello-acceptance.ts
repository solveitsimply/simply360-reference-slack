import {
  Simply360,
  type ExternalBlueprintRuntimeOperation,
  type ExternalBlueprintRuntimePreview,
} from '@simply360/sdk';
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { open, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import {
  MarketplaceUserDelegatedAuthorizationIdentitySchema,
  type MarketplaceUserDelegatedAuthorizationIdentity,
} from '@simply360/integration-sdk/oauth';
import { z } from 'zod';

import {
  HELLO_BLUEPRINT_PACKAGE_KEY,
  HELLO_MANAGED_COLLECTION_REF,
  HELLO_MANAGED_FIELD_REF,
  HELLO_MANAGED_FIELD_TITLE,
  HELLO_PROVIDER_PERMISSIONS,
  HELLO_USER_CLIENT_ID,
  HELLO_USER_SCOPES,
} from './hello-assets.js';
import type { HelloGrantNamespace, StoredHelloCredential } from './hello-state.js';

const SimplyIdSchema = z.string().regex(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/u);
const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);
const IdempotencyKeySchema = z.string().regex(/^[A-Za-z0-9._:~-]{8,191}$/u);
const TitleSchema = z.string().trim().min(1).max(200);
const UpgradeDecisionsSchema = z.record(z.string().min(1).max(300), z.discriminatedUnion('action', [
  z.object({ action: z.literal('APPLY') }).strict(),
  z.object({ action: z.literal('MAP_EXISTING'), mappedEntitySimplyId: SimplyIdSchema }).strict(),
]));
const HELLO_DRIFT_FIELD_TITLE = 'Note (private acceptance drift)';

const compareCodeUnits = (left: string, right: string): number => (left < right ? -1 : left > right ? 1 : 0);

const canonicalJson = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.entries(value)
      .sort(([left], [right]) => compareCodeUnits(left, right))
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`)
      .join(',')}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new Error('Reviewed upgrade material must be JSON');
  return encoded;
};

const fingerprint = (value: unknown): string => createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');

const ExternalBlueprintConsentProjectionSchema = z.object({
  schemaVersion: z.literal('simply360.external-blueprint-consent/v1'),
  integrationAppVersionSimplyId: SimplyIdSchema,
  appPermissionHash: Sha256Schema,
  packages: z.array(z.object({
    packageKey: z.string().min(1).max(64).regex(/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u),
    packageVersionSimplyId: SimplyIdSchema,
    definitionHash: Sha256Schema,
    artifactHash: Sha256Schema,
    appVersionReferenceHash: Sha256Schema,
    operation: z.enum(['INSTALL', 'UPGRADE', 'RECONCILE', 'UNINSTALL']),
    changeFingerprint: Sha256Schema,
    decisionsHash: Sha256Schema,
  }).strict()).min(1).max(20),
}).strict().superRefine((projection, context) => {
  const keys = projection.packages.map(({ packageKey }) => packageKey);
  const sorted = [...keys].sort(compareCodeUnits);
  if (new Set(keys).size !== keys.length || sorted.some((value, index) => value !== keys[index])) {
    context.addIssue({ code: 'custom', path: ['packages'], message: 'Blueprint consent packages must be unique and sorted' });
  }
});

export const HelloInstallationVersionUpgradeReviewedEffectsSchema = z.object({
  schemaVersion: z.literal('simply360.hello-installation-version-upgrade-reviewed-effects/v1'),
  teamIntegrationSimplyId: SimplyIdSchema,
  sourceIntegrationAppVersionSimplyId: SimplyIdSchema,
  sourceIntegrationAppReleaseSimplyId: SimplyIdSchema,
  sourceIntegrationInstallationEpochSimplyId: SimplyIdSchema,
  targetIntegrationAppVersionSimplyId: SimplyIdSchema,
  targetIntegrationAppReleaseSimplyId: SimplyIdSchema,
  expectedAuthorityRevision: z.number().int().positive().safe(),
  roleSelectionHash: Sha256Schema,
  sharedBlueprintSiblingTeamIntegrationSimplyIds: z.array(SimplyIdSchema).max(20),
  revokedGrantCount: z.number().int().nonnegative().safe(),
  reconsentRequiredProviderAccountLinkCount: z.number().int().nonnegative().safe(),
  externalBlueprintConsent: z.object({
    projection: ExternalBlueprintConsentProjectionSchema,
    consentFingerprint: z.string().regex(/^consent\.v1\.[a-f0-9]{64}$/u),
  }).strict(),
}).strict().superRefine((reviewed, context) => {
  const sorted = [...reviewed.sharedBlueprintSiblingTeamIntegrationSimplyIds].sort(compareCodeUnits);
  if (
    new Set(sorted).size !== sorted.length ||
    sorted.some((value, index) => value !== reviewed.sharedBlueprintSiblingTeamIntegrationSimplyIds[index])
  ) {
    context.addIssue({ code: 'custom', path: ['sharedBlueprintSiblingTeamIntegrationSimplyIds'], message: 'Sibling IDs must be unique and sorted' });
  }
});

export type HelloInstallationVersionUpgradeReviewedEffects = z.infer<
  typeof HelloInstallationVersionUpgradeReviewedEffectsSchema
>;

const HelloInstallationVersionUpgradeCommitPacketPayloadSchema = z.object({
  teamSimplyId: SimplyIdSchema,
  reviewedEffects: HelloInstallationVersionUpgradeReviewedEffectsSchema,
  reviewedEffectsHash: Sha256Schema,
  consentPreviewSimplyId: SimplyIdSchema,
  previewConsentFingerprint: z.string().regex(/^consent\.v1\.[a-f0-9]{64}$/u),
  previewExpiresAt: z.string().datetime({ offset: true }),
  csrfState: z.string().min(16).max(2048),
  idempotencyKey: IdempotencyKeySchema.max(64),
}).strict();

export const HelloInstallationVersionUpgradeCommitPacketSchema = z.object({
  schemaVersion: z.literal('simply360.hello-installation-version-upgrade-commit-packet/v1'),
  payload: HelloInstallationVersionUpgradeCommitPacketPayloadSchema,
  packetHash: Sha256Schema,
}).strict().superRefine((packet, context) => {
  if (fingerprint(packet.payload) !== packet.packetHash) {
    context.addIssue({ code: 'custom', path: ['packetHash'], message: 'Recovery packet hash does not match its exact payload' });
  }
  if (fingerprint(packet.payload.reviewedEffects) !== packet.payload.reviewedEffectsHash) {
    context.addIssue({ code: 'custom', path: ['payload', 'reviewedEffectsHash'], message: 'Reviewed effects hash does not match the packet' });
  }
});

export type HelloInstallationVersionUpgradeCommitPacket = z.infer<
  typeof HelloInstallationVersionUpgradeCommitPacketSchema
>;

export interface HelloInstallationVersionUpgradePacketStore {
  save(packet: HelloInstallationVersionUpgradeCommitPacket): Promise<void>;
}

export const readHelloInstallationVersionUpgradeCommitPacket = async (
  path: string,
): Promise<HelloInstallationVersionUpgradeCommitPacket> => {
  const file = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const metadata = await file.stat();
    if (!metadata.isFile() || (metadata.mode & 0o777) !== 0o600) {
      throw new Error('Recovery packet must be a regular 0600 file');
    }
    if (typeof process.getuid === 'function' && metadata.uid !== process.getuid()) {
      throw new Error('Recovery packet must be owned by the current user');
    }
    if (metadata.size > 64 * 1024) throw new Error('Recovery packet exceeds 64 KiB');
    const bytes = await file.readFile();
    return HelloInstallationVersionUpgradeCommitPacketSchema.parse(JSON.parse(bytes.toString('utf8')));
  } finally {
    await file.close();
  }
};

export const createHelloInstallationVersionUpgradePacketFileStore = (
  path: string,
): HelloInstallationVersionUpgradePacketStore => ({
  save: async (packet) => {
    const parsed = HelloInstallationVersionUpgradeCommitPacketSchema.parse(packet);
    let file;
    let directory;
    let created = false;
    try {
      file = await open(path, 'wx', 0o600);
      created = true;
      await file.chmod(0o600);
      await file.writeFile(`${JSON.stringify(parsed)}\n`, 'utf8');
      await file.sync();
      await file.close();
      file = undefined;
      directory = await open(dirname(path), 'r');
      await directory.sync();
    } catch (error) {
      if (created) await unlink(path).catch(() => undefined);
      throw error;
    } finally {
      await file?.close();
      await directory?.close();
    }
  },
});

export const HelloAcceptanceConfigSchema = z.object({
  schemaVersion: z.literal('simply360.hello-acceptance-config/v1'),
  environment: z.literal('DEV'),
  baseUrl: z.literal('https://api.dev.simply360.app'),
  teamSimplyId: SimplyIdSchema,
  teamIntegrationSimplyId: SimplyIdSchema,
  teamUserLinkSimplyId: SimplyIdSchema,
  integrationInstallationGrantSimplyId: SimplyIdSchema,
  integrationAppVersionSimplyId: SimplyIdSchema,
  dataCollectionSimplyId: SimplyIdSchema,
  titleDataFieldSimplyId: SimplyIdSchema,
  blueprintPackageKey: z.literal(HELLO_BLUEPRINT_PACKAGE_KEY),
}).strict();

export type HelloAcceptanceConfig = z.infer<typeof HelloAcceptanceConfigSchema>;

export const HelloAcceptanceActionSchema = z.discriminatedUnion('action', [
  z.object({ action: z.literal('read-records') }).strict(),
  z.object({
    action: z.enum(['user-write-record', 'service-write-record']),
    title: TitleSchema,
    idempotencyKey: IdempotencyKeySchema,
  }).strict(),
  z.object({
    action: z.literal('attest-provider-link'),
    providerSubjectFingerprint: Sha256Schema,
    providerAccountFingerprint: Sha256Schema,
    externalCredentialReferenceHash: Sha256Schema,
    accountLabel: z.string().trim().min(1).max(200).optional(),
    idempotencyKey: IdempotencyKeySchema,
  }).strict(),
  z.object({ action: z.literal('list-provider-links'), includeRevoked: z.boolean().default(false) }).strict(),
  z.object({
    action: z.literal('revoke-provider-link'),
    accountLinkSimplyId: SimplyIdSchema,
    idempotencyKey: IdempotencyKeySchema,
    reason: z.string().trim().min(1).max(500),
  }).strict(),
  z.object({ action: z.literal('preview-blueprint-install') }).strict(),
  z.object({ action: z.literal('install-blueprint'), idempotencyKey: IdempotencyKeySchema }).strict(),
  z.object({ action: z.literal('preview-blueprint-uninstall') }).strict(),
  z.object({ action: z.literal('uninstall-blueprint') }).strict(),
  z.object({ action: z.literal('inspect-blueprint-drift') }).strict(),
  z.object({ action: z.literal('introduce-blueprint-drift') }).strict(),
  z.object({ action: z.literal('preview-blueprint-reconcile') }).strict(),
  z.object({ action: z.literal('reconcile-blueprint') }).strict(),
  z.object({
    action: z.literal('preview-blueprint-upgrade'),
    targetIntegrationAppVersionSimplyId: SimplyIdSchema,
    decisions: UpgradeDecisionsSchema,
  }).strict(),
  z.object({
    action: z.literal('upgrade-blueprint'),
    targetIntegrationAppVersionSimplyId: SimplyIdSchema,
    decisions: UpgradeDecisionsSchema,
    idempotencyKey: IdempotencyKeySchema.max(64),
  }).strict(),
  z.object({
    action: z.literal('preview-installation-version-upgrade'),
    targetIntegrationAppVersionSimplyId: SimplyIdSchema,
    sourceIntegrationInstallationEpochSimplyId: SimplyIdSchema,
    expectedAuthorityRevision: z.number().int().positive(),
    decisions: UpgradeDecisionsSchema,
  }).strict(),
  z.object({
    action: z.literal('apply-installation-version-upgrade'),
    targetIntegrationAppVersionSimplyId: SimplyIdSchema,
    sourceIntegrationInstallationEpochSimplyId: SimplyIdSchema,
    expectedAuthorityRevision: z.number().int().positive(),
    decisions: UpgradeDecisionsSchema,
    expectedReviewedEffects: HelloInstallationVersionUpgradeReviewedEffectsSchema,
    expectedReviewedEffectsHash: Sha256Schema,
    idempotencyKey: IdempotencyKeySchema.max(64),
  }).strict(),
  z.object({
    action: z.literal('replay-installation-version-upgrade-commit'),
    packet: HelloInstallationVersionUpgradeCommitPacketSchema,
  }).strict(),
  z.object({ action: z.literal('background-task-status'), backgroundTaskSimplyId: SimplyIdSchema }).strict(),
]);

export type HelloAcceptanceAction = z.infer<typeof HelloAcceptanceActionSchema>;

export interface HelloAcceptanceTokens {
  readonly installationService: string;
  readonly teamAdmin: string;
}

export interface HelloAcceptanceClients {
  readonly user: Simply360;
  readonly service: Simply360;
  readonly admin: Simply360;
  readonly userAuthorizationIdentity?: MarketplaceUserDelegatedAuthorizationIdentity;
}

export interface HelloAcceptanceCredentialStore {
  loadCredential<T extends Readonly<Record<string, unknown>>>(
    namespace: HelloGrantNamespace,
  ): Promise<StoredHelloCredential<T> | undefined>;
}

const tokenProvider = (token: string): (() => string) => () => {
  if (token.length < 16 || token.length > 16_384 || /\s/u.test(token)) {
    throw new Error('Acceptance token is missing or malformed');
  }
  return token;
};

/** OAuth clients derive Team authority from their bearer token and send no Team header. */
export const createHelloAcceptanceClients = (
  config: HelloAcceptanceConfig,
  tokens: HelloAcceptanceTokens,
): HelloAcceptanceClients => ({
  user: new Simply360({ baseUrl: config.baseUrl, getToken: tokenProvider('') }),
  service: new Simply360({ baseUrl: config.baseUrl, getToken: tokenProvider(tokens.installationService) }),
  admin: new Simply360({
    baseUrl: config.baseUrl,
    getToken: tokenProvider(tokens.teamAdmin),
    teamSimplyId: config.teamSimplyId,
  }),
});

const assertUserAuthority = (config: HelloAcceptanceConfig, clients: HelloAcceptanceClients): void => {
  const identity = clients.userAuthorizationIdentity;
  if (!identity) throw new Error('User-delegated authorization identity receipt is required');
  if (
    identity.teamSimplyId !== config.teamSimplyId ||
    identity.teamIntegrationSimplyId !== config.teamIntegrationSimplyId ||
    identity.teamUserLinkSimplyId !== config.teamUserLinkSimplyId ||
    identity.integrationInstallationGrantSimplyId !== config.integrationInstallationGrantSimplyId ||
    identity.integrationAppVersionSimplyId !== config.integrationAppVersionSimplyId ||
    identity.clientId !== HELLO_USER_CLIENT_ID ||
    identity.environment !== 'dev' ||
    identity.phase !== 'ACTIVE' ||
    identity.scopes.length !== HELLO_USER_SCOPES.length ||
    !HELLO_USER_SCOPES.every((scope) => identity.scopes.includes(scope))
  ) {
    throw new Error('User-delegated authorization identity does not match selected acceptance coordinates');
  }
};

const StoredActiveHelloOAuthCredentialSchema = z.object({
  kind: z.literal('SIMPLY360_NATIVE_OAUTH'),
  status: z.literal('ACTIVE'),
  accessToken: z.string().min(16).max(16_384).regex(/^\S+$/u),
  tokenType: z.literal('Bearer'),
  binding: MarketplaceUserDelegatedAuthorizationIdentitySchema,
}).passthrough();

/**
 * Bind the bearer and its public receipt from one encrypted exact-grant item.
 * The returned client closes over the bearer; no token or refresh credential
 * is projected to the caller.
 */
export const bindHelloAcceptanceUserCredential = async (
  config: HelloAcceptanceConfig,
  clients: HelloAcceptanceClients,
  store: HelloAcceptanceCredentialStore,
): Promise<HelloAcceptanceClients> => {
  const stored = await store.loadCredential({
    teamIntegrationSimplyId: config.teamIntegrationSimplyId,
    scope: 'member',
    memberSimplyId: config.teamUserLinkSimplyId,
    grant: 'simply360',
    integrationInstallationGrantSimplyId: config.integrationInstallationGrantSimplyId,
  });
  if (!stored) throw new Error('Selected user-delegated credential is unavailable');
  const credential = StoredActiveHelloOAuthCredentialSchema.parse(stored.value);
  const bound = {
    ...clients,
    user: new Simply360({ baseUrl: config.baseUrl, getToken: tokenProvider(credential.accessToken) }),
    userAuthorizationIdentity: credential.binding,
  };
  assertUserAuthority(config, bound);
  return bound;
};

const installPreviewBody = (config: HelloAcceptanceConfig) => ({
  integrationAppVersionSimplyId: config.integrationAppVersionSimplyId,
  selectedOptionalPackageKeys: [] as [],
});

const uninstallDecisions = (): Record<string, 'PRESERVE'> => ({
  [`COLLECTION:${HELLO_BLUEPRINT_PACKAGE_KEY}`]: 'PRESERVE',
});

const exactPreviewPackage = (
  config: HelloAcceptanceConfig,
  preview: ExternalBlueprintRuntimePreview,
  operation: ExternalBlueprintRuntimeOperation,
  versionSimplyId = config.integrationAppVersionSimplyId,
): ExternalBlueprintRuntimePreview['packages'][0] => {
  const projectedPackages = preview.consentProjection.packages;
  if (
    preview.integrationAppVersionSimplyId !== versionSimplyId ||
    preview.consentProjection.integrationAppVersionSimplyId !== versionSimplyId ||
    preview.packages.length !== 1 ||
    preview.packages[0].packageKey !== config.blueprintPackageKey ||
    projectedPackages.length !== 1 ||
    projectedPackages[0].packageKey !== config.blueprintPackageKey ||
    preview.packages[0].operation !== operation ||
    projectedPackages[0].operation !== operation ||
    preview.packages[0].packageVersionSimplyId !== projectedPackages[0].packageVersionSimplyId ||
    preview.packages[0].changeFingerprint !== projectedPackages[0].changeFingerprint
  ) {
    throw new Error('Blueprint preview does not match the selected app version and package');
  }
  return preview.packages[0];
};

/** Discover only the reviewed managed field through public Blueprint provenance. */
const readManagedField = async (clients: HelloAcceptanceClients, teamBlueprintSimplyId: string) => {
  const collections = await clients.admin.dataCollections.list();
  const owned = collections.data.filter((item) => item.blueprintProvenance.some((source) =>
    source.teamBlueprintSimplyId === teamBlueprintSimplyId &&
    source.blueprintEntityType === 'DATA_COLLECTION' &&
    source.blueprintRef === HELLO_MANAGED_COLLECTION_REF &&
    source.ownershipDisposition === 'BLUEPRINT_MANAGED'));
  if (owned.length !== 1) throw new Error('Expected exactly one reviewed integration-owned collection');
  const collection = owned[0]!;
  const fields = await clients.admin.dataCollections.listFields(collection.dataCollectionSimplyId);
  const selected = fields.data.filter((item) => item.blueprintProvenance.some((source) =>
    source.teamBlueprintSimplyId === teamBlueprintSimplyId &&
    source.blueprintEntityType === 'DATA_FIELD' &&
    source.blueprintRef === HELLO_MANAGED_FIELD_REF &&
    source.ownershipDisposition === 'BLUEPRINT_MANAGED'));
  if (selected.length !== 1) throw new Error('Expected exactly one reviewed integration-owned field');
  return { collection, field: selected[0]! };
};

const englishTitle = (title: import('@simply360/sdk').PublicLocalizedText): string | undefined => {
  if (typeof title === 'string') return title;
  const english = title?.en;
  return typeof english === 'string' ? english : english?.val;
};

const assertExactUpgradeDecisions = (
  selected: ExternalBlueprintRuntimePreview['packages'][0],
  decisions: z.infer<typeof UpgradeDecisionsSchema>,
): void => {
  for (const [changeId, decision] of Object.entries(decisions)) {
    const change = selected.changes.find((item) => item.changeId === changeId);
    if (!change || !change.allowedDecisions.includes(decision.action)) {
      throw new Error('Upgrade decision is outside the current preview');
    }
    if (decision.action === 'MAP_EXISTING' && change.mappedEntitySimplyId !== decision.mappedEntitySimplyId) {
      throw new Error('Upgrade mapping is not the exact public candidate offered by the current preview');
    }
  }
  if (selected.changes.some((change) => change.requiresDecision && !decisions[change.changeId])) {
    throw new Error('Upgrade requires every current explicit decision');
  }
};

const prepareInstallationVersionUpgradePreview = async (
  config: HelloAcceptanceConfig,
  clients: HelloAcceptanceClients,
  action: Extract<HelloAcceptanceAction, { action: 'preview-installation-version-upgrade' | 'apply-installation-version-upgrade' }>,
) => {
  if (action.targetIntegrationAppVersionSimplyId === config.integrationAppVersionSimplyId) {
    throw new Error('Installation version upgrade target must differ from the selected source version');
  }
  const currentResponse = await clients.admin.integrations.getInstallationCurrentRoleSelection(config.teamIntegrationSimplyId);
  const current = currentResponse.data;
  if (
    current.teamIntegrationSimplyId !== config.teamIntegrationSimplyId ||
    current.integrationAppVersionSimplyId !== config.integrationAppVersionSimplyId ||
    current.integrationInstallationEpochSimplyId !== action.sourceIntegrationInstallationEpochSimplyId ||
    current.authorityRevision !== action.expectedAuthorityRevision
  ) {
    throw new Error('Current installation authority does not match the reviewed source coordinates');
  }

  const blueprintBody = {
    targetIntegrationAppVersionSimplyId: action.targetIntegrationAppVersionSimplyId,
    decisionsByPackageKey: { [config.blueprintPackageKey]: action.decisions },
  };
  const blueprintResponse = await clients.admin.blueprints.previewExternalUpgrade(config.teamIntegrationSimplyId, blueprintBody);
  const selectedPackage = exactPreviewPackage(config, blueprintResponse.data, 'UPGRADE', action.targetIntegrationAppVersionSimplyId);
  assertExactUpgradeDecisions(selectedPackage, action.decisions);
  const externalBlueprintConsent = {
    projection: blueprintResponse.data.consentProjection,
    consentFingerprint: blueprintResponse.data.consentFingerprint,
  };
  const previewResponse = await clients.admin.integrations.createInstallationVersionUpgradePreview(
    config.teamIntegrationSimplyId,
    {
      targetIntegrationAppVersionSimplyId: action.targetIntegrationAppVersionSimplyId,
      roleSelection: current.roleSelection,
      externalBlueprintConsent,
    },
  );
  const preview = previewResponse.data;
  if (
    preview.teamIntegrationSimplyId !== config.teamIntegrationSimplyId ||
    preview.sourceIntegrationAppVersionSimplyId !== config.integrationAppVersionSimplyId ||
    preview.sourceIntegrationInstallationEpochSimplyId !== action.sourceIntegrationInstallationEpochSimplyId ||
    preview.integrationAppVersionSimplyId !== action.targetIntegrationAppVersionSimplyId ||
    preview.sourceIntegrationAppReleaseSimplyId === preview.targetIntegrationAppReleaseSimplyId ||
    canonicalJson(preview.roleSelection) !== canonicalJson(current.roleSelection) ||
    canonicalJson(preview.externalBlueprint) !== canonicalJson(externalBlueprintConsent) ||
    preview.signedConsent.consent.teamIntegrationSimplyId !== config.teamIntegrationSimplyId ||
    preview.signedConsent.consent.integrationAppVersionSimplyId !== action.targetIntegrationAppVersionSimplyId ||
    canonicalJson(preview.signedConsent.consent.externalBlueprint) !== canonicalJson(externalBlueprintConsent.projection) ||
    preview.signedConsent.consent.externalBlueprintConsentFingerprint !== externalBlueprintConsent.consentFingerprint ||
    preview.sharedBlueprintSiblingTeamIntegrationSimplyIds.includes(config.teamIntegrationSimplyId) ||
    new Set(preview.sharedBlueprintSiblingTeamIntegrationSimplyIds).size !==
      preview.sharedBlueprintSiblingTeamIntegrationSimplyIds.length
  ) {
    throw new Error('Version-upgrade preview does not match the reviewed installation authority');
  }
  const reviewedEffects = HelloInstallationVersionUpgradeReviewedEffectsSchema.parse({
    schemaVersion: 'simply360.hello-installation-version-upgrade-reviewed-effects/v1',
    teamIntegrationSimplyId: config.teamIntegrationSimplyId,
    sourceIntegrationAppVersionSimplyId: config.integrationAppVersionSimplyId,
    sourceIntegrationAppReleaseSimplyId: preview.sourceIntegrationAppReleaseSimplyId,
    sourceIntegrationInstallationEpochSimplyId: action.sourceIntegrationInstallationEpochSimplyId,
    targetIntegrationAppVersionSimplyId: action.targetIntegrationAppVersionSimplyId,
    targetIntegrationAppReleaseSimplyId: preview.targetIntegrationAppReleaseSimplyId,
    expectedAuthorityRevision: action.expectedAuthorityRevision,
    roleSelectionHash: fingerprint(current.roleSelection),
    sharedBlueprintSiblingTeamIntegrationSimplyIds: [...preview.sharedBlueprintSiblingTeamIntegrationSimplyIds]
      .sort(compareCodeUnits),
    revokedGrantCount: preview.revokedGrantCount,
    reconsentRequiredProviderAccountLinkCount: preview.reconsentRequiredProviderAccountLinkCount,
    externalBlueprintConsent,
  });
  const reviewedEffectsHash = fingerprint(reviewedEffects);
  if (
    action.action === 'apply-installation-version-upgrade' &&
    (
      fingerprint(action.expectedReviewedEffects) !== action.expectedReviewedEffectsHash ||
      action.expectedReviewedEffectsHash !== reviewedEffectsHash ||
      canonicalJson(action.expectedReviewedEffects) !== canonicalJson(reviewedEffects)
    )
  ) {
    throw new Error('Current version-upgrade effects differ from the explicitly reviewed preview');
  }
  return { current, preview, reviewedEffects, reviewedEffectsHash, requestId: previewResponse.meta.requestId };
};

const MarketplaceInstallationVersionUpgradeCommitResponseSchema = z.object({
  outcome: z.enum(['PENDING_SETUP', 'ALREADY_APPLIED']),
  status: z.literal('PENDING_SETUP'),
  teamIntegrationSimplyId: SimplyIdSchema,
  sourceIntegrationInstallationEpochSimplyId: SimplyIdSchema,
  targetIntegrationInstallationEpochSimplyId: SimplyIdSchema,
  integrationInstallationConsentSimplyId: SimplyIdSchema,
  integrationInstallationOperationSimplyId: SimplyIdSchema,
  authorityRevision: z.number().int().positive().safe(),
  revokedGrantCount: z.number().int().nonnegative().safe(),
  reconsentRequiredProviderAccountLinkCount: z.number().int().nonnegative().safe(),
  materializationEffect: z.enum(['ENQUEUED', 'NOT_APPLICABLE']).nullable(),
}).passthrough();

const MarketplaceInstallationVersionUpgradeReadbackSchema = z.object({
  integration: z.object({
    teamIntegrationSimplyId: SimplyIdSchema,
    integrationAppVersionSimplyId: SimplyIdSchema,
    installationStatus: z.enum(['PENDING_SETUP', 'ACTIVE']),
  }).passthrough(),
}).passthrough();

const commitInstallationVersionUpgradePacket = async (
  config: HelloAcceptanceConfig,
  clients: HelloAcceptanceClients,
  packetInput: HelloInstallationVersionUpgradeCommitPacket,
) => {
  const packet = HelloInstallationVersionUpgradeCommitPacketSchema.parse(packetInput);
  const { payload } = packet;
  const expected = payload.reviewedEffects;
  if (
    payload.teamSimplyId !== config.teamSimplyId ||
    expected.teamIntegrationSimplyId !== config.teamIntegrationSimplyId ||
    expected.sourceIntegrationAppVersionSimplyId !== config.integrationAppVersionSimplyId
  ) {
    throw new Error('Recovery packet does not belong to the selected Team installation');
  }
  const response = await clients.admin.integrations.commitInstallationVersionUpgradePreview(
    expected.teamIntegrationSimplyId,
    {
      consentPreviewSimplyId: payload.consentPreviewSimplyId,
      csrfState: payload.csrfState,
      idempotencyKey: payload.idempotencyKey,
    },
  );
  const commit = MarketplaceInstallationVersionUpgradeCommitResponseSchema.parse(response.data);
  if (
    commit.teamIntegrationSimplyId !== expected.teamIntegrationSimplyId ||
    commit.sourceIntegrationInstallationEpochSimplyId !== expected.sourceIntegrationInstallationEpochSimplyId ||
    commit.targetIntegrationInstallationEpochSimplyId === expected.sourceIntegrationInstallationEpochSimplyId ||
    commit.authorityRevision !== expected.expectedAuthorityRevision + 1 ||
    commit.revokedGrantCount !== expected.revokedGrantCount ||
    commit.reconsentRequiredProviderAccountLinkCount !== expected.reconsentRequiredProviderAccountLinkCount
  ) {
    throw new Error('Version-upgrade commit does not match the explicitly reviewed effects');
  }
  const readbackResponse = await clients.admin.integrations.getTeamIntegration(expected.teamIntegrationSimplyId);
  const readback = MarketplaceInstallationVersionUpgradeReadbackSchema.parse(readbackResponse.data).integration;
  if (
    readback.teamIntegrationSimplyId !== expected.teamIntegrationSimplyId ||
    readback.integrationAppVersionSimplyId !== expected.targetIntegrationAppVersionSimplyId
  ) {
    throw new Error('Public installation readback does not prove the reviewed target version');
  }
  return {
    outcome: commit.outcome,
    status: commit.status,
    teamIntegrationSimplyId: commit.teamIntegrationSimplyId,
    sourceIntegrationInstallationEpochSimplyId: commit.sourceIntegrationInstallationEpochSimplyId,
    targetIntegrationInstallationEpochSimplyId: commit.targetIntegrationInstallationEpochSimplyId,
    integrationInstallationConsentSimplyId: commit.integrationInstallationConsentSimplyId,
    integrationInstallationOperationSimplyId: commit.integrationInstallationOperationSimplyId,
    authorityRevision: commit.authorityRevision,
    revokedGrantCount: commit.revokedGrantCount,
    reconsentRequiredProviderAccountLinkCount: commit.reconsentRequiredProviderAccountLinkCount,
    materializationEffect: commit.materializationEffect,
    reviewedEffectsHash: payload.reviewedEffectsHash,
    recoveryPacketHash: packet.packetHash,
    readbackInstallationStatus: readback.installationStatus,
    requestId: response.meta.requestId,
    readbackRequestId: readbackResponse.meta.requestId,
  };
};

export const runHelloAcceptanceAction = async (input: {
  readonly config: HelloAcceptanceConfig;
  readonly action: HelloAcceptanceAction;
  readonly clients: HelloAcceptanceClients;
  readonly installationVersionUpgradePacketStore?: HelloInstallationVersionUpgradePacketStore;
}): Promise<Readonly<Record<string, unknown>>> => {
  const { action, clients, config } = input;
  switch (action.action) {
    case 'read-records': {
      assertUserAuthority(config, clients);
      const response = await clients.user.dataRecords.list({
        dataCollectionSimplyId: config.dataCollectionSimplyId,
        limit: 10,
        fields: config.titleDataFieldSimplyId,
        projection: 'SUMMARY',
      });
      return {
        outcome: 'READ',
        count: response.data.length,
        dataRecordSimplyIds: response.data.map(({ dataRecordSimplyId }) => dataRecordSimplyId),
        requestId: response.meta.requestId,
      };
    }
    case 'user-write-record':
    case 'service-write-record': {
      if (action.action === 'user-write-record') assertUserAuthority(config, clients);
      const client = action.action === 'user-write-record' ? clients.user : clients.service;
      const response = await client.dataRecords.create({
        dataCollectionSimplyId: config.dataCollectionSimplyId,
        fields: { [config.titleDataFieldSimplyId]: action.title },
        idempotencyKey: action.idempotencyKey,
      });
      return {
        outcome: 'WRITTEN',
        dataRecordSimplyId: response.data.dataRecordSimplyId,
        requestId: response.meta.requestId,
      };
    }
    case 'attest-provider-link': {
      assertUserAuthority(config, clients);
      const response = await clients.user.integrations.attestExternalProviderAccountLink({
        schemaVersion: 'simply360.external-provider-account-attestation/v1',
        providerSubjectFingerprint: action.providerSubjectFingerprint,
        providerAccountFingerprint: action.providerAccountFingerprint,
        externalCredentialReferenceHash: action.externalCredentialReferenceHash,
        grantedPermissions: [...HELLO_PROVIDER_PERMISSIONS],
        ...(action.accountLabel ? { accountLabel: action.accountLabel } : {}),
      }, { idempotencyKey: action.idempotencyKey });
      return {
        outcome: response.data.replayed ? 'ATTESTATION_REPLAYED' : 'ATTESTED',
        accountLinkSimplyId: response.data.accountLinkSimplyId,
        integrationInstallationOperationSimplyId: response.data.integrationInstallationOperationSimplyId,
        teamIntegrationSimplyId: response.data.teamIntegrationSimplyId,
        teamUserLinkSimplyId: response.data.teamUserLinkSimplyId,
        integrationInstallationGrantSimplyId: response.data.integrationInstallationGrantSimplyId,
        requestId: response.meta.requestId,
      };
    }
    case 'list-provider-links': {
      const response = await clients.admin.integrations.listProviderAccountLinks({
        teamIntegrationSimplyId: config.teamIntegrationSimplyId,
        includeRevoked: action.includeRevoked,
      });
      return {
        outcome: 'LISTED',
        accountLinks: response.data.map(({ accountLinkSimplyId, teamUserLinkSimplyId, status }) => ({
          accountLinkSimplyId,
          teamUserLinkSimplyId,
          status,
        })),
        requestId: response.meta.requestId,
      };
    }
    case 'revoke-provider-link': {
      const inventory = await clients.admin.integrations.listProviderAccountLinks({
        teamIntegrationSimplyId: config.teamIntegrationSimplyId,
        includeRevoked: true,
      });
      const selected = inventory.data.filter(({ accountLinkSimplyId }) => accountLinkSimplyId === action.accountLinkSimplyId);
      const target = selected[0];
      if (
        !target || selected.length !== 1 ||
        target.teamIntegrationSimplyId !== config.teamIntegrationSimplyId
      ) {
        throw new Error('Provider account link is not owned by the selected installation');
      }
      const response = await clients.admin.integrations.revokeProviderAccountLink({
        accountLinkSimplyId: action.accountLinkSimplyId,
        idempotencyKey: action.idempotencyKey,
        reason: action.reason,
      });
      return {
        outcome: response.data.alreadyRevoked ? 'REVOCATION_REPLAYED' : 'REVOKED',
        accountLinkSimplyId: response.data.accountLinkSimplyId,
        integrationInstallationOperationSimplyId: response.data.integrationInstallationOperationSimplyId,
        requestId: response.meta.requestId,
      };
    }
    case 'preview-blueprint-install': {
      const response = await clients.admin.blueprints.previewExternalInstall(
        config.teamIntegrationSimplyId,
        installPreviewBody(config),
      );
      const selectedPackage = exactPreviewPackage(config, response.data, 'INSTALL');
      return {
        outcome: 'PREVIEWED',
        consentFingerprint: response.data.consentFingerprint,
        packageKey: selectedPackage.packageKey,
        changeFingerprint: selectedPackage.changeFingerprint,
        changes: selectedPackage.changes.map(({ changeId, disposition }) => ({ changeId, disposition })),
        requestId: response.meta.requestId,
      };
    }
    case 'install-blueprint': {
      const preview = await clients.admin.blueprints.previewExternalInstall(
        config.teamIntegrationSimplyId,
        installPreviewBody(config),
      );
      exactPreviewPackage(config, preview.data, 'INSTALL');
      const response = await clients.admin.blueprints.installExternal(config.teamIntegrationSimplyId, {
        ...installPreviewBody(config),
        consentFingerprint: preview.data.consentFingerprint,
        consentProjection: preview.data.consentProjection,
      }, action.idempotencyKey);
      return {
        outcome: 'INSTALL_QUEUED',
        backgroundTaskSimplyId: response.data.backgroundTaskSimplyId,
        requestId: response.meta.requestId,
      };
    }
    case 'preview-blueprint-uninstall': {
      const response = await clients.admin.blueprints.previewExternalUninstall(
        config.teamIntegrationSimplyId,
        config.blueprintPackageKey,
        { decisions: uninstallDecisions() },
      );
      const selectedPackage = exactPreviewPackage(config, response.data, 'UNINSTALL');
      return {
        outcome: 'UNINSTALL_PREVIEWED',
        consentFingerprint: response.data.consentFingerprint,
        packageKey: selectedPackage.packageKey,
        changeFingerprint: selectedPackage.changeFingerprint,
        changes: selectedPackage.changes.map(({ changeId, disposition }) => ({ changeId, disposition })),
        requestId: response.meta.requestId,
      };
    }
    case 'uninstall-blueprint': {
      const preview = await clients.admin.blueprints.previewExternalUninstall(
        config.teamIntegrationSimplyId,
        config.blueprintPackageKey,
        { decisions: uninstallDecisions() },
      );
      exactPreviewPackage(config, preview.data, 'UNINSTALL');
      const response = await clients.admin.blueprints.uninstallExternal(
        config.teamIntegrationSimplyId,
        config.blueprintPackageKey,
        {
          decisions: uninstallDecisions(),
          consentFingerprint: preview.data.consentFingerprint,
          consentProjection: preview.data.consentProjection,
        },
      );
      return {
        outcome: 'UNINSTALLED',
        packageKey: response.data.packageKey,
        packageVersionSimplyId: response.data.packageVersionSimplyId,
        teamBlueprintSimplyId: response.data.teamBlueprintSimplyId,
        requestId: response.meta.requestId,
      };
    }
    case 'inspect-blueprint-drift': {
      const response = await clients.admin.blueprints.inspectExternalDrift(config.teamIntegrationSimplyId, config.blueprintPackageKey);
      return {
        outcome: 'DRIFT_READ',
        teamBlueprintSimplyId: response.data.teamBlueprintSimplyId,
        drifted: response.data.drifted,
        errorCount: response.data.report.errorCount,
        requestId: response.meta.requestId,
      };
    }
    case 'introduce-blueprint-drift': {
      const before = await clients.admin.blueprints.inspectExternalDrift(config.teamIntegrationSimplyId, config.blueprintPackageKey);
      if (before.data.drifted || before.data.report.errorCount !== 0) throw new Error('Drift proof requires a clean installed Blueprint');
      const selected = await readManagedField(clients, before.data.teamBlueprintSimplyId);
      if (englishTitle(selected.field.title) !== HELLO_MANAGED_FIELD_TITLE) throw new Error('Reviewed field title has changed');
      await clients.admin.dataFields.update(selected.field.dataFieldSimplyId, { title: { en: HELLO_DRIFT_FIELD_TITLE } });
      const after = await clients.admin.blueprints.inspectExternalDrift(config.teamIntegrationSimplyId, config.blueprintPackageKey);
      const readback = await readManagedField(clients, before.data.teamBlueprintSimplyId);
      if (!after.data.drifted || after.data.teamBlueprintSimplyId !== before.data.teamBlueprintSimplyId ||
          after.data.report.errorCount !== 0 || readback.field.dataFieldSimplyId !== selected.field.dataFieldSimplyId ||
          englishTitle(readback.field.title) !== HELLO_DRIFT_FIELD_TITLE) throw new Error('Drift mutation requires exact readback');
      return { outcome: 'DRIFT_CONFIRMED', teamBlueprintSimplyId: before.data.teamBlueprintSimplyId,
        dataCollectionSimplyId: selected.collection.dataCollectionSimplyId, dataFieldSimplyId: selected.field.dataFieldSimplyId,
        requestId: after.meta.requestId };
    }
    case 'preview-blueprint-reconcile':
    case 'reconcile-blueprint': {
      const preview = await clients.admin.blueprints.previewExternalReconcile(config.teamIntegrationSimplyId, config.blueprintPackageKey);
      const selected = exactPreviewPackage(config, preview.data, 'RECONCILE');
      if (action.action === 'preview-blueprint-reconcile') return {
        outcome: 'RECONCILE_PREVIEWED', consentFingerprint: preview.data.consentFingerprint,
        changes: selected.changes, requestId: preview.meta.requestId,
      };
      const response = await clients.admin.blueprints.reconcileExternal(config.teamIntegrationSimplyId, config.blueprintPackageKey, {
        consentFingerprint: preview.data.consentFingerprint, consentProjection: preview.data.consentProjection,
      });
      const after = await clients.admin.blueprints.inspectExternalDrift(config.teamIntegrationSimplyId, config.blueprintPackageKey);
      const readback = await readManagedField(clients, response.data.teamBlueprintSimplyId);
      if (after.data.drifted || after.data.report.errorCount !== 0 || response.data.report.errorCount !== 0 ||
          after.data.teamBlueprintSimplyId !== response.data.teamBlueprintSimplyId ||
          englishTitle(readback.field.title) !== HELLO_MANAGED_FIELD_TITLE) throw new Error('Reconcile did not restore the reviewed managed field');
      return { outcome: 'RECONCILED', teamBlueprintSimplyId: response.data.teamBlueprintSimplyId,
        dataFieldSimplyId: readback.field.dataFieldSimplyId, drifted: false, requestId: response.meta.requestId };
    }
    case 'preview-blueprint-upgrade':
    case 'upgrade-blueprint': {
      const body = { targetIntegrationAppVersionSimplyId: action.targetIntegrationAppVersionSimplyId,
        decisionsByPackageKey: { [config.blueprintPackageKey]: action.decisions } };
      const preview = await clients.admin.blueprints.previewExternalUpgrade(config.teamIntegrationSimplyId, body);
      const selected = exactPreviewPackage(config, preview.data, 'UPGRADE', action.targetIntegrationAppVersionSimplyId);
      if (action.action === 'preview-blueprint-upgrade') return {
        outcome: 'UPGRADE_PREVIEWED', consentFingerprint: preview.data.consentFingerprint,
        changes: selected.changes, requestId: preview.meta.requestId,
      };
      assertExactUpgradeDecisions(selected, action.decisions);
      const response = await clients.admin.blueprints.upgradeExternal(config.teamIntegrationSimplyId, {
        ...body, consentFingerprint: preview.data.consentFingerprint, consentProjection: preview.data.consentProjection,
      }, action.idempotencyKey);
      return { outcome: 'UPGRADE_QUEUED', backgroundTaskSimplyId: response.data.backgroundTaskSimplyId,
        requestId: response.meta.requestId };
    }
    case 'preview-installation-version-upgrade':
    case 'apply-installation-version-upgrade': {
      const prepared = await prepareInstallationVersionUpgradePreview(config, clients, action);
      if (action.action === 'preview-installation-version-upgrade') {
        return {
          outcome: 'INSTALLATION_VERSION_UPGRADE_PREVIEWED',
          teamIntegrationSimplyId: prepared.preview.teamIntegrationSimplyId,
          sourceIntegrationAppVersionSimplyId: prepared.preview.sourceIntegrationAppVersionSimplyId,
          sourceIntegrationInstallationEpochSimplyId: prepared.preview.sourceIntegrationInstallationEpochSimplyId,
          targetIntegrationAppVersionSimplyId: prepared.preview.integrationAppVersionSimplyId,
          authorityRevision: prepared.current.authorityRevision,
          sharedBlueprintSiblingTeamIntegrationSimplyIds: prepared.preview.sharedBlueprintSiblingTeamIntegrationSimplyIds,
          revokedGrantCount: prepared.preview.revokedGrantCount,
          reconsentRequiredProviderAccountLinkCount: prepared.preview.reconsentRequiredProviderAccountLinkCount,
          consentFingerprint: prepared.preview.consentFingerprint,
          reviewedEffects: prepared.reviewedEffects,
          reviewedEffectsHash: prepared.reviewedEffectsHash,
          requestId: prepared.requestId,
        };
      }
      if (!input.installationVersionUpgradePacketStore) {
        throw new Error('A private recovery packet store is required before version-upgrade commit');
      }
      const payload = HelloInstallationVersionUpgradeCommitPacketPayloadSchema.parse({
        teamSimplyId: config.teamSimplyId,
        reviewedEffects: prepared.reviewedEffects,
        reviewedEffectsHash: prepared.reviewedEffectsHash,
        consentPreviewSimplyId: prepared.preview.consentPreviewSimplyId,
        previewConsentFingerprint: prepared.preview.consentFingerprint,
        previewExpiresAt: prepared.preview.expiresAt,
        csrfState: prepared.preview.csrfState,
        idempotencyKey: action.idempotencyKey,
      });
      const packet = HelloInstallationVersionUpgradeCommitPacketSchema.parse({
        schemaVersion: 'simply360.hello-installation-version-upgrade-commit-packet/v1',
        payload,
        packetHash: fingerprint(payload),
      });
      await input.installationVersionUpgradePacketStore.save(packet);
      return await commitInstallationVersionUpgradePacket(config, clients, packet);
    }
    case 'replay-installation-version-upgrade-commit': {
      return await commitInstallationVersionUpgradePacket(config, clients, action.packet);
    }
    case 'background-task-status': {
      const response = await clients.admin.backgroundTasks.get(action.backgroundTaskSimplyId);
      return {
        outcome: 'TASK_READ',
        backgroundTaskSimplyId: action.backgroundTaskSimplyId,
        status: response.data.status,
        requestId: response.meta.requestId,
      };
    }
  }
};
