import {
  Simply360,
  type ExternalBlueprintRuntimeOperation,
  type ExternalBlueprintRuntimePreview,
} from '@simply360/sdk';
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

export const runHelloAcceptanceAction = async (input: {
  readonly config: HelloAcceptanceConfig;
  readonly action: HelloAcceptanceAction;
  readonly clients: HelloAcceptanceClients;
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
      for (const [changeId, decision] of Object.entries(action.decisions)) {
        const change = selected.changes.find((item) => item.changeId === changeId);
        if (!change || !change.allowedDecisions.includes(decision.action)) throw new Error('Upgrade decision is outside the current preview');
      }
      if (selected.changes.some((change) => change.requiresDecision && !action.decisions[change.changeId])) {
        throw new Error('Upgrade requires every current explicit decision');
      }
      const response = await clients.admin.blueprints.upgradeExternal(config.teamIntegrationSimplyId, {
        ...body, consentFingerprint: preview.data.consentFingerprint, consentProjection: preview.data.consentProjection,
      }, action.idempotencyKey);
      return { outcome: 'UPGRADE_QUEUED', backgroundTaskSimplyId: response.data.backgroundTaskSimplyId,
        requestId: response.meta.requestId };
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
