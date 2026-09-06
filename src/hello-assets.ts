import {
  buildExternalBlueprintPackage,
  computeExternalBlueprintPackageSha256,
  defineCollection,
  defineExternalBlueprint,
  defineField,
  defineLifecycleDeclaration,
  formulaField,
  validateExternalBlueprintDefinition,
} from '@simply360/blueprint-sdk';
import {
  AppManifestV1Schema,
  normalizeAppManifestV1,
  type AppManifestV1,
} from '@simply360/integration-sdk/manifest';

const REPOSITORY_URL = 'https://github.com/solveitsimply/simply360-reference-slack';
const RUNTIME_ORIGIN = 'https://reference-slack.dev.simply360.app';
const SOURCE_COMMIT_PATTERN = /^[a-f0-9]{40}$/u;

export const HELLO_APP_SLUG = 'marketplace-hello-app';
export const HELLO_PUBLISHER_SLUG = 'hello-app-dev-publisher';
export const HELLO_BLUEPRINT_PACKAGE_KEY = 'hello-records';
export const HELLO_SERVICE_CLIENT_KEY = 'hello-app-dev';
export const HELLO_USER_CLIENT_KEY = 'hello-app-dev-user';
export const HELLO_SERVICE_CLIENT_ID = 's360_marketplace_server_dev_hello01';
export const HELLO_USER_CLIENT_ID = 's360_marketplace_native_dev_hello01';
export const HELLO_PROVIDER_PERMISSIONS = ['hello.read', 'hello.write'] as const;
export const HELLO_USER_SCOPES = [
  'identity:read',
  'teams:read',
  'schema:read',
  'records:read',
  'records:write',
  'integrations:write',
  'offline_access',
] as const;
export const HELLO_SUBSCRIPTION_EVENT_TYPES = ['dataRecord.created'] as const;
export const HELLO_LIFECYCLE_EVENT_TYPES = [
  'app.install.completed',
  'app.setup.completed',
  'app.uninstalled',
  'app.grant.revoked',
  'app.account-link.revoked',
] as const;

export interface HelloAcceptanceBundle {
  readonly manifest: AppManifestV1;
  readonly blueprintPackage: Awaited<ReturnType<typeof buildExternalBlueprintPackage>>;
  readonly blueprintPackageSha256: string;
}

export const buildHelloAcceptanceBundle = async (input: {
  readonly sourceCommit: string;
  readonly semanticVersion: string;
}): Promise<HelloAcceptanceBundle> => {
  if (!SOURCE_COMMIT_PATTERN.test(input.sourceCommit)) {
    throw new Error('sourceCommit must be the exact lowercase 40-character Git SHA');
  }

  const definition = defineExternalBlueprint({
    collections: [
      defineCollection({
        collectionKey: 'hello-records',
        label: { en: 'Hello records' },
        description: { en: 'Synthetic records used only for private integration acceptance.' },
        lifecycleOwner: 'TEAM',
        recordLifecycle: 'ACTIVE_ONLY',
        calculatedName: formulaField('title'),
        fields: [
          defineField({ kind: 'TEXT', fieldKey: 'title', label: { en: 'Title' }, required: true, maxLength: 200 }),
          defineField({ kind: 'DATE', fieldKey: 'greeted-on', label: { en: 'Greeted on' }, required: false }),
          defineField({ kind: 'BOOLEAN', fieldKey: 'greeted', label: { en: 'Greeted' }, required: false }),
        ],
        sharedContractKeys: [],
      }),
    ],
    smartCollections: [],
    dataViews: [],
    reports: [],
    labels: [],
    sharedCollectionContracts: [],
    mappings: [],
    options: [],
    lifecycle: [
      defineLifecycleDeclaration({
        resourceType: 'COLLECTION',
        collectionKey: 'hello-records',
        owner: 'TEAM',
        uninstallBehavior: 'PRESERVE',
      }),
    ],
  });
  validateExternalBlueprintDefinition(definition);
  const blueprintPackage = await buildExternalBlueprintPackage(definition, {
    publisherSlug: HELLO_PUBLISHER_SLUG,
    packageKey: HELLO_BLUEPRINT_PACKAGE_KEY,
    semanticVersion: input.semanticVersion,
    displayName: 'Hello records',
    summary: 'Provider-neutral structural package for private hello integration acceptance.',
    support: {
      supportUrl: `${REPOSITORY_URL}/blob/${input.sourceCommit}/README.md`,
      escalationEmail: 'support@simply360.app',
    },
    compatibility: { minimumPlatformVersion: '1.0.0' },
    provenance: { sourceRepository: REPOSITORY_URL, sourceCommit: input.sourceCommit },
  });
  const blueprintPackageSha256 = await computeExternalBlueprintPackageSha256(blueprintPackage);

  const candidate = {
    schemaVersion: 'simply360.app-manifest/v1',
    app: {
      slug: HELLO_APP_SLUG,
      semanticVersion: input.semanticVersion,
      displayName: 'Marketplace Hello App (dev fixture)',
      summary: 'Private provider-neutral out-of-tree acceptance app for Simply360 dev.',
      supportUrl: `${REPOSITORY_URL}/blob/${input.sourceCommit}/README.md`,
      privacyUrl: `${REPOSITORY_URL}/blob/${input.sourceCommit}/docs/privacy.md`,
      termsUrl: `${REPOSITORY_URL}/blob/${input.sourceCommit}/docs/terms.md`,
    },
    oauth: {
      accountBindingModes: ['team', 'user'],
      perUserLinkMultiplicity: 'MULTIPLE_PER_USER',
      clients: [
        {
          clientKey: HELLO_SERVICE_CLIENT_KEY,
          clientType: 'SERVER',
          tokenEndpointAuthMethod: 'CLIENT_SECRET_BASIC',
          grantModes: ['teamInstallation'],
          redirectUris: [`${RUNTIME_ORIGIN}/oauth/simply360/callback`],
          scopes: ['offline_access', 'records:read', 'records:write', 'schema:read'],
          audience: 'urn:simply360:public-api',
          resource: 'urn:simply360:team-api',
        },
        {
          clientKey: HELLO_USER_CLIENT_KEY,
          clientType: 'NATIVE',
          tokenEndpointAuthMethod: 'NONE',
          grantModes: ['userDelegated'],
          redirectUris: [`${RUNTIME_ORIGIN}/oauth/simply360/callback`],
          scopes: [...HELLO_USER_SCOPES],
          audience: 'urn:simply360:public-api',
          resource: 'urn:simply360:team-api',
          externalProviderAccount: {
            credentialCustody: 'EXTERNAL_CONNECTOR',
            providerPermissions: [...HELLO_PROVIDER_PERMISSIONS],
          },
        },
      ],
    },
    capabilities: [
      { capabilityKey: 'RECORD_API', registryVersion: 1, configuration: {} },
      { capabilityKey: 'EVENT_DESTINATION', registryVersion: 1, configuration: {} },
      { capabilityKey: 'EXTERNAL_BLUEPRINT_PACKAGE', registryVersion: 1, configuration: {} },
    ],
    eventDestinations: [{
      endpointKey: 'record-events',
      exactUrl: `${RUNTIME_ORIGIN}/events/simply360`,
      protocolVersion: 2,
      eventTypes: [...HELLO_SUBSCRIPTION_EVENT_TYPES],
      filters: {},
    }],
    remoteActions: [],
    remoteTriggers: [],
    blueprintPackages: [{
      packageKey: HELLO_BLUEPRINT_PACKAGE_KEY,
      version: input.semanticVersion,
      sha256: blueprintPackageSha256,
      required: true,
      installOrder: 1,
    }],
    trustedFirstPartyBlueprintRequirements: [],
    dataAccess: {
      classifications: ['TEAM_OPERATIONAL'],
      purpose: 'Read and write only synthetic hello records for private integration acceptance.',
      retention: 'UNTIL_UNINSTALL',
      exportBehavior: 'NOT_APPLICABLE',
      deletionBehavior: 'AVAILABLE_ON_REQUEST',
    },
    lifecycle: {
      setupLaunchUrl: `${RUNTIME_ORIGIN}/oauth/simply360/start`,
      notifications: {
        endpointKey: 'lifecycle',
        exactUrl: `${RUNTIME_ORIGIN}/lifecycle`,
        protocolVersion: 1,
        eventTypes: [...HELLO_LIFECYCLE_EVENT_TYPES],
      },
    },
    support: {
      owner: 'PUBLISHER',
      escalationEmail: 'support@simply360.app',
      documentationUrl: `${REPOSITORY_URL}/blob/${input.sourceCommit}/README.md`,
      incidentUrl: `${REPOSITORY_URL}/blob/${input.sourceCommit}/SECURITY.md`,
      deprecationPolicyUrl: `${REPOSITORY_URL}/blob/${input.sourceCommit}/docs/deprecation.md`,
    },
    provenance: { sourceRepository: REPOSITORY_URL, sourceCommit: input.sourceCommit },
  };
  const manifest = AppManifestV1Schema.parse(candidate);
  return { manifest: normalizeAppManifestV1(manifest), blueprintPackage, blueprintPackageSha256 };
};
