import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  HelloAcceptanceActionSchema,
  HelloAcceptanceConfigSchema,
  HelloInstallationVersionUpgradeCommitPacketSchema,
  HelloLifecycleFencedError,
  bindHelloAcceptanceUserCredential,
  createHelloAcceptanceClients,
  createHelloInstallationVersionUpgradePacketFileStore,
  readHelloInstallationVersionUpgradeCommitPacket,
  runHelloAcceptanceAction,
} from '../dist/index.js';

const config = HelloAcceptanceConfigSchema.parse({
  schemaVersion: 'simply360.hello-acceptance-config/v1',
  environment: 'DEV',
  baseUrl: 'https://api.dev.simply360.app',
  teamSimplyId: 'TEAM-0001-AAAA',
  teamIntegrationSimplyId: 'TINT-0001-AAAA',
  teamUserLinkSimplyId: 'TULK-0001-AAAA',
  integrationInstallationGrantSimplyId: 'IGRT-0001-AAAA',
  integrationAppVersionSimplyId: 'IAVR-0001-AAAA',
  dataCollectionSimplyId: 'DCOL-0001-AAAA',
  titleDataFieldSimplyId: 'DFLD-0001-AAAA',
  blueprintPackageKey: 'hello-records',
});

const userAuthorizationIdentity = {
  principalType: 'USER_DELEGATED',
  teamSimplyId: config.teamSimplyId,
  teamIntegrationSimplyId: config.teamIntegrationSimplyId,
  teamUserLinkSimplyId: config.teamUserLinkSimplyId,
  integrationInstallationEpochSimplyId: 'IEPO-0001-AAAA',
  integrationPublisherSimplyId: 'IPUB-0001-AAAA',
  integrationAppSimplyId: 'IAPP-0001-AAAA',
  integrationAppVersionSimplyId: config.integrationAppVersionSimplyId,
  integrationAppReleaseSimplyId: 'IARL-0001-AAAA',
  integrationAppOAuthClientSimplyId: 'IAOC-0001-AAAA',
  integrationInstallationConsentSimplyId: 'IICO-0001-AAAA',
  integrationInstallationGrantSimplyId: 'IGRT-0001-AAAA',
  clientId: 's360_marketplace_native_dev_hello01',
  audience: 'urn:simply360:public-api',
  resource: 'urn:simply360:team-api',
  environment: 'dev',
  phase: 'ACTIVE',
  scopes: ['identity:read', 'teams:read', 'schema:read', 'records:read', 'records:write', 'integrations:write', 'offline_access'],
};

const response = (data) => ({
  ok: true,
  status: 200,
  text: async () => JSON.stringify({ data, meta: { requestId: 'request-1', pagination: { total: 1, limit: 10, offset: 0 } } }),
  headers: { forEach: () => {} },
});

const storedCredential = (binding = userAuthorizationIdentity) => ({
  revision: 1,
  value: {
    kind: 'SIMPLY360_NATIVE_OAUTH',
    status: 'ACTIVE',
    accessToken: 'user-delegated-token-for-test',
    refreshToken: 'refresh-token-never-projected',
    tokenType: 'Bearer',
    binding,
  },
});

const clients = async () => bindHelloAcceptanceUserCredential(config, createHelloAcceptanceClients(config, {
  installationService: 'installation-service-token-for-test',
  teamAdmin: 'team-admin-token-for-test',
}), { loadCredential: async () => storedCredential() });

test('preflight schemas reject placeholders, production endpoints, internal coordinates, and extra authority', () => {
  assert.throws(() => HelloAcceptanceConfigSchema.parse({
    ...config,
    teamIntegrationSimplyId: 'REQUIRED_TEAM_INTEGRATION_SIMPLY_ID',
  }));
  assert.throws(() => HelloAcceptanceConfigSchema.parse({
    ...config,
    baseUrl: 'https://api.simply360.app',
  }));
  assert.throws(() => HelloAcceptanceConfigSchema.parse({ ...config, teamId: 42 }));
  assert.throws(() => HelloAcceptanceActionSchema.parse({
    action: 'attest-provider-link',
    providerSubjectFingerprint: 'a'.repeat(64),
    providerAccountFingerprint: 'b'.repeat(64),
    externalCredentialReferenceHash: 'c'.repeat(64),
    idempotencyKey: 'attest-key-0001',
    teamIntegrationSimplyId: 'TINT-9999-ZZZZ',
  }));
});

test('loads the bearer and receipt from one exact fenced credential namespace', async (context) => {
  const originalFetch = globalThis.fetch;
  context.after(() => { globalThis.fetch = originalFetch; });
  globalThis.fetch = async () => response([]);
  const namespaces = [];
  const isolatedClients = await bindHelloAcceptanceUserCredential(config, createHelloAcceptanceClients(config, {
    installationService: '',
    teamAdmin: '',
  }), { loadCredential: async (namespace) => {
    namespaces.push(namespace);
    return storedCredential();
  } });
  const result = await runHelloAcceptanceAction({
    config,
    clients: isolatedClients,
    action: { action: 'read-records' },
  });
  assert.equal(result.outcome, 'READ');
  assert.deepEqual(namespaces, [{
    teamIntegrationSimplyId: config.teamIntegrationSimplyId,
    scope: 'member',
    memberSimplyId: config.teamUserLinkSimplyId,
    grant: 'simply360',
    integrationInstallationGrantSimplyId: config.integrationInstallationGrantSimplyId,
  }]);
  assert.doesNotMatch(JSON.stringify(result), /token|refresh/iu);
});

test('uses the packed public SDK with bearer-derived OAuth authority and Team-scoped admin authority', async (context) => {
  const originalFetch = globalThis.fetch;
  context.after(() => { globalThis.fetch = originalFetch; });
  const calls = [];
  const link = {
    accountLinkSimplyId: 'IPAL-0001-AAAA',
    teamIntegrationSimplyId: config.teamIntegrationSimplyId,
    teamUserLinkSimplyId: config.teamUserLinkSimplyId,
    status: 'ACTIVE',
  };
  const responses = [
    [{ dataRecordSimplyId: 'DREC-0001-AAAA' }],
    { dataRecordSimplyId: 'DREC-0002-AAAA' },
    { dataRecordSimplyId: 'DREC-0003-AAAA' },
    {
      accountLinkSimplyId: 'IPAL-0001-AAAA',
      integrationInstallationOperationSimplyId: 'IOPR-0001-AAAA',
      teamIntegrationSimplyId: config.teamIntegrationSimplyId,
      teamUserLinkSimplyId: 'TULK-0001-AAAA',
      integrationInstallationGrantSimplyId: 'IGRT-0001-AAAA',
      replayed: false,
    },
    [link],
    [link],
    {
      accountLinkSimplyId: 'IPAL-0001-AAAA',
      integrationInstallationOperationSimplyId: 'IOPR-0002-AAAA',
      revoked: true,
      alreadyRevoked: false,
    },
  ];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return response(responses.shift());
  };
  const instances = await clients();

  await runHelloAcceptanceAction({ config, clients: instances, action: { action: 'read-records' } });
  await runHelloAcceptanceAction({
    config,
    clients: instances,
    action: { action: 'service-write-record', title: 'Hello', idempotencyKey: 'write-key-0001' },
  });
  await runHelloAcceptanceAction({
    config,
    clients: instances,
    action: { action: 'user-write-record', title: 'Hello from user', idempotencyKey: 'user-write-0001' },
  });
  const attested = await runHelloAcceptanceAction({
    config,
    clients: instances,
    action: {
      action: 'attest-provider-link',
      providerSubjectFingerprint: 'a'.repeat(64),
      providerAccountFingerprint: 'b'.repeat(64),
      externalCredentialReferenceHash: 'c'.repeat(64),
      idempotencyKey: 'attest-key-0001',
    },
  });
  await runHelloAcceptanceAction({
    config,
    clients: instances,
    action: { action: 'list-provider-links', includeRevoked: false },
  });
  await runHelloAcceptanceAction({
    config,
    clients: instances,
    action: {
      action: 'revoke-provider-link',
      accountLinkSimplyId: 'IPAL-0001-AAAA',
      idempotencyKey: 'revoke-key-0001',
      reason: 'Private acceptance selective revocation',
    },
  });

  assert.equal(calls.length, 7);
  assert.match(calls[0].url, /\/v1\/data-records\?/u);
  assert.equal(calls[0].init.headers.Authorization, 'Bearer user-delegated-token-for-test');
  assert.equal(calls[0].init.headers['X-Team-Id'], undefined);
  assert.equal(calls[1].init.headers.Authorization, 'Bearer installation-service-token-for-test');
  assert.equal(calls[1].init.headers['X-Team-Id'], undefined);
  assert.equal(calls[2].init.headers.Authorization, 'Bearer user-delegated-token-for-test');
  assert.equal(calls[2].init.headers['X-Team-Id'], undefined);
  assert.equal(calls[3].init.headers.Authorization, 'Bearer user-delegated-token-for-test');
  assert.equal(calls[3].init.headers['X-Team-Id'], undefined);
  assert.deepEqual(JSON.parse(calls[3].init.body), {
    schemaVersion: 'simply360.external-provider-account-attestation/v1',
    providerSubjectFingerprint: 'a'.repeat(64),
    providerAccountFingerprint: 'b'.repeat(64),
    externalCredentialReferenceHash: 'c'.repeat(64),
    grantedPermissions: ['hello.read', 'hello.write'],
  });
  assert.equal(calls[4].init.headers.Authorization, 'Bearer team-admin-token-for-test');
  assert.equal(calls[4].init.headers['X-Team-Id'], config.teamSimplyId);
  assert.match(calls[5].url, /teamIntegrationSimplyId=TINT-0001-AAAA.*includeRevoked=true/u);
  assert.equal(calls[6].init.headers['Idempotency-Key'], 'revoke-key-0001');
  assert.doesNotMatch(JSON.stringify(attested), /token|fingerprint|credential/iu);
});

test('rejects a sibling or lifecycle-fenced stored credential and a sibling link before mutation dispatch', async (context) => {
  const originalFetch = globalThis.fetch;
  context.after(() => { globalThis.fetch = originalFetch; });
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return response([{
      accountLinkSimplyId: 'IPAL-0001-AAAA',
      teamIntegrationSimplyId: 'TINT-9999-ZZZZ',
      teamUserLinkSimplyId: config.teamUserLinkSimplyId,
      status: 'ACTIVE',
    }]);
  };
  const baseClients = createHelloAcceptanceClients(config, {
    installationService: '',
    teamAdmin: 'team-admin-token-for-test',
  });
  await assert.rejects(
    bindHelloAcceptanceUserCredential(config, baseClients, {
      loadCredential: async () => storedCredential({
        ...userAuthorizationIdentity,
        teamIntegrationSimplyId: 'TINT-9999-ZZZZ',
      }),
    }),
    /does not match selected acceptance coordinates/u,
  );
  assert.equal(calls.length, 0);
  await assert.rejects(
    bindHelloAcceptanceUserCredential(config, baseClients, {
      loadCredential: async () => { throw new HelloLifecycleFencedError(); },
    }),
    HelloLifecycleFencedError,
  );
  assert.equal(calls.length, 0);

  await assert.rejects(
    runHelloAcceptanceAction({
      config,
      clients: baseClients,
      action: {
        action: 'revoke-provider-link',
        accountLinkSimplyId: 'IPAL-0001-AAAA',
        idempotencyKey: 'revoke-key-0001',
        reason: 'Must not revoke sibling',
      },
    }),
    /not owned by the selected installation/u,
  );
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.method, 'GET');
});

test('executes Blueprint lifecycle only from the immediately returned public consent projection', async (context) => {
  const originalFetch = globalThis.fetch;
  context.after(() => { globalThis.fetch = originalFetch; });
  const calls = [];
  const consentProjection = {
    schemaVersion: 'simply360.external-blueprint-consent/v1',
    integrationAppVersionSimplyId: config.integrationAppVersionSimplyId,
    appPermissionHash: 'a'.repeat(64),
    packages: [{
      packageKey: 'hello-records',
      packageVersionSimplyId: 'IBPV-0001-AAAA',
      definitionHash: 'b'.repeat(64),
      artifactHash: 'c'.repeat(64),
      appVersionReferenceHash: 'd'.repeat(64),
      operation: 'INSTALL',
      changeFingerprint: 'e'.repeat(64),
      decisionsHash: 'f'.repeat(64),
    }],
  };
  const preview = {
    integrationAppVersionSimplyId: config.integrationAppVersionSimplyId,
    consentFingerprint: `consent.v1.${'9'.repeat(64)}`,
    consentProjection,
    packages: [{ packageKey: 'hello-records', packageVersionSimplyId: 'IBPV-0001-AAAA', operation: 'INSTALL', changeFingerprint: 'e'.repeat(64), changes: [] }],
  };
  const responses = [
    preview,
    { backgroundTaskSimplyId: 'BTAS-0001-AAAA', status: 'QUEUED' },
    { ...preview, packages: [{ ...preview.packages[0], operation: 'UNINSTALL' }],
      consentProjection: { ...consentProjection, packages: [{ ...consentProjection.packages[0], operation: 'UNINSTALL' }] } },
    {
      packageKey: 'hello-records',
      packageVersionSimplyId: 'IBPV-0001-AAAA',
      teamBlueprintSimplyId: 'TBPR-0001-AAAA',
      state: 'DISCONNECTED',
    },
  ];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return response(responses.shift());
  };
  const instances = await clients();

  const installed = await runHelloAcceptanceAction({
    config,
    clients: instances,
    action: { action: 'install-blueprint', idempotencyKey: 'blueprint-install-0001' },
  });
  const uninstalled = await runHelloAcceptanceAction({
    config,
    clients: instances,
    action: { action: 'uninstall-blueprint' },
  });

  assert.equal(installed.backgroundTaskSimplyId, 'BTAS-0001-AAAA');
  const installBody = JSON.parse(calls[1].init.body);
  assert.equal(installBody.consentFingerprint, preview.consentFingerprint);
  assert.deepEqual(installBody.consentProjection, consentProjection);
  assert.equal(calls[1].init.headers['Idempotency-Key'], 'blueprint-install-0001');
  assert.deepEqual(JSON.parse(calls[2].init.body), { decisions: { 'COLLECTION:hello-records': 'PRESERVE' } });
  const uninstallBody = JSON.parse(calls[3].init.body);
  assert.equal(uninstallBody.consentFingerprint, preview.consentFingerprint);
  assert.equal(uninstallBody.consentProjection.packages[0].operation, 'UNINSTALL');
  assert.deepEqual(uninstallBody.decisions, { 'COLLECTION:hello-records': 'PRESERVE' });
  assert.equal(uninstalled.teamBlueprintSimplyId, 'TBPR-0001-AAAA');
});

test('rejects an unexpected Blueprint package before execute', async (context) => {
  const originalFetch = globalThis.fetch;
  context.after(() => { globalThis.fetch = originalFetch; });
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return response({
      integrationAppVersionSimplyId: config.integrationAppVersionSimplyId,
      consentFingerprint: `consent.v1.${'9'.repeat(64)}`,
      consentProjection: {
        schemaVersion: 'simply360.external-blueprint-consent/v1',
        integrationAppVersionSimplyId: config.integrationAppVersionSimplyId,
        appPermissionHash: 'a'.repeat(64),
        packages: [{ packageKey: 'sibling', operation: 'INSTALL' }],
      },
      packages: [{ packageKey: 'sibling', changeFingerprint: 'e'.repeat(64), changes: [] }],
    });
  };
  await assert.rejects(
    runHelloAcceptanceAction({
      config,
      clients: await clients(),
      action: { action: 'install-blueprint', idempotencyKey: 'blueprint-install-0001' },
    }),
    /does not match the selected app version and package/u,
  );
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.method, 'POST');
});

const lifecyclePreview = (operation, version = config.integrationAppVersionSimplyId, changes = []) => ({
  integrationAppVersionSimplyId: version,
  consentFingerprint: `consent.v1.${'9'.repeat(64)}`,
  consentProjection: {
    schemaVersion: 'simply360.external-blueprint-consent/v1',
    integrationAppVersionSimplyId: version,
    appPermissionHash: 'a'.repeat(64),
    packages: [{ packageKey: 'hello-records', packageVersionSimplyId: 'IBPV-0002-AAAA',
      definitionHash: 'b'.repeat(64), artifactHash: 'c'.repeat(64), appVersionReferenceHash: 'd'.repeat(64),
      operation, changeFingerprint: 'e'.repeat(64), decisionsHash: 'f'.repeat(64) }],
  },
  packages: [{ packageKey: 'hello-records', packageVersionSimplyId: 'IBPV-0002-AAAA', operation,
    changeFingerprint: 'e'.repeat(64), changes }],
});

const currentRoleSelection = (overrides = {}) => ({
  teamIntegrationSimplyId: config.teamIntegrationSimplyId,
  integrationAppVersionSimplyId: config.integrationAppVersionSimplyId,
  integrationInstallationEpochSimplyId: 'IIEP-0001-AAAA',
  authorityRevision: 7,
  roleSelection: {
    schemaVersion: 'simply360.integration-installation-role-snapshot/v1',
    collections: [{
      dataCollectionSimplyId: config.dataCollectionSimplyId,
      defaultFieldPermissionType: 'ALLOW_UPDATE',
      actions: ['CREATE_RECORDS', 'READ_RECORD_METADATA'],
    }],
    fields: [{
      dataFieldSimplyId: config.titleDataFieldSimplyId,
      dataCollectionSimplyId: config.dataCollectionSimplyId,
      permissionType: 'ALLOW_UPDATE',
    }],
    features: [],
  },
  ...overrides,
});

const compareCodeUnits = (left, right) => (left < right ? -1 : left > right ? 1 : 0);
const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.entries(value).sort(([left], [right]) => compareCodeUnits(left, right))
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(',')}}`;
  }
  return JSON.stringify(value);
};
const hash = (value) => createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');

const reviewedEffects = (blueprint, overrides = {}) => ({
  schemaVersion: 'simply360.hello-installation-version-upgrade-reviewed-effects/v1',
  teamIntegrationSimplyId: config.teamIntegrationSimplyId,
  sourceIntegrationAppVersionSimplyId: config.integrationAppVersionSimplyId,
  sourceIntegrationAppReleaseSimplyId: 'IARL-0001-AAAA',
  sourceIntegrationInstallationEpochSimplyId: 'IIEP-0001-AAAA',
  targetIntegrationAppVersionSimplyId: 'IAVR-0002-AAAA',
  targetIntegrationAppReleaseSimplyId: 'IARL-0002-AAAA',
  expectedAuthorityRevision: 7,
  roleSelectionHash: hash(currentRoleSelection().roleSelection),
  sharedBlueprintSiblingTeamIntegrationSimplyIds: ['TINT-0002-BBBB'],
  revokedGrantCount: 1,
  reconsentRequiredProviderAccountLinkCount: 2,
  externalBlueprintConsent: {
    projection: blueprint.consentProjection,
    consentFingerprint: blueprint.consentFingerprint,
  },
  ...overrides,
});

const applyVersionUpgradeAction = (blueprint, overrides = {}) => {
  const expectedReviewedEffects = reviewedEffects(blueprint);
  return {
    action: 'apply-installation-version-upgrade',
    targetIntegrationAppVersionSimplyId: 'IAVR-0002-AAAA',
    sourceIntegrationInstallationEpochSimplyId: 'IIEP-0001-AAAA',
    expectedAuthorityRevision: 7,
    decisions: { 'new-managed-collection': { action: 'APPLY' } },
    expectedReviewedEffects,
    expectedReviewedEffectsHash: hash(expectedReviewedEffects),
    idempotencyKey: 'installation-upgrade-0001',
    ...overrides,
  };
};

const installationVersionPreview = (blueprint, overrides = {}) => ({
  consentPreviewSimplyId: 'ICPV-0001-AAAA',
  teamIntegrationSimplyId: config.teamIntegrationSimplyId,
  integrationAppVersionSimplyId: 'IAVR-0002-AAAA',
  sourceIntegrationAppVersionSimplyId: config.integrationAppVersionSimplyId,
  sourceIntegrationAppReleaseSimplyId: 'IARL-0001-AAAA',
  sourceIntegrationInstallationEpochSimplyId: 'IIEP-0001-AAAA',
  targetIntegrationAppReleaseSimplyId: 'IARL-0002-AAAA',
  roleSelection: currentRoleSelection().roleSelection,
  externalBlueprint: {
    projection: blueprint.consentProjection,
    consentFingerprint: blueprint.consentFingerprint,
  },
  signedConsent: {
    consent: {
      teamIntegrationSimplyId: config.teamIntegrationSimplyId,
      integrationAppVersionSimplyId: 'IAVR-0002-AAAA',
      externalBlueprint: blueprint.consentProjection,
      externalBlueprintConsentFingerprint: blueprint.consentFingerprint,
    },
    signature: 'signature-not-projected',
  },
  consentFingerprint: `consent.v1.${'8'.repeat(64)}`,
  csrfState: 'csrf-kept-in-memory-only',
  expiresAt: '2026-09-06T20:00:00.000Z',
  sharedBlueprintSiblingTeamIntegrationSimplyIds: ['TINT-0002-BBBB'],
  revokedGrantCount: 1,
  reconsentRequiredProviderAccountLinkCount: 2,
  ...overrides,
});

const installationVersionCommit = (overrides = {}) => ({
  outcome: 'PENDING_SETUP',
  status: 'PENDING_SETUP',
  teamIntegrationSimplyId: config.teamIntegrationSimplyId,
  sourceIntegrationInstallationEpochSimplyId: 'IIEP-0001-AAAA',
  targetIntegrationInstallationEpochSimplyId: 'IIEP-0002-AAAA',
  integrationInstallationConsentSimplyId: 'IICO-0002-AAAA',
  integrationInstallationOperationSimplyId: 'IIOP-0002-AAAA',
  authorityRevision: 8,
  revokedGrantCount: 1,
  reconsentRequiredProviderAccountLinkCount: 2,
  materializationEffect: 'ENQUEUED',
  ...overrides,
});

const installationVersionReadback = (overrides = {}) => ({
  integration: {
    teamIntegrationSimplyId: config.teamIntegrationSimplyId,
    integrationAppVersionSimplyId: 'IAVR-0002-AAAA',
    installationStatus: 'PENDING_SETUP',
    ...overrides,
  },
});

const installationVersionCommitPacket = (blueprint, payloadOverrides = {}) => {
  const effects = reviewedEffects(blueprint);
  const payload = {
    teamSimplyId: config.teamSimplyId,
    reviewedEffects: effects,
    reviewedEffectsHash: hash(effects),
    consentPreviewSimplyId: 'ICPV-0001-AAAA',
    previewConsentFingerprint: `consent.v1.${'8'.repeat(64)}`,
    previewExpiresAt: '2026-09-06T20:00:00.000Z',
    csrfState: 'csrf-kept-in-memory-only',
    idempotencyKey: 'installation-upgrade-0001',
    ...payloadOverrides,
  };
  return {
    schemaVersion: 'simply360.hello-installation-version-upgrade-commit-packet/v1',
    payload,
    packetHash: hash(payload),
  };
};

const managedProvenance = (blueprintEntityType, blueprintRef) => ({
  blueprintEntityType, blueprintRef, ownershipDisposition: 'BLUEPRINT_MANAGED',
  teamBlueprintSimplyId: 'TBPR-0001-AAAA', blueprintDefinitionSimplyId: 'BPDF-0001-AAAA',
  blueprintSlug: 'hello-records', blueprintVersionSimplyId: 'BPVR-0002-AAAA', blueprintVersion: '1.0.10',
});
const managedCollection = { dataCollectionSimplyId: 'DCOL-0002-AAAA',
  blueprintProvenance: [managedProvenance('DATA_COLLECTION', 'hello-integration-notes')] };
const managedField = (title) => ({ dataFieldSimplyId: 'DFLD-0002-AAAA', title: { en: { val: title } },
  blueprintProvenance: [managedProvenance('DATA_FIELD', 'hello-integration-notes.note')] });
const driftResult = (drifted) => ({ teamBlueprintSimplyId: 'TBPR-0001-AAAA', drifted, report: { errorCount: 0 } });

const captureResponses = (context, responses) => {
  const originalFetch = globalThis.fetch;
  context.after(() => { globalThis.fetch = originalFetch; });
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    assert.ok(responses.length, 'Unexpected extra public API request');
    return response(responses.shift());
  };
  return calls;
};

test('upgrades with explicit current decisions and an immediately returned target-version projection', async (context) => {
  const change = { changeId: 'new-managed-collection', allowedDecisions: ['APPLY', 'MAP_EXISTING'], requiresDecision: true };
  const preview = lifecyclePreview('UPGRADE', 'IAVR-0002-AAAA', [change]);
  const calls = captureResponses(context, [preview, { backgroundTaskSimplyId: 'BTAS-0002-AAAA', status: 'QUEUED' }]);
  const result = await runHelloAcceptanceAction({ config, clients: await clients(), action: {
    action: 'upgrade-blueprint', targetIntegrationAppVersionSimplyId: 'IAVR-0002-AAAA',
    decisions: { 'new-managed-collection': { action: 'APPLY' } }, idempotencyKey: 'blueprint-upgrade-0001',
  } });
  assert.equal(result.outcome, 'UPGRADE_QUEUED');
  assert.equal(calls.length, 2);
  assert.match(calls[0].url, /external-blueprints\/upgrade\/preview$/u);
  assert.equal(calls[1].init.headers['X-Team-Id'], config.teamSimplyId);
  assert.equal(calls[1].init.headers['Idempotency-Key'], 'blueprint-upgrade-0001');
  assert.deepEqual(JSON.parse(calls[1].init.body), {
    targetIntegrationAppVersionSimplyId: 'IAVR-0002-AAAA', decisionsByPackageKey: { 'hello-records': { 'new-managed-collection': { action: 'APPLY' } } },
    consentFingerprint: preview.consentFingerprint, consentProjection: preview.consentProjection,
  });
});

test('refuses missing upgrade choices and wrong operation or target before dispatch', async (context) => {
  const change = { changeId: 'required-change', allowedDecisions: ['APPLY'], requiresDecision: true };
  const calls = captureResponses(context, [
    lifecyclePreview('UPGRADE', 'IAVR-0002-AAAA', [change]),
    lifecyclePreview('INSTALL', 'IAVR-0002-AAAA'),
    lifecyclePreview('UPGRADE', 'IAVR-9999-ZZZZ'),
    lifecyclePreview('UPGRADE', 'IAVR-0002-AAAA', [change]),
    lifecyclePreview('UPGRADE', 'IAVR-0002-AAAA', [{
      ...change,
      allowedDecisions: ['MAP_EXISTING'],
      mappedEntitySimplyId: 'DCOL-0002-AAAA',
    }]),
  ]);
  const instances = await clients();
  const action = { action: 'upgrade-blueprint', targetIntegrationAppVersionSimplyId: 'IAVR-0002-AAAA',
    decisions: {}, idempotencyKey: 'blueprint-upgrade-0002' };
  await assert.rejects(runHelloAcceptanceAction({ config, clients: instances, action }), /every current explicit decision/u);
  await assert.rejects(runHelloAcceptanceAction({ config, clients: instances, action }), /does not match/u);
  await assert.rejects(runHelloAcceptanceAction({ config, clients: instances, action }), /does not match/u);
  await assert.rejects(runHelloAcceptanceAction({ config, clients: instances,
    action: { ...action, decisions: { unrelated: { action: 'APPLY' } } } }), /outside the current preview/u);
  await assert.rejects(runHelloAcceptanceAction({ config, clients: instances,
    action: { ...action, decisions: { 'required-change': { action: 'MAP_EXISTING', mappedEntitySimplyId: 'DCOL-9999-ZZZZ' } } } }),
  /exact public candidate/u);
  assert.equal(calls.length, 5);
  assert.ok(calls.every((call) => call.url.endsWith('/preview')));
  assert.throws(() => HelloAcceptanceActionSchema.parse({ ...action, decisions: { destructive: { action: 'DELETE' } } }));
});

test('previews one exact installation version using its persisted role and fresh combined Blueprint consent', async (context) => {
  const blueprint = lifecyclePreview('UPGRADE', 'IAVR-0002-AAAA', [
    { changeId: 'new-managed-collection', allowedDecisions: ['APPLY'], requiresDecision: true },
  ]);
  const preview = installationVersionPreview(blueprint);
  const calls = captureResponses(context, [currentRoleSelection(), blueprint, preview]);
  const result = await runHelloAcceptanceAction({
    config,
    clients: await clients(),
    action: {
      action: 'preview-installation-version-upgrade',
      targetIntegrationAppVersionSimplyId: 'IAVR-0002-AAAA',
      sourceIntegrationInstallationEpochSimplyId: 'IIEP-0001-AAAA',
      expectedAuthorityRevision: 7,
      decisions: { 'new-managed-collection': { action: 'APPLY' } },
    },
  });

  assert.equal(result.outcome, 'INSTALLATION_VERSION_UPGRADE_PREVIEWED');
  assert.deepEqual(result.sharedBlueprintSiblingTeamIntegrationSimplyIds, ['TINT-0002-BBBB']);
  assert.deepEqual(result.reviewedEffects, reviewedEffects(blueprint));
  assert.equal(result.reviewedEffectsHash, hash(result.reviewedEffects));
  assert.doesNotMatch(JSON.stringify(result), /csrf|signature/iu);
  assert.equal(Object.hasOwn(result, 'roleSelection'), false);
  assert.equal(calls.length, 3);
  assert.match(calls[0].url, /consent-role-selection$/u);
  assert.match(calls[1].url, /external-blueprints\/upgrade\/preview$/u);
  assert.match(calls[2].url, /version-upgrade-preview$/u);
  assert.deepEqual(JSON.parse(calls[1].init.body), {
    targetIntegrationAppVersionSimplyId: 'IAVR-0002-AAAA',
    decisionsByPackageKey: { 'hello-records': { 'new-managed-collection': { action: 'APPLY' } } },
  });
  assert.deepEqual(JSON.parse(calls[2].init.body), {
    targetIntegrationAppVersionSimplyId: 'IAVR-0002-AAAA',
    roleSelection: currentRoleSelection().roleSelection,
    externalBlueprintConsent: {
      projection: blueprint.consentProjection,
      consentFingerprint: blueprint.consentFingerprint,
    },
  });
});

test('applies only its fresh preview with one fixed header key and keeps CSRF in memory', async (context) => {
  const blueprint = lifecyclePreview('UPGRADE', 'IAVR-0002-AAAA', [
    { changeId: 'new-managed-collection', allowedDecisions: ['APPLY'], requiresDecision: true },
  ]);
  const preview = installationVersionPreview(blueprint);
  const calls = captureResponses(context, [
    currentRoleSelection(), blueprint, preview, installationVersionCommit(), installationVersionReadback(),
  ]);
  const saved = [];
  const result = await runHelloAcceptanceAction({
    config,
    clients: await clients(),
    action: applyVersionUpgradeAction(blueprint),
    installationVersionUpgradePacketStore: { save: async (packet) => { saved.push(packet); } },
  });

  assert.equal(result.outcome, 'PENDING_SETUP');
  assert.equal(result.integrationInstallationOperationSimplyId, 'IIOP-0002-AAAA');
  assert.doesNotMatch(JSON.stringify(result), /csrf|signature|roleSelection/iu);
  assert.equal(calls.length, 5);
  assert.match(calls[3].url, /version-upgrade-commit$/u);
  assert.match(calls[4].url, /team-integrations\/TINT-0001-AAAA$/u);
  assert.equal(calls[3].init.headers['Idempotency-Key'], 'installation-upgrade-0001');
  assert.deepEqual(JSON.parse(calls[3].init.body), {
    consentPreviewSimplyId: 'ICPV-0001-AAAA',
    csrfState: 'csrf-kept-in-memory-only',
  });
  assert.equal(saved.length, 1);
  assert.equal(saved[0].packetHash, result.recoveryPacketHash);
  assert.equal(saved[0].payload.reviewedEffectsHash, result.reviewedEffectsHash);
  assert.equal(result.readbackInstallationStatus, 'PENDING_SETUP');
  assert.doesNotMatch(JSON.stringify(result), /idempotency|csrf/iu);
});

test('refuses changed sibling and revocation effects after human review before commit', async (context) => {
  const change = { changeId: 'new-managed-collection', allowedDecisions: ['APPLY'], requiresDecision: true };
  const blueprint = lifecyclePreview('UPGRADE', 'IAVR-0002-AAAA', [change]);
  const action = applyVersionUpgradeAction(blueprint);
  const calls = captureResponses(context, [
    currentRoleSelection(), blueprint, installationVersionPreview(blueprint, {
      sharedBlueprintSiblingTeamIntegrationSimplyIds: ['TINT-0003-CCCC'],
    }),
    currentRoleSelection(), blueprint, installationVersionPreview(blueprint, {
      revokedGrantCount: 2,
    }),
    currentRoleSelection(), blueprint, installationVersionPreview(blueprint, {
      reconsentRequiredProviderAccountLinkCount: 3,
    }),
  ]);
  const store = { save: async () => assert.fail('drift must be rejected before packet persistence') };

  await assert.rejects(runHelloAcceptanceAction({ config, clients: await clients(), action,
    installationVersionUpgradePacketStore: store }), /differ from the explicitly reviewed preview/u);
  await assert.rejects(runHelloAcceptanceAction({ config, clients: await clients(), action,
    installationVersionUpgradePacketStore: store }), /differ from the explicitly reviewed preview/u);
  await assert.rejects(runHelloAcceptanceAction({ config, clients: await clients(), action,
    installationVersionUpgradePacketStore: store }), /differ from the explicitly reviewed preview/u);
  assert.equal(calls.length, 9);
  assert.ok(calls.every(({ url }) => !url.endsWith('/version-upgrade-commit')));
});

test('retains the exact pre-dispatch packet after lost success and replays without creating new previews', async (context) => {
  const change = { changeId: 'new-managed-collection', allowedDecisions: ['APPLY'], requiresDecision: true };
  const blueprint = lifecyclePreview('UPGRADE', 'IAVR-0002-AAAA', [change]);
  const action = applyVersionUpgradeAction(blueprint);
  const originalFetch = globalThis.fetch;
  context.after(() => { globalThis.fetch = originalFetch; });
  const initialResponses = [currentRoleSelection(), blueprint, installationVersionPreview(blueprint)];
  const initialCalls = [];
  globalThis.fetch = async (url, init) => {
    initialCalls.push({ url: String(url), init });
    if (initialResponses.length > 0) return response(initialResponses.shift());
    throw new Error('simulated lost success response');
  };
  const saved = [];
  await assert.rejects(runHelloAcceptanceAction({
    config,
    clients: await clients(),
    action,
    installationVersionUpgradePacketStore: { save: async (packet) => { saved.push(packet); } },
  }), /lost success/u);
  assert.equal(saved.length, 1);
  assert.equal(initialCalls.length, 4);
  assert.equal(HelloInstallationVersionUpgradeCommitPacketSchema.safeParse(saved[0]).success, true);

  const replayCalls = [];
  const replayResponses = [installationVersionCommit({ outcome: 'ALREADY_APPLIED' }),
    installationVersionReadback({ installationStatus: 'ACTIVE' })];
  globalThis.fetch = async (url, init) => {
    replayCalls.push({ url: String(url), init });
    return response(replayResponses.shift());
  };
  const result = await runHelloAcceptanceAction({
    config,
    clients: await clients(),
    action: { action: 'replay-installation-version-upgrade-commit', packet: saved[0] },
  });
  assert.equal(result.outcome, 'ALREADY_APPLIED');
  assert.equal(result.readbackInstallationStatus, 'ACTIVE');
  assert.equal(replayCalls.length, 2);
  assert.match(replayCalls[0].url, /version-upgrade-commit$/u);
  assert.match(replayCalls[1].url, /team-integrations\/TINT-0001-AAAA$/u);
  assert.ok(replayCalls.every(({ url }) => !url.includes('preview')));
  assert.equal(replayCalls[0].init.headers['Idempotency-Key'], action.idempotencyKey);
});

test('rejects tampered recovery packets and invalid commit/readback evidence', async (context) => {
  const blueprint = lifecyclePreview('UPGRADE', 'IAVR-0002-AAAA', [
    { changeId: 'new-managed-collection', allowedDecisions: ['APPLY'], requiresDecision: true },
  ]);
  const packet = installationVersionCommitPacket(blueprint);
  const tampered = structuredClone(packet);
  tampered.payload.idempotencyKey = 'installation-upgrade-tampered';
  assert.equal(HelloInstallationVersionUpgradeCommitPacketSchema.safeParse(tampered).success, false);

  const calls = captureResponses(context, [
    installationVersionCommit({ revokedGrantCount: 9 }),
    installationVersionCommit({ reconsentRequiredProviderAccountLinkCount: 9 }),
    { ...installationVersionCommit(), integrationInstallationConsentSimplyId: 'invalid' },
    installationVersionCommit(), installationVersionReadback({ integrationAppVersionSimplyId: 'IAVR-9999-ZZZZ' }),
  ]);
  const replay = (selected = packet) => runHelloAcceptanceAction({
    config,
    clients: createHelloAcceptanceClients(config, {
      installationService: 'installation-service-token-for-test',
      teamAdmin: 'team-admin-token-for-test',
    }),
    action: { action: 'replay-installation-version-upgrade-commit', packet: selected },
  });
  await assert.rejects(replay(), /explicitly reviewed effects/u);
  await assert.rejects(replay(), /explicitly reviewed effects/u);
  await assert.rejects(replay(), /expected string to match pattern|Invalid string/iu);
  await assert.rejects(replay(), /does not prove the reviewed target version/u);
  await assert.rejects(replay(tampered), /Recovery packet hash/u);
  assert.equal(calls.length, 5);
});

test('persists one exact private recovery packet and refuses overwrite, loose mode, and tampering', async (context) => {
  const blueprint = lifecyclePreview('UPGRADE', 'IAVR-0002-AAAA');
  const packet = installationVersionCommitPacket(blueprint);
  const path = join(tmpdir(), `hello-upgrade-recovery-${process.pid}-${Date.now()}.json`);
  context.after(() => { try { unlinkSync(path); } catch {} });
  const store = createHelloInstallationVersionUpgradePacketFileStore(path);
  await store.save(packet);
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.deepEqual(await readHelloInstallationVersionUpgradeCommitPacket(path), packet);
  await assert.rejects(store.save(packet), /exist/iu);

  chmodSync(path, 0o644);
  await assert.rejects(readHelloInstallationVersionUpgradeCommitPacket(path), /0600/u);
  chmodSync(path, 0o600);
  const tampered = structuredClone(packet);
  tampered.payload.csrfState = 'tampered-csrf-state-value';
  writeFileSync(path, JSON.stringify(tampered), { mode: 0o600 });
  await assert.rejects(readHelloInstallationVersionUpgradeCommitPacket(path), /Recovery packet hash/u);
});

test('refuses stale source authority, changed role, wrong target, and Team denial without mutation retry', async (context) => {
  const change = { changeId: 'new-managed-collection', allowedDecisions: ['APPLY'], requiresDecision: true };
  const blueprint = lifecyclePreview('UPGRADE', 'IAVR-0002-AAAA', [change]);
  const action = applyVersionUpgradeAction(blueprint, { idempotencyKey: 'installation-upgrade-0002' });
  const calls = captureResponses(context, [
    currentRoleSelection({ authorityRevision: 8 }),
    currentRoleSelection(), blueprint, installationVersionPreview(blueprint, {
      roleSelection: { ...currentRoleSelection().roleSelection, features: [{ featurePermissionKey: 'UNREVIEWED', hasEditPermission: true }] },
    }),
    currentRoleSelection(), lifecyclePreview('UPGRADE', 'IAVR-9999-ZZZZ', [change]),
  ]);
  const instances = await clients();
  const store = { save: async () => assert.fail('must not save before preview validation') };
  await assert.rejects(runHelloAcceptanceAction({ config, clients: instances, action,
    installationVersionUpgradePacketStore: store }), /source coordinates/u);
  await assert.rejects(runHelloAcceptanceAction({ config, clients: instances, action,
    installationVersionUpgradePacketStore: store }), /reviewed installation authority/u);
  await assert.rejects(runHelloAcceptanceAction({ config, clients: instances, action,
    installationVersionUpgradePacketStore: store }), /selected app version and package/u);
  assert.equal(calls.length, 6);
  assert.ok(calls.every(({ url }) => !url.endsWith('/version-upgrade-commit')));

  const originalFetch = globalThis.fetch;
  let deniedCalls = 0;
  globalThis.fetch = async () => {
    deniedCalls += 1;
    return ({
    ok: false,
    status: 403,
    text: async () => JSON.stringify({ error: 'Team authority denied', code: 'TEAM_ACCESS_DENIED' }),
    headers: { forEach: () => {} },
    });
  };
  try {
    await assert.rejects(runHelloAcceptanceAction({ config, clients: instances, action,
      installationVersionUpgradePacketStore: store }), /Team authority denied/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(deniedCalls, 1);
});

test('CLI requires an explicit apply flag before installation-version mutation setup', () => {
  const configPath = join(tmpdir(), `hello-consent-config-${process.pid}.json`);
  writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 });
  const result = spawnSync(process.execPath, [
    'scripts/run-hello-acceptance.mjs',
    'apply-installation-version-upgrade',
    '--config', configPath,
    '--source-epoch-simply-id', 'IIEP-0001-AAAA',
    '--expected-authority-revision', '7',
    '--target-app-version-simply-id', 'IAVR-0002-AAAA',
    '--decisions-path', '/private/not-read-without-apply.json',
    '--idempotency-key', 'installation-upgrade-0003',
  ], { cwd: process.cwd(), encoding: 'utf8' });
  unlinkSync(configPath);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /requires --apply/u);
  assert.doesNotMatch(result.stderr, /token|credential/iu);
});

test('introduces reversible managed-field drift using only exact public provenance and confirms it', async (context) => {
  const calls = captureResponses(context, [driftResult(false), [managedCollection], [managedField('Note')],
    { result: {} }, driftResult(true), [managedCollection], [managedField('Note (private acceptance drift)')]]);
  const result = await runHelloAcceptanceAction({ config, clients: await clients(), action: { action: 'introduce-blueprint-drift' } });
  assert.equal(result.outcome, 'DRIFT_CONFIRMED');
  assert.equal(result.dataFieldSimplyId, 'DFLD-0002-AAAA');
  assert.equal(calls.filter(({ init }) => init.method === 'PUT').length, 1);
  assert.match(calls[3].url, /\/v1\/data-fields\/DFLD-0002-AAAA$/u);
  assert.deepEqual(JSON.parse(calls[3].init.body), { title: { en: 'Note (private acceptance drift)' } });
  assert.ok(calls.every(({ init }) => init.headers['X-Team-Id'] === config.teamSimplyId));
});

test('will not mutate existing drift, ambiguous ownership, or a changed field title', async (context) => {
  const calls = captureResponses(context, [driftResult(true), driftResult(false), [managedCollection, managedCollection],
    driftResult(false), [managedCollection], [managedField('Unrelated edit')]]);
  const instances = await clients();
  const invoke = () => runHelloAcceptanceAction({ config, clients: instances, action: { action: 'introduce-blueprint-drift' } });
  await assert.rejects(invoke(), /requires a clean/u);
  await assert.rejects(invoke(), /exactly one reviewed integration-owned collection/u);
  await assert.rejects(invoke(), /field title has changed/u);
  assert.ok(calls.every(({ init }) => init.method === 'GET'));
});

test('reconciles using fresh consent and verifies both no drift and restored managed title', async (context) => {
  const preview = lifecyclePreview('RECONCILE');
  const calls = captureResponses(context, [preview, driftResult(false), driftResult(false), [managedCollection], [managedField('Note')]]);
  const result = await runHelloAcceptanceAction({ config, clients: await clients(), action: { action: 'reconcile-blueprint' } });
  assert.equal(result.outcome, 'RECONCILED');
  assert.deepEqual(JSON.parse(calls[1].init.body), { consentFingerprint: preview.consentFingerprint,
    consentProjection: preview.consentProjection });
  assert.equal(result.drifted, false);
  assert.equal(result.dataFieldSimplyId, 'DFLD-0002-AAAA');
});

test('does not claim successful reconciliation when public readback retains drift', async (context) => {
  captureResponses(context, [lifecyclePreview('RECONCILE'), driftResult(false), driftResult(true), [managedCollection], [managedField('Note')]]);
  await assert.rejects(runHelloAcceptanceAction({ config, clients: await clients(), action: { action: 'reconcile-blueprint' } }),
    /did not restore/u);
});
