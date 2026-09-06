import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';

import { AppManifestV1Schema } from '@simply360/integration-sdk/manifest';

import {
  HELLO_BLUEPRINT_PACKAGE_KEY,
  HELLO_BASELINE_SEMANTIC_VERSION,
  HELLO_BASELINE_SOURCE_COMMIT,
  HELLO_LIFECYCLE_EVENT_TYPES,
  HELLO_MANAGED_COLLECTION_REF,
  HELLO_MANAGED_FIELD_REF,
  HELLO_MANAGED_FIELD_TITLE,
  HELLO_PROVIDER_PERMISSIONS,
  HELLO_SERVICE_CLIENT_KEY,
  HELLO_SUBSCRIPTION_EVENT_TYPES,
  HELLO_USER_CLIENT_KEY,
  HELLO_USER_SCOPES,
  HELLO_UPGRADE_LIFECYCLE_EVENT_TYPES,
  HELLO_UPGRADE_SEMANTIC_VERSION,
  buildHelloAcceptanceBundle,
} from '../dist/index.js';

const upgradeSourceCommit = '0123456789abcdef0123456789abcdef01234567';
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const prettyJsonSha256 = (value) => sha256(`${JSON.stringify(value, null, 2)}\n`);

test('builds a provider-neutral HYBRID manifest and public Blueprint package from packed SDKs', async () => {
  const bundle = await buildHelloAcceptanceBundle({
    sourceCommit: HELLO_BASELINE_SOURCE_COMMIT,
    semanticVersion: HELLO_BASELINE_SEMANTIC_VERSION,
  });
  assert.doesNotThrow(() => AppManifestV1Schema.parse(bundle.manifest));
  assert.equal(bundle.manifest.provenance.sourceCommit, HELLO_BASELINE_SOURCE_COMMIT);
  assert.equal(bundle.blueprintPackage.provenance.sourceCommit, HELLO_BASELINE_SOURCE_COMMIT);
  assert.equal(bundle.manifest.blueprintPackages[0].packageKey, HELLO_BLUEPRINT_PACKAGE_KEY);
  assert.equal(bundle.manifest.blueprintPackages[0].sha256, bundle.blueprintPackageSha256);
  assert.equal(bundle.manifest.blueprintPackages[0].required, true);

  const serviceClient = bundle.manifest.oauth.clients.find(({ clientKey }) => clientKey === HELLO_SERVICE_CLIENT_KEY);
  const userClient = bundle.manifest.oauth.clients.find(({ clientKey }) => clientKey === HELLO_USER_CLIENT_KEY);
  assert.deepEqual(
    { type: serviceClient?.clientType, auth: serviceClient?.tokenEndpointAuthMethod, grants: serviceClient?.grantModes },
    { type: 'SERVER', auth: 'CLIENT_SECRET_BASIC', grants: ['teamInstallation'] },
  );
  assert.ok(serviceClient?.scopes.includes('records:write'));
  assert.deepEqual(
    { type: userClient?.clientType, auth: userClient?.tokenEndpointAuthMethod, grants: userClient?.grantModes },
    { type: 'NATIVE', auth: 'NONE', grants: ['userDelegated'] },
  );
  assert.ok(userClient?.scopes.includes('records:write'));
  assert.deepEqual(userClient?.scopes, [...HELLO_USER_SCOPES].sort());
  assert.equal(bundle.manifest.oauth.perUserLinkMultiplicity, 'MULTIPLE_PER_USER');
  assert.deepEqual(userClient?.externalProviderAccount, {
    credentialCustody: 'EXTERNAL_CONNECTOR',
    providerPermissions: [...HELLO_PROVIDER_PERMISSIONS],
  });

  assert.deepEqual(bundle.manifest.eventDestinations[0].eventTypes, [...HELLO_SUBSCRIPTION_EVENT_TYPES].sort());
  assert.deepEqual(bundle.manifest.lifecycle.notifications.eventTypes, [...HELLO_LIFECYCLE_EVENT_TYPES].sort());
  assert.match(bundle.manifest.oauth.clients[0].redirectUris[0], /\/oauth\/simply360\/callback$/u);
  assert.match(bundle.manifest.eventDestinations[0].exactUrl, /\/events\/simply360$/u);
  assert.match(bundle.manifest.lifecycle.setupLaunchUrl, /\/oauth\/simply360\/start$/u);
  assert.match(bundle.manifest.lifecycle.notifications.exactUrl, /\/lifecycle$/u);
  assert.deepEqual(bundle.manifest.remoteActions, []);
  assert.deepEqual(bundle.manifest.remoteTriggers, []);

  const serialized = JSON.stringify(bundle);
  assert.doesNotMatch(serialized, /(?:^|")(?:id|teamId|installationId|memberId|recordId)"\s*:/iu);
  assert.doesNotMatch(serialized, /"(?:client_secret|access_token|refresh_token)"\s*:|xox[baprs]-/iu);
});

test('preserves every reviewed 3848891/1.0.9 asset byte while selecting the historical definition', async () => {
  const baseline = await buildHelloAcceptanceBundle({
    sourceCommit: HELLO_BASELINE_SOURCE_COMMIT,
    semanticVersion: HELLO_BASELINE_SEMANTIC_VERSION,
  });
  const bundleReceipt = {
    sourceCommit: HELLO_BASELINE_SOURCE_COMMIT,
    semanticVersion: HELLO_BASELINE_SEMANTIC_VERSION,
    blueprintPackageSha256: baseline.blueprintPackageSha256,
  };

  assert.equal(baseline.blueprintPackageSha256, '73c11cc95a484bc987699469c1435e7414f6eb72f90f38b1aafcd0cba7135eaf');
  assert.equal(prettyJsonSha256(baseline.manifest), 'b6416921bd4e82aadc9edb542dfb47b9334c464a37a1ecda95629b5c4df64aa2');
  assert.equal(prettyJsonSha256(baseline.blueprintPackage), 'd294fabcb3436b449e1f2b4b16bf8a0bb32fe2d722f7aeb14ec2fb1c5be3ddb0');
  assert.equal(prettyJsonSha256(bundleReceipt), '09cb6d63801f86db9cba425a38a3b5f8c810467cf0aa1ef1d9490b85665745c1');
  assert.deepEqual(baseline.blueprintPackage.definition.collections.map(({ collectionKey }) => collectionKey), ['hello-records']);
});

test('builds 1.0.10 as one additional integration-owned collection with one managed field', async () => {
  const upgrade = await buildHelloAcceptanceBundle({
    sourceCommit: upgradeSourceCommit,
    semanticVersion: HELLO_UPGRADE_SEMANTIC_VERSION,
  });
  assert.doesNotThrow(() => AppManifestV1Schema.parse(upgrade.manifest));
  assert.equal(upgrade.manifest.provenance.sourceCommit, upgradeSourceCommit);
  assert.equal(upgrade.manifest.app.semanticVersion, HELLO_UPGRADE_SEMANTIC_VERSION);
  assert.deepEqual(upgrade.manifest.lifecycle.notifications.eventTypes, [...HELLO_UPGRADE_LIFECYCLE_EVENT_TYPES].sort());
  assert.deepEqual(upgrade.manifest.lifecycle.notifications.eventTypes, [
    'app.account-link.revoked',
    'app.grant.revoked',
    'app.install.completed',
    'app.setup.completed',
    'app.uninstalled',
    'app.upgrade.completed',
  ]);

  const teamCollection = upgrade.blueprintPackage.definition.collections.find(({ collectionKey }) => collectionKey === 'hello-records');
  assert.deepEqual(teamCollection, {
    calculatedName: { fieldKey: 'title', kind: 'FIELD' },
    collectionKey: 'hello-records',
    description: { en: 'Synthetic records used only for private integration acceptance.' },
    fields: [
      { fieldKey: 'greeted', kind: 'BOOLEAN', label: { en: 'Greeted' }, required: false },
      { fieldKey: 'greeted-on', kind: 'DATE', label: { en: 'Greeted on' }, required: false },
      { fieldKey: 'title', kind: 'TEXT', label: { en: 'Title' }, maxLength: 200, required: true },
    ],
    label: { en: 'Hello records' },
    lifecycleOwner: 'TEAM',
    recordLifecycle: 'ACTIVE_ONLY',
    sharedContractKeys: [],
  });
  const managedCollection = upgrade.blueprintPackage.definition.collections.find(
    ({ collectionKey }) => collectionKey === HELLO_MANAGED_COLLECTION_REF,
  );
  assert.deepEqual(managedCollection, {
    calculatedName: { fieldKey: 'note', kind: 'FIELD' },
    collectionKey: HELLO_MANAGED_COLLECTION_REF,
    description: { en: 'Synthetic integration-owned state used only for private upgrade acceptance.' },
    fields: [
      {
        fieldKey: 'note',
        kind: 'TEXT',
        label: { en: HELLO_MANAGED_FIELD_TITLE },
        maxLength: 200,
        required: false,
      },
    ],
    label: { en: 'Hello integration notes' },
    lifecycleOwner: 'INTEGRATION',
    recordLifecycle: 'ACTIVE_ONLY',
    sharedContractKeys: [],
  });
  assert.equal(`${managedCollection.collectionKey}.${managedCollection.fields[0].fieldKey}`, HELLO_MANAGED_FIELD_REF);
  assert.deepEqual(upgrade.blueprintPackage.definition.lifecycle, [
    { collectionKey: HELLO_MANAGED_COLLECTION_REF, owner: 'INTEGRATION', resourceType: 'COLLECTION', uninstallBehavior: 'PRESERVE' },
    { collectionKey: 'hello-records', owner: 'TEAM', resourceType: 'COLLECTION', uninstallBehavior: 'PRESERVE' },
  ]);
  assert.notEqual(upgrade.blueprintPackageSha256, '73c11cc95a484bc987699469c1435e7414f6eb72f90f38b1aafcd0cba7135eaf');
});

test('rejects unknown definition versions and refuses to relabel the 1.0.9 baseline', async () => {
  await assert.rejects(
    buildHelloAcceptanceBundle({ sourceCommit: 'dev', semanticVersion: HELLO_UPGRADE_SEMANTIC_VERSION }),
    /exact lowercase 40-character Git SHA/u,
  );
  await assert.rejects(
    buildHelloAcceptanceBundle({ sourceCommit: upgradeSourceCommit, semanticVersion: HELLO_BASELINE_SEMANTIC_VERSION }),
    /historical source commit/u,
  );
  await assert.rejects(
    buildHelloAcceptanceBundle({ sourceCommit: HELLO_BASELINE_SOURCE_COMMIT, semanticVersion: HELLO_UPGRADE_SEMANTIC_VERSION }),
    /requires a successor source commit/u,
  );
  await assert.rejects(
    buildHelloAcceptanceBundle({ sourceCommit: upgradeSourceCommit, semanticVersion: '1.0.11' }),
    /must select the reviewed 1\.0\.9 baseline or 1\.0\.10 upgrade/u,
  );
});
