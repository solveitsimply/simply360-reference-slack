import assert from 'node:assert/strict';
import { test } from 'node:test';

import { AppManifestV1Schema } from '@simply360/integration-sdk/manifest';

import {
  HELLO_BLUEPRINT_PACKAGE_KEY,
  HELLO_LIFECYCLE_EVENT_TYPES,
  HELLO_PROVIDER_PERMISSIONS,
  HELLO_SERVICE_CLIENT_KEY,
  HELLO_SUBSCRIPTION_EVENT_TYPES,
  HELLO_USER_CLIENT_KEY,
  HELLO_USER_SCOPES,
  buildHelloAcceptanceBundle,
} from '../dist/index.js';

const sourceCommit = '0123456789abcdef0123456789abcdef01234567';

test('builds a provider-neutral HYBRID manifest and public Blueprint package from packed SDKs', async () => {
  const bundle = await buildHelloAcceptanceBundle({ sourceCommit, semanticVersion: '1.0.9' });
  assert.doesNotThrow(() => AppManifestV1Schema.parse(bundle.manifest));
  assert.equal(bundle.manifest.provenance.sourceCommit, sourceCommit);
  assert.equal(bundle.blueprintPackage.provenance.sourceCommit, sourceCommit);
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

test('binds asset hashes to exact source and semantic version', async () => {
  const baseline = await buildHelloAcceptanceBundle({ sourceCommit, semanticVersion: '1.0.9' });
  const nextVersion = await buildHelloAcceptanceBundle({ sourceCommit, semanticVersion: '1.0.10' });
  const nextSource = await buildHelloAcceptanceBundle({ sourceCommit: '1'.repeat(40), semanticVersion: '1.0.9' });
  assert.notEqual(baseline.blueprintPackageSha256, nextVersion.blueprintPackageSha256);
  assert.notEqual(baseline.blueprintPackageSha256, nextSource.blueprintPackageSha256);
  await assert.rejects(
    buildHelloAcceptanceBundle({ sourceCommit: 'dev', semanticVersion: '1.0.9' }),
    /exact lowercase 40-character Git SHA/u,
  );
  await assert.rejects(
    buildHelloAcceptanceBundle({ sourceCommit, semanticVersion: 'not-a-version' }),
  );
});
