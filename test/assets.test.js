import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  assertExactAssetSource,
  buildReferenceAssets,
  canonicalJsonSha256,
  slackMessageLogBlueprintDefinition,
} from '../dist/index.js';

const sourceCommit = '0123456789abcdef0123456789abcdef01234567';

test('assets bind exact source and Blueprint hashes without internal identifiers', () => {
  const { appManifest, blueprintPackage } = buildReferenceAssets(sourceCommit);
  assert.equal(appManifest.provenance.sourceCommit, sourceCommit);
  assert.equal(blueprintPackage.provenance.sourceCommit, sourceCommit);
  assert.equal(
    blueprintPackage.definitionSha256,
    canonicalJsonSha256(slackMessageLogBlueprintDefinition),
  );
  assert.equal(
    appManifest.blueprintPackages[0].sha256,
    canonicalJsonSha256(blueprintPackage),
  );
  const serialized = JSON.stringify({ appManifest, blueprintPackage });
  assert.doesNotMatch(serialized, /(?:^|")(?:id|teamId|installationId|recordId)"\s*:/i);
  assert.doesNotMatch(serialized, /"(?:client_secret|access_token|refresh_token)"\s*:|xox[baprs]-/i);
});

test('manifest declares only the approved v1 proof capabilities and strict schemas', () => {
  const { appManifest } = buildReferenceAssets(sourceCommit);
  assert.deepEqual(
    appManifest.capabilities.map((entry) => entry.capabilityKey).sort(),
    [
      'EVENT_DESTINATION',
      'EXTERNAL_BLUEPRINT_PACKAGE',
      'RECORD_API',
      'REMOTE_ACTION_PROVIDER',
      'REMOTE_TRIGGER_PROVIDER',
    ],
  );
  assert.equal(appManifest.remoteActions[0].inputSchema.additionalProperties, false);
  assert.equal(appManifest.remoteActions[0].outputSchema.additionalProperties, false);
  assert.equal(appManifest.remoteTriggers[0].inputSchema.additionalProperties, false);
  assert.equal(appManifest.eventDestinations[0].protocolVersion, 2);
});

test('asset generation refuses fabricated or abbreviated source commits', () => {
  assert.throws(() => buildReferenceAssets('dev'), /exact lowercase 40-character Git SHA/);
  assert.throws(() => buildReferenceAssets('A'.repeat(40)), /exact lowercase 40-character Git SHA/);
});

test('asset publication requires the exact clean checked-out source', () => {
  assert.doesNotThrow(() =>
    assertExactAssetSource({
      requestedCommit: sourceCommit,
      checkedOutCommit: sourceCommit,
      worktreeIsClean: true,
    }),
  );
  assert.throws(
    () =>
      assertExactAssetSource({
        requestedCommit: sourceCommit,
        checkedOutCommit: '1'.repeat(40),
        worktreeIsClean: true,
      }),
    /must match the checked-out Git commit/,
  );
  assert.throws(
    () =>
      assertExactAssetSource({
        requestedCommit: sourceCommit,
        checkedOutCommit: sourceCommit,
        worktreeIsClean: false,
      }),
    /clean Git worktree/,
  );
});
