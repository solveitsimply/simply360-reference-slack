import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { checkInfrastructureTemplates } from '../scripts/check-infra.mjs';

const root = new URL('../', import.meta.url);
const [runtime, roles] = await Promise.all([
  readFile(new URL('infra/dev.template.yaml', root), 'utf8'),
  readFile(new URL('infra/oidc-roles.template.yaml', root), 'utf8'),
]);

test('accepts the reviewed runtime and bootstrap topology', () => {
  assert.doesNotThrow(() => checkInfrastructureTemplates({ runtime, roles }));
});

test('rejects a DynamoDB property attached to the retained secret', () => {
  const invalid = runtime.replace(
    '      Name: s360/reference-slack/dev/runtime',
    '      TableName: simply360-reference-slack-dev-hello-state\n      Name: s360/reference-slack/dev/runtime',
  );
  assert.throws(
    () => checkInfrastructureTemplates({ runtime: invalid, roles }),
    /DynamoDB table name attached to runtime secret/u,
  );
});

test('rejects weakened artifact custody and immutable-version access', () => {
  for (const invalid of [
    roles.replace(
      '        BlockPublicPolicy: true',
      '        BlockPublicPolicy: false',
    ),
    roles.replace('        Status: Enabled', '        Status: Suspended'),
    roles.replace(
      "                aws:SecureTransport: 'false'",
      "                aws:SecureTransport: 'true'",
    ),
    roles.replaceAll('                  - s3:GetObjectVersion\n', ''),
  ]) {
    assert.throws(
      () => checkInfrastructureTemplates({ runtime, roles: invalid }),
      /infrastructure invariant/u,
    );
  }
});
