import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));

test('the actual Lambda ZIP cold-loads without the repository and preserves receipt bytes', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 's360-reference-lambda-package-'));
  try {
    execFileSync(process.execPath, ['scripts/package-hello-lambda.mjs'], { cwd: root });
    const archive = path.join(root, 'dist-lambda/hello-lambda.zip');
    assert.equal(execFileSync('unzip', ['-Z1', archive], { encoding: 'utf8' }).trim(), 'index.cjs');
    execFileSync('unzip', ['-q', archive, '-d', directory]);
    const result = execFileSync(process.execPath, ['--input-type=commonjs', '-e', `
      const assert = require('node:assert/strict');
      const { handler, adaptHelloRouterToApiGateway } = require('./index.cjs');
      (async () => {
        const health = await handler({ rawPath: '/healthz', requestContext: { http: { method: 'GET' } } });
        assert.equal(health.statusCode, 200);
        assert.deepEqual(JSON.parse(health.body), { status: 'ok' });
        assert.equal(health.isBase64Encoded, false);
        for (const outcome of ['CLEANED', 'DUPLICATE']) {
          const body = JSON.stringify({ outcome, cleanupReceipt: {
            schemaVersion: 'simply360.reference-slack.account-link-cleanup-receipt/v1',
            installationSimplyId: 'TINT-0001-AAAA',
            integrationProviderAccountLinkSimplyId: 'IPAL-0001-AAAA',
            integrationInstallationOperationSimplyId: 'OPER-0001-AAAA',
            eventSimplyId: 'EVNT-0001-AAAA', verifiedBodySha256: 'a'.repeat(64),
            outcome: outcome === 'CLEANED' ? 'CLEANED' : 'REPLAYED'
          } });
          const adapter = adaptHelloRouterToApiGateway({ handle: async () => ({
            statusCode: 200, headers: { 'Content-Type': 'application/json' }, body
          }) });
          const response = await adapter({ rawPath: '/lifecycle', body: '{}', requestContext: { http: { method: 'POST' } } });
          assert.equal(response.body, body);
          assert.equal(response.statusCode, 200);
          assert.equal(response.isBase64Encoded, false);
        }
        process.stdout.write('packaged handler and receipt adapter passed');
      })().catch(error => { console.error(error); process.exitCode = 1; });
    `], {
      cwd: directory,
      encoding: 'utf8',
      timeout: 15_000,
      // No inherited AWS credentials, Node flags, dependency paths or test loader.
      env: {
        AWS_REGION: 'us-east-1',
        AWS_EC2_METADATA_DISABLED: 'true',
        HELLO_STATE_TABLE_NAME: 'simply360-reference-slack-dev-hello-state',
        HELLO_RUNTIME_SECRET_ID: 's360/reference-slack/dev/runtime',
        S360_AUTHORIZATION_ENDPOINT: 'https://api.dev.simply360.app/oauth/authorize',
        S360_TOKEN_ENDPOINT: 'https://api.dev.simply360.app/oauth/token',
        S360_CLIENT_ID: 'hello-public-native-client',
        S360_REDIRECT_URI: 'https://reference-slack.dev.simply360.app/oauth/simply360/callback',
        S360_INTEGRATION_PUBLISHER_SIMPLY_ID: 'IPUB-0001-AAAA',
        S360_INTEGRATION_APP_SIMPLY_ID: 'IAPP-0001-AAAA',
        S360_INTEGRATION_APP_VERSION_SIMPLY_ID: 'IAVR-0001-AAAA',
        S360_INTEGRATION_APP_RELEASE_SIMPLY_ID: 'IARL-0001-AAAA',
        S360_INTEGRATION_APP_OAUTH_CLIENT_SIMPLY_ID: 'IAOC-0001-AAAA',
        S360_OAUTH_SCOPES: 'records:read,offline_access',
        S360_EVENT_TYPES: 'dataRecord.created',
        S360_LIFECYCLE_EVENT_TYPES: 'app.uninstalled,app.grant.revoked,app.account-link.revoked',
      },
    });
    assert.equal(result, 'packaged handler and receipt adapter passed');

    const first = await readFile(archive);
    execFileSync(process.execPath, ['scripts/package-hello-lambda.mjs'], { cwd: root });
    assert.deepEqual(await readFile(archive), first, 'packaging the same source and dependencies must preserve archive bytes');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
