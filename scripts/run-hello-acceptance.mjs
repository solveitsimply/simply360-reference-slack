import { readFile } from 'node:fs/promises';

import { z } from 'zod';

import {
  HelloAcceptanceActionSchema,
  HelloAcceptanceConfigSchema,
  bindHelloAcceptanceUserCredential,
  createHelloAcceptanceClients,
  createHelloStateStore,
  runHelloAcceptanceAction,
} from '../dist/index.js';

const TOKEN_ENV = {
  installationService: 'S360_HELLO_INSTALLATION_SERVICE_ACCESS_TOKEN',
  teamAdmin: 'S360_HELLO_TEAM_ADMIN_ACCESS_TOKEN',
};
const STATE_ENV = {
  region: 'AWS_REGION',
  tableName: 'HELLO_STATE_TABLE_NAME',
  runtimeSecretId: 'HELLO_RUNTIME_SECRET_ID',
};
const USER_ACTIONS = new Set(['read-records', 'user-write-record', 'attest-provider-link']);
const MUTATING_ACTIONS = new Set([
  'user-write-record',
  'service-write-record',
  'attest-provider-link',
  'revoke-provider-link',
  'install-blueprint',
  'uninstall-blueprint',
  'upgrade-blueprint',
  'introduce-blueprint-drift',
  'reconcile-blueprint',
]);

const parseFlags = (values) => {
  const flags = new Map();
  for (let index = 0; index < values.length; index += 1) {
    const key = values[index];
    if (!key?.startsWith('--') || key === '--') throw new Error('Expected a named --flag');
    if (flags.has(key)) throw new Error(`Duplicate flag: ${key}`);
    if (key === '--apply' || key === '--include-revoked') {
      flags.set(key, true);
      continue;
    }
    const value = values[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${key}`);
    flags.set(key, value);
    index += 1;
  }
  return flags;
};

const required = (flags, name) => {
  const value = flags.get(name);
  if (typeof value !== 'string') throw new Error(`Missing required flag: ${name}`);
  return value;
};

const requiredEnvironment = (name) => {
  const value = process.env[name];
  if (!value || value.trim() !== value) throw new Error(`Missing required environment setting: ${name}`);
  return value;
};

const assertOnly = (flags, names) => {
  const accepted = new Set(names);
  for (const name of flags.keys()) {
    if (!accepted.has(name)) throw new Error(`Unknown flag: ${name}`);
  }
};

const actionFromFlags = async (name, flags) => {
  const shared = ['--config', ...(MUTATING_ACTIONS.has(name) ? ['--apply'] : [])];
  switch (name) {
    case 'read-records':
    case 'preview-blueprint-install':
    case 'preview-blueprint-uninstall':
    case 'inspect-blueprint-drift':
    case 'introduce-blueprint-drift':
    case 'preview-blueprint-reconcile':
    case 'reconcile-blueprint':
      assertOnly(flags, shared);
      return { action: name };
    case 'user-write-record':
    case 'service-write-record':
      assertOnly(flags, [...shared, '--title', '--idempotency-key']);
      return { action: name, title: required(flags, '--title'), idempotencyKey: required(flags, '--idempotency-key') };
    case 'attest-provider-link':
      assertOnly(flags, [
        ...shared,
        '--provider-subject-fingerprint',
        '--provider-account-fingerprint',
        '--external-credential-reference-hash',
        '--account-label',
        '--idempotency-key',
      ]);
      return {
        action: name,
        providerSubjectFingerprint: required(flags, '--provider-subject-fingerprint'),
        providerAccountFingerprint: required(flags, '--provider-account-fingerprint'),
        externalCredentialReferenceHash: required(flags, '--external-credential-reference-hash'),
        ...(typeof flags.get('--account-label') === 'string' ? { accountLabel: flags.get('--account-label') } : {}),
        idempotencyKey: required(flags, '--idempotency-key'),
      };
    case 'list-provider-links':
      assertOnly(flags, ['--config', '--include-revoked']);
      return { action: name, includeRevoked: flags.get('--include-revoked') === true };
    case 'revoke-provider-link':
      assertOnly(flags, [...shared, '--account-link-simply-id', '--idempotency-key', '--reason']);
      return {
        action: name,
        accountLinkSimplyId: required(flags, '--account-link-simply-id'),
        idempotencyKey: required(flags, '--idempotency-key'),
        reason: required(flags, '--reason'),
      };
    case 'install-blueprint':
      assertOnly(flags, [...shared, '--idempotency-key']);
      return { action: name, idempotencyKey: required(flags, '--idempotency-key') };
    case 'uninstall-blueprint':
      assertOnly(flags, shared);
      return { action: name };
    case 'preview-blueprint-upgrade':
    case 'upgrade-blueprint': {
      const mutating = name === 'upgrade-blueprint';
      assertOnly(flags, [...shared, '--target-app-version-simply-id', '--decisions-path', ...(mutating ? ['--idempotency-key'] : [])]);
      const bytes = await readFile(required(flags, '--decisions-path'));
      if (bytes.length > 64 * 1024) throw new Error('Upgrade decisions exceed 64 KiB');
      return {
        action: name,
        targetIntegrationAppVersionSimplyId: required(flags, '--target-app-version-simply-id'),
        decisions: JSON.parse(bytes.toString('utf8')),
        ...(mutating ? { idempotencyKey: required(flags, '--idempotency-key') } : {}),
      };
    }
    case 'background-task-status':
      assertOnly(flags, ['--config', '--background-task-simply-id']);
      return { action: name, backgroundTaskSimplyId: required(flags, '--background-task-simply-id') };
    default:
      throw new Error(`Unknown action: ${name}`);
  }
};

const parseConfig = async (path) => {
  const bytes = await readFile(path);
  if (bytes.length > 64 * 1024) throw new Error('Acceptance config exceeds 64 KiB');
  return HelloAcceptanceConfigSchema.parse(JSON.parse(bytes.toString('utf8')));
};

const credentialStatus = () => ({
  ...Object.fromEntries(Object.entries(TOKEN_ENV).map(([key, name]) => [key, process.env[name] ? 'PRESENT' : 'MISSING'])),
  userCredentialState: Object.values(STATE_ENV).every((name) => process.env[name]) ? 'PRESENT' : 'MISSING',
});

const main = async () => {
  const [actionName, ...rawFlags] = process.argv.slice(2);
  if (!actionName) throw new Error('Usage: npm run acceptance:hello -- <action> --config <path>');
  const flags = parseFlags(rawFlags);
  const configPath = required(flags, '--config');
  const config = await parseConfig(configPath);

  if (actionName === 'preflight') {
    assertOnly(flags, ['--config']);
    process.stdout.write(`${JSON.stringify({ outcome: 'PREFLIGHT_OK', environment: config.environment, credentialStatus: credentialStatus() })}\n`);
    return;
  }
  if (MUTATING_ACTIONS.has(actionName) && flags.get('--apply') !== true) {
    throw new Error(`Action ${actionName} requires --apply`);
  }
  const action = HelloAcceptanceActionSchema.parse(await actionFromFlags(actionName, flags));
  const tokens = {
    installationService: process.env[TOKEN_ENV.installationService] ?? '',
    teamAdmin: process.env[TOKEN_ENV.teamAdmin] ?? '',
  };
  let clients = createHelloAcceptanceClients(config, tokens);
  if (USER_ACTIONS.has(action.action)) {
    clients = await bindHelloAcceptanceUserCredential(config, clients, createHelloStateStore({
      region: requiredEnvironment(STATE_ENV.region),
      tableName: requiredEnvironment(STATE_ENV.tableName),
      runtimeSecretId: requiredEnvironment(STATE_ENV.runtimeSecretId),
    }));
  }
  const result = await runHelloAcceptanceAction({
    config,
    action,
    clients,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
};

try {
  await main();
} catch (error) {
  const issues = error instanceof z.ZodError
    ? error.issues.map(({ path, message }) => ({ path: path.join('.'), message }))
    : undefined;
  process.stderr.write(`${JSON.stringify({
    error: issues ? 'INVALID_ACCEPTANCE_INPUT' : 'ACCEPTANCE_FAILED',
    ...(issues ? { issues } : { message: error instanceof Error ? error.message : 'Unknown failure' }),
  })}\n`);
  process.exitCode = 1;
}
