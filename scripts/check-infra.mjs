import { readFile } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
const [runtime, roles] = await Promise.all([
  readFile(new URL('infra/dev.template.yaml', root), 'utf8'),
  readFile(new URL('infra/oidc-roles.template.yaml', root), 'utf8'),
]);
const requireText = (source, text, label) => {
  if (!source.includes(text)) throw new Error(`missing infrastructure invariant: ${label}`);
};
const forbidText = (source, text, label) => {
  if (source.includes(text)) throw new Error(`forbidden infrastructure configuration: ${label}`);
};
for (const [text, label] of [
  ['RuntimeSecret:', 'owner-managed credential container'],
  ['DeletionPolicy: Retain', 'credential-preserving secret teardown'],
  ['DisableExecuteApiEndpoint: true', 'custom-origin-only API access'],
  ['RetentionInDays: 7', 'seven-day API logs'],
  ['ThrottlingBurstLimit: 10', 'bounded API burst'],
  ['ThrottlingRateLimit: 5', 'bounded API rate'],
  ['SlackOAuthRedirectUri:', 'Slack callback output'],
  ['Simply360LifecycleEndpoint:', 'Simply360 lifecycle output'],
]) requireText(runtime, text, label);
forbidText(runtime, 'SecretString:', 'committed secret value');
for (const [text, label] of [
  ['repo:solveitsimply/simply360-reference-slack:environment:dev', 'exact GitHub environment subject'],
  ['StackExecutionRole:', 'separate CloudFormation execution role'],
  ['GitHubDeployRole:', 'GitHub deploy role'],
  ['simply360-reference-slack-dev-', 'repo-scoped artifact bucket'],
]) requireText(roles, text, label);
process.stdout.write('infrastructure invariants passed\n');
