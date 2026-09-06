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
  ['HelloStateTable:', 'single durable hello-state table'],
  ['Type: AWS::DynamoDB::Table', 'DynamoDB hello-state resource'],
  ['BillingMode: PAY_PER_REQUEST', 'on-demand DynamoDB billing'],
  ['PointInTimeRecoveryEnabled: true', 'DynamoDB point-in-time recovery'],
  ['SSEType: KMS', 'DynamoDB server-side encryption'],
  ['AttributeName: expiresAtEpoch', 'DynamoDB TTL attribute'],
  ['TableName: simply360-reference-slack-dev-hello-state', 'exact durable table name'],
  ['DisableExecuteApiEndpoint: true', 'custom-origin-only API access'],
  ['RetentionInDays: 7', 'seven-day API logs'],
  ['ThrottlingBurstLimit: 10', 'bounded API burst'],
  ['ThrottlingRateLimit: 5', 'bounded API rate'],
  ['Simply360LifecycleEndpoint:', 'Simply360 lifecycle output'],
  ['Type: AWS::Lambda::Function', 'one hosted hello Lambda'],
  ['Runtime: nodejs22.x', 'Node 22 runtime'],
  ['ReservedConcurrentExecutions: 2', 'bounded Lambda concurrency'],
  ['S3ObjectVersion: !Ref RuntimeArtifactObjectVersion', 'immutable artifact version binding'],
  ['Type: AWS::ApiGatewayV2::Integration', 'one Lambda proxy integration'],
  ["RouteKey: 'GET /healthz'", 'health route'],
  ["RouteKey: 'GET /oauth/simply360/start'", 'hosted-consent start route'],
  ["RouteKey: 'GET /oauth/simply360/callback'", 'hosted-consent callback route'],
  ["RouteKey: 'POST /events/simply360'", 'signed event route'],
  ["RouteKey: 'POST /lifecycle'", 'signed lifecycle route'],
  ['S360_LIFECYCLE_EVENT_TYPES:', 'reviewed lifecycle allowlist configuration'],
]) requireText(runtime, text, label);
forbidText(runtime, 'SecretString:', 'committed secret value');
for (const [text, label] of [
  ["RouteKey: 'POST /setup'", 'legacy setup route'],
  ["RouteKey: 'POST /actions", 'legacy action route'],
  ["RouteKey: 'POST /events/slack'", 'deferred Slack event route'],
  ["RouteKey: 'GET /oauth/slack", 'deferred Slack OAuth route'],
  ["RouteKey: '$default'", 'default catch-all route'],
  [':${HttpApi}/*/*', 'wildcard API Gateway Lambda invocation'],
  ['AWS::SQS::Queue', 'unapproved queue'],
  ['AWS::EC2::NatGateway', 'unapproved NAT'],
  ['AWS::EC2::VPC', 'unapproved VPC'],
]) forbidText(runtime, text, label);
if ((runtime.match(/Type: AWS::ApiGatewayV2::Route/gu) ?? []).length !== 5) {
  throw new Error('hosted runtime must expose exactly five API Gateway routes');
}
if ((runtime.match(/Type: AWS::Lambda::Permission/gu) ?? []).length !== 5) {
  throw new Error('each reviewed route must have one exact Lambda invoke permission');
}
if ((runtime.match(/Type: AWS::Lambda::Function/gu) ?? []).length !== 1) {
  throw new Error('hosted runtime must contain exactly one Lambda function');
}
for (const [text, label] of [
  [
    'repo:solveitsimply@67548625/simply360-reference-slack@1305919064:environment:dev',
    'immutable GitHub environment subject',
  ],
  ['StackExecutionRole:', 'separate CloudFormation execution role'],
  ['GitHubDeployRole:', 'GitHub deploy role'],
  ['simply360-reference-slack-dev-', 'repo-scoped artifact bucket'],
  ['Resource: arn:aws:apigateway:us-east-1::/apis', 'HTTP API collection permission'],
  ['apigateway:Request/ApiName: Simply360ReferenceSlackDev-http', 'exact HTTP API creation condition'],
  ['Resource: arn:aws:apigateway:us-east-1::/domainnames', 'domain collection permission'],
  [
    'arn:aws:apigateway:us-east-1::/domainnames/reference-slack.dev.simply360.app/apimappings',
    'exact API mapping collection permission',
  ],
  ['apigateway:AddCertificateToDomain', 'domain certificate binding permission'],
  ['apigateway:RemoveCertificateFromDomain', 'domain certificate cleanup permission'],
  ['HelloRuntimeRole:', 'separate hello runtime role'],
  ['dynamodb:TransactGetItems', 'atomic fence and credential read'],
  ['dynamodb:TransactWriteItems', 'atomic lifecycle-guarded writes'],
  ['arn:aws:dynamodb:us-east-1:592668326732:table/simply360-reference-slack-dev-hello-state', 'exact runtime table IAM boundary'],
  ['arn:aws:lambda:us-east-1:592668326732:function:simply360-reference-slack-dev-hello', 'exact Lambda IAM boundary'],
  ['arn:aws:secretsmanager:us-east-1:592668326732:secret:s360/reference-slack/dev/runtime-*', 'exact runtime secret IAM boundary'],
]) requireText(roles, text, label);
forbidText(
  roles,
  'repo:solveitsimply/simply360-reference-slack:environment:dev',
  'mutable GitHub environment subject',
);
process.stdout.write('infrastructure invariants passed\n');
