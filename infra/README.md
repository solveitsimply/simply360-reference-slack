# NonProd private hello runtime (not provisioned)

No AWS resources are created by this repository today. The exact dev-only
runtime templates are [`dev.template.yaml`](./dev.template.yaml) and
[`oidc-roles.template.yaml`](./oidc-roles.template.yaml). They are intentionally
not deployed by CI. The runtime creates the reviewed HTTPS origin, API Gateway
access logging, an empty owner-managed secret container, one on-demand DynamoDB
table, and one bounded Node 22 Lambda. API Gateway exposes exactly five routes:
health, Simply360 hosted-consent start/callback, signed events, and signed
lifecycle. It never exposes the loopback-only legacy router, Slack provider
routes, setup, actions, triggers, or management APIs.

`RuntimeSecret` and `HelloStateTable` use CloudFormation retain policies. Stack
deletion cannot silently destroy credentials or durable replay state; a
reviewed teardown must first revoke provider grants, selectively remove each
installation namespace, and then explicitly delete the retained resources.

## Ownership and guardrails

| Setting | Required value |
| --- | --- |
| AWS account | Simply360 NonProd `592668326732` |
| Region | `us-east-1` |
| Stack | `Simply360ReferenceSlackDev` |
| Public origin | `https://reference-slack.dev.simply360.app` |
| GitHub repository | `solveitsimply/simply360-reference-slack` |
| GitHub repository ID | `1305919064` |
| GitHub repository owner ID | `67548625` |
| Branch | protected `dev` only |
| GitHub environment | `dev` |
| Hosted zone | `dev.simply360.app` (`Z0784342XIP781QDXCJA`) |
| Requested certificate | `arn:aws:acm:us-east-1:592668326732:certificate/1a260620-98e8-41e5-9f51-d459b4a154b3` |
| Secret | `s360/reference-slack/dev/runtime` |
| Durable table | `simply360-reference-slack-dev-hello-state` |
| Runtime | `simply360-reference-slack-dev-hello`, arm64 Node 22, concurrency 2 |
| Log retention | 7 days |
| Recurring cost | expected $2–$10/month; stop above $25/month |

Production, `main`, customer data, paid Slack plans, extra scopes, public
distribution, and spend above the ceiling require fresh approval.

## GitHub OIDC deployment role

Reuse the organization OIDC provider
`token.actions.githubusercontent.com`. The role must:

- trust audience `sts.amazonaws.com`;
- bind repository ID `1305919064`;
- use immutable subject
  `repo:solveitsimply@67548625/simply360-reference-slack@1305919064:environment:dev`;
- bind the `dev` environment and protected `dev` deployment branch;
- reject pull-request subjects and all other repositories/branches;
- grant CloudFormation deployment only to `Simply360ReferenceSlackDev` and its
  explicitly tagged resources; and
- use no stored AWS access keys.

Because GitHub changes the `sub` claim when a job uses an environment, validate
the actual token claims from a read-only diagnostic workflow before authoring
the final trust condition. Do not guess a trust-policy key or weaken it to an
organization-wide wildcard. The `dev` environment must require the protected
`dev` branch and must not allow workflow-PR approval.

## Intended low-volume topology

- Regional API Gateway HTTP API with the exact five public routes documented in
  [Slack provisioning](../docs/provisioning-slack-dev.md).
- One Node 22 Lambda runtime with `ReservedConcurrentExecutions: 2`, 256 MiB
  memory, a 15-second timeout, no VPC, and no queue.
- One on-demand DynamoDB table for exact installation, member, Simply360 grant,
  and generic provider-account-link namespaces; single-use OAuth state; encrypted
  credential aggregates; and durable idempotency outcomes. Multiple grants and
  provider links for one member remain independently revocable. Ambiguous
  provider outcomes retain a non-expiring in-progress fence; only a typed,
  authoritatively proven no-effect outcome permits retry. The table uses TTL,
  point-in-time recovery, DynamoDB KMS encryption, and no payload logging.
- No queue, VPC, or NAT. The approved hello runtime performs only bounded
  synchronous work.
- a stack-created, initially empty Secrets Manager container named
  `s360/reference-slack/dev/runtime`; only the owner writes values directly
  after stack creation. `helloStateEncryptionKeyCurrent` is the canonical
  base64 encoding of 32 random bytes. During a reviewed rotation only,
  `helloStateEncryptionKeyPrevious` holds the preceding key until every
  retained credential and result has been rewritten or expired.
- Route-level throttles, WAF/egress controls if required by the final threat
  model, CloudWatch alarms, metadata-only structured logs, and 7-day retention.
- Route 53 + ACM for `reference-slack.dev.simply360.app`.

The stack must not enter Amplify's default stacks, a VPC, the Simply360
database, or internal package/runtime networks. It must be independently
deletable.

## Bootstrap and checked runtime package

Bootstrap `oidc-roles.template.yaml` once using an existing NonProd human
operator/organization bootstrap role—not GitHub—with `CAPABILITY_NAMED_IAM`,
the existing organization OIDC-provider ARN, the reviewed artifact-bucket ARN,
the hosted-zone ID, and certificate ARN. This avoids the chicken-and-egg error:
the GitHub deploy role and the CloudFormation execution role are created by
that bootstrap stack, so neither may create itself. Record all three role
ARNs. The protected GitHub `dev` environment must allow only `dev`; the trust
policy then pins the exact immutable subject
`repo:solveitsimply@67548625/simply360-reference-slack@1305919064:environment:dev`.

The bootstrap also creates `simply360-reference-slack-dev-runtime`. Its Lambda
trust and inline permissions are limited to the exact state table, retained
runtime secret, and function log group. The CloudFormation execution role may
pass only that runtime role to Lambda and may manage only the exact dev function
and table. Runtime data access is limited to Get/Put/Update/Delete/Query,
BatchWrite, TransactWrite, and TransactGet; the last operation provides one
consistent read of installation fence, exact grant fence, and credential.

Create a deterministic Lambda archive from the reviewed source and dependency
lock:

```bash
npm ci
npm run check
npm run package:hello-lambda
```

The package command emits `dist-lambda/hello-lambda.zip`, its SHA-256, and byte
count. Rebuilding unchanged bytes produces the same archive. Upload it once as
`simply360-reference-slack/<source-sha>/hello-lambda.zip` to the approved
versioned artifact bucket. Supply its returned S3 object version through
`RuntimeArtifactObjectVersion`; the template does not accept an unversioned
artifact reference.

After bootstrap, validate locally without deployment:

```bash
npm run check
sam validate --lint --template-file infra/dev.template.yaml
aws cloudformation validate-template --template-body file://infra/oidc-roles.template.yaml
```

The owner may create the runtime stack only after the approved cost review.
Supply the exact publisher/app/version/release/OAuth-client coordinates from
the immutable registration receipt, the reviewed public client ID, canonical
dev OAuth endpoints, and exact manifest-declared subscription and lifecycle
event lists. It outputs the public callback URLs, `RuntimeSecretArn`, durable
table name/ARN, and function ARN. Write encryption and webhook keys directly to
the secret ARN; never pass a secret value to CloudFormation, GitHub, shell
history, repository files, or generated assets.

The runtime secret JSON contains `helloStateEncryptionKeyCurrent`, optional
`helloStateEncryptionKeyPrevious`, and at most eight
`simply360WebhookKeyBindings`. Each binding has exact `teamSimplyId` and
`teamIntegrationSimplyId`, one `{kid, secret}` current key, and optionally a
previous key plus `validUntil`. Installation coordinates and key IDs must be
unique. Previous-key overlap cannot exceed the platform's seven-day maximum.
The handler reloads the secret for every signed delivery so rotation and
revocation do not wait for a warm-container cache.

The stack source is ready for a reviewed change set. No template in this
repository performs an upload, stack apply, secret write, or live route probe.
