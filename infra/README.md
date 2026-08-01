# NonProd infrastructure target (not provisioned)

No AWS resources are created by this repository today. The exact dev-only
foundation templates are [`dev.template.yaml`](./dev.template.yaml) and
[`oidc-roles.template.yaml`](./oidc-roles.template.yaml). They are intentionally
not deployed by CI. The foundation creates the reviewed HTTPS origin, API
Gateway access logging, and an empty owner-managed secret container, but no
Lambda integration or management route. Until public remote-action and
remote-trigger contracts exist, every route remains an API Gateway 404 rather
than exposing the loopback-only local harness.

`RuntimeSecret` uses CloudFormation retain policies. Stack deletion cannot
silently destroy credentials; a reviewed teardown must remove the empty or
revoked secret explicitly after the reference installation is removed.

## Ownership and guardrails

| Setting | Required value |
| --- | --- |
| AWS account | Simply360 NonProd `592668326732` |
| Region | `us-east-1` |
| Stack | `Simply360ReferenceSlackDev` |
| Public origin | `https://reference-slack.dev.simply360.app` |
| GitHub repository | `solveitsimply/simply360-reference-slack` |
| GitHub repository ID | `1305919064` |
| Branch | protected `dev` only |
| GitHub environment | `dev` |
| Secret | `s360/reference-slack/dev/runtime` |
| Log retention | 7 days |
| Recurring cost | expected $2–$10/month; stop above $25/month |

Production, `main`, customer data, paid Slack plans, extra scopes, public
distribution, and spend above the ceiling require fresh approval.

## GitHub OIDC deployment role

Reuse the organization OIDC provider
`token.actions.githubusercontent.com`. The role must:

- trust audience `sts.amazonaws.com`;
- bind repository ID `1305919064`;
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

- Regional API Gateway HTTP API with the exact public routes documented in
  [Slack provisioning](../docs/provisioning-slack-dev.md).
- One bounded-concurrency Node 22 Lambda runtime.
- DynamoDB tables for installation configuration, OAuth state/code metadata,
  and durable idempotency outcomes; point-in-time recovery enabled, no payload
  logging.
- SQS + DLQ only where the published remote-action continuation contract
  requires asynchronous work. The reviewed `send-to-channel` action is
  synchronous and must not create a queue by default.
- a stack-created, initially empty Secrets Manager container named
  `s360/reference-slack/dev/runtime`; only the owner writes values directly
  after stack creation.
- Route-level throttles, WAF/egress controls if required by the final threat
  model, CloudWatch alarms, metadata-only structured logs, and 7-day retention.
- Route 53 + ACM for `reference-slack.dev.simply360.app`.

The stack must not enter Amplify's default stacks, a VPC, the Simply360
database, or internal package/runtime networks. It must be independently
deletable.

## Bootstrap and intentionally deferred runtime

Bootstrap `oidc-roles.template.yaml` once using an existing NonProd human
operator/organization bootstrap role—not GitHub—with `CAPABILITY_NAMED_IAM`,
the existing organization OIDC-provider ARN, the reviewed artifact-bucket ARN,
the hosted-zone ID, and certificate ARN. This avoids the chicken-and-egg error:
the GitHub deploy role and the CloudFormation execution role are created by
that bootstrap stack, so neither may create itself. Record both output role
ARNs. The protected GitHub `dev` environment must allow only `dev`; the trust
policy then pins the exact subject
`repo:solveitsimply/simply360-reference-slack:environment:dev`.

After bootstrap, validate locally without deployment:

```bash
npm run check
sam validate --lint --template-file infra/dev.template.yaml
aws cloudformation validate-template --template-body file://infra/oidc-roles.template.yaml
```

The owner may create the foundation stack only after the approved cost review.
It outputs the public callback URLs and `RuntimeSecretArn`. Write credentials
directly to that ARN; never pass a secret value to CloudFormation, GitHub,
shell history, repository files, or generated assets.

A template around the loopback-only local router would expose unauthenticated
management routes and harness-only `REMOTE_ACTION_V1` / `REMOTE_TRIGGER_V1`
shapes. The foundation intentionally creates no such route. A future runtime
update must be reviewed with published SDK adapters, management-route
authentication, durable state/idempotency design, IAM policy, route limits,
cost estimate, and rollback procedure before it is deployed.
