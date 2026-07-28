# NonProd infrastructure target (not provisioned)

No AWS resources are created by this repository today. This is the exact target
for the later reviewed deployment after the public SDK and remote-protocol
blockers close.

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
- Secrets Manager access limited to
  `s360/reference-slack/dev/runtime`.
- Route-level throttles, WAF/egress controls if required by the final threat
  model, CloudWatch alarms, metadata-only structured logs, and 7-day retention.
- Route 53 + ACM for `reference-slack.dev.simply360.app`.

The stack must not enter Amplify's default stacks, a VPC, the Simply360
database, or internal package/runtime networks. It must be independently
deletable.

## Why no deploy template is committed yet

A template without deployable public `REMOTE_ACTION_V1` /
`REMOTE_TRIGGER_V1` adapters would create a reachable partial service and
misrepresent Direction-43 mock readiness. Provisioning waits for those public
contracts and the published SDKs; provider logic and local lifecycle evidence
are already complete. The later template must be reviewed together with the
adapters, IAM policy, route limits, cost estimate, and rollback procedure.
