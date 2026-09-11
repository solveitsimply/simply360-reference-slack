# Deferred Slack development proof

The September 2026 selected milestone is the provider-neutral private hello
app. Do not execute the Slack workspace/app, Slack credential, remote-action,
or inbound-trigger steps below for that milestone. They are retained as the
reviewed full-provider extension and require a later explicit decision.

For the selected hello proof, the immutable submission/registration receipt
must supply the NATIVE/NONE client ID and the public publisher, app, version,
release, and OAuth-client Simply IDs. Configure those exact values together
with the canonical audience `urn:simply360:public-api`, resource
`urn:simply360:team-api`, `dev` environment, exact HTTPS authorize/token
endpoints, and the allowlisted
`https://reference-slack.dev.simply360.app/oauth/simply360/callback`. No client
secret exists for this public client. The external authorization request must
not contain a Team or installation ID; Simply360 hosted consent makes that
choice and the returned public identity receipt binds credential custody.
The runtime accepts only `/healthz`, the two Simply360 OAuth routes,
`/events/simply360`, and `/lifecycle`. Its deployment parameters must copy the
exact receipt coordinates and manifest-declared subscription/lifecycle event
types; do not add legacy Slack, setup, action, or management routes.

These are owner-interactive instructions for Jake. They do not assert that any
step has occurred. Stop if a name, scope, environment, account, or cost differs
from this document.

## Preconditions

- Repository: `solveitsimply/simply360-reference-slack`
- GitHub repository ID: `1305919064`
- GitHub repository owner ID: `67548625`
- Protected branch: `dev`
- Slack workspace: `Simply360 Developer Test`
- Slack app: `Simply360 Reference for Slack (Dev)`
- AWS account: Simply360 NonProd (`592668326732`)
- AWS region: `us-east-1`
- Stack: `Simply360ReferenceSlackDev`
- Public origin: `https://reference-slack.dev.simply360.app`
- Hosted zone: `dev.simply360.app` (`Z0784342XIP781QDXCJA`)
- Requested certificate:
  `arn:aws:acm:us-east-1:592668326732:certificate/1a260620-98e8-41e5-9f51-d459b4a154b3`
- Recurring-cost ceiling: $25/month; expected low-volume range is $2–$10/month
- Only synthetic publisher-test-Team data is permitted.

The following must exist before the deferred Slack provider verifies callbacks:

1. published, version-pinned `@simply360/integration-sdk` and
   `@simply360/blueprint-sdk`;
2. public `REMOTE_ACTION_V1` and `REMOTE_TRIGGER_V1` invocation/result
   contracts;
3. the reviewed NonProd stack and HTTPS origin;
4. one reviewed Simply360 confidential app client with its one-time secret
   placed directly in Secrets Manager; and
5. a generated app manifest and Blueprint package for the exact accepted
   repository SHA.

Do not work around a missing item with an internal import, a made-up endpoint,
a client-credentials grant, a tunnel, or a real Team.

## 1. Create the dedicated Slack workspace

1. Sign in to Slack as Jake.
2. Create or select a workspace named exactly `Simply360 Developer Test`.
3. Confirm it contains no customer, production, or personal business data.
4. Create a private test channel such as `#simply360-reference-proof`; invite
   only the synthetic proof operators.
5. Record the workspace/team ID and channel ID as non-secret evidence. Configure
   the exact workspace/team ID as the runtime's `slackTeamId` installation
   binding. Do not record tokens or secrets.

## 2. Create the Slack app from the reviewed manifest

1. Open `https://api.slack.com/apps`.
2. Choose **Create New App** → **From an app manifest**.
3. Select `Simply360 Developer Test`.
4. Paste [reference/slack-app-manifest.yaml](../reference/slack-app-manifest.yaml).
5. Before creating, confirm the only bot scopes are `chat:write` and
   `commands`. Slack requires `commands` for the reviewed message shortcut;
   it does not grant message-history access.
6. Confirm there are no user scopes, event subscriptions, admin scopes,
   history scopes, Socket Mode, org-wide deployment, or unreviewed request
   URLs.
7. Create the app with the exact name
   `Simply360 Reference for Slack (Dev)`.

The message shortcut is explicit user intent. Do not enable
`message.channels`, `message.groups`, or other broad event subscriptions.

## 3. Store credentials without copying them into the repository

After `Simply360ReferenceSlackDev` has been created, use its
`RuntimeSecretArn` output. It is an initially empty Secrets Manager JSON secret
named exactly:

```text
s360/reference-slack/dev/runtime
```

Required keys:

```text
slackClientId
slackClientSecret
slackSigningSecretCurrent
slackSigningSecretPrevious
slackBotTokenCurrent
slackBotTokenPrevious
slackBotRefreshTokenCurrent
simply360ClientId
simply360ClientSecretCurrent
simply360ClientSecretPrevious
simply360WebhookKidCurrent
simply360WebhookSecretCurrent
simply360WebhookKidPrevious
simply360WebhookSecretPrevious
```

Use empty/absent `Previous` values until an overlap rotation is in progress.
Write secret values directly from the provider UI to the stack output ARN. Do
not paste them into CloudFormation parameters, shell history, GitHub variables,
issue comments, logs, docs, or the generated manifest.

1. In Slack **Basic Information**, copy Client ID, Client Secret, and Signing
   Secret directly into their secret keys.
2. Under **OAuth & Permissions**, install the app to the dedicated workspace.
3. Copy the initial Bot User OAuth Token directly into
   `slackBotTokenCurrent`. After the first rotating OAuth response, store the
   returned refresh token in `slackBotRefreshTokenCurrent` and replace both
   values atomically on every refresh.
4. Invite the bot to the synthetic test channel. `chat:write.public` is not
   approved, so posting to a channel without membership must fail.

## 4. Generate exact-SHA Simply360 artifacts

From a clean checkout of the accepted `dev` commit:

```bash
npm ci
npm run check
npm run assets -- "$(git rev-parse HEAD)"
```

Verify:

- `git status --short` remains clean (`generated/` is ignored);
- both generated artifacts name the exact checked-out 40-character SHA, and
  generation fails if the worktree is dirty or the supplied SHA differs from
  `HEAD`;
- the Blueprint hash in the app manifest matches the generated Blueprint
  package; and
- neither file contains a secret value.

Submit the generated artifacts through the publisher APIs only after the npm
SDK and remote-protocol blockers are closed. Do not insert marketplace rows
manually.

### Lambda artifact cold-start check

`npm run package:hello-lambda` emits a deterministic ZIP containing `index.cjs`.
The bundled AWS SDK dependencies require Node built-ins during initialization;
CommonJS output supplies Node's normal loader. The previous ESM bundle built
successfully but failed on cold load with a dynamic `node:https` require.
The handler remains `index.handler`; [AWS documents `.cjs` as CommonJS](https://docs.aws.amazon.com/lambda/latest/dg/nodejs-handler.html).

`npm run check` includes `check:lambda-package`. This check builds the actual ZIP,
extracts it into an isolated temporary directory, loads its exported handler in
Node without inherited credentials, module paths or a test loader, and calls
`GET /healthz`. It also verifies exact cleanup/replay response-byte preservation
and identical ZIP bytes on a second build. Existing signed-event and durable
cleanup tests continue to establish receiver behavior. This local package check
does not establish deployment, signed live delivery or zero-charge acceptance.

The packaging correction is intentionally unallocated/excluded shared
engineering. It adds no provider operation, Team usage driver, infrastructure,
permission or recurring charge; existing runtime/provider attribution and the
private-integration plan's live acceptance gates remain unchanged. Public API,
SDK, MCP, TeamAgent and mobile contracts are unaffected by the Lambda module
format.

## 5. Configure callbacks after the stack is deployed

The Slack manifest pins:

- OAuth redirect:
  `https://reference-slack.dev.simply360.app/oauth/slack/callback`
- Interactivity request URL:
  `https://reference-slack.dev.simply360.app/events/slack`

Simply360 pins:

- OAuth redirect:
  `https://reference-slack.dev.simply360.app/oauth/simply360/callback`
- event destination:
  `https://reference-slack.dev.simply360.app/events/simply360`
- action endpoint:
  `https://reference-slack.dev.simply360.app/actions/send-to-channel`
- setup URL:
  `https://reference-slack.dev.simply360.app/setup`
- lifecycle endpoint:
  `https://reference-slack.dev.simply360.app/lifecycle`

Slack request-URL verification must succeed against the deployed exact SHA.
TLS, DNS, request signing, and application logs must be checked before
installation. Do not substitute a localhost, ngrok, Cloudflare Tunnel, or
unreviewed hostname.

## 6. Hosted acceptance

Use only publisher test teams and synthetic records. Record exact identifiers,
hashes, timestamps, and sanitized status—not tokens or payload content.

1. Install two independently named instances of the same app.
2. Link two users to one instance and revoke only one link.
3. Install/map the same reviewed `slack-message-log` Blueprint on both.
4. Prove a PENDING_SETUP family can call setup/status and gets 403 on ordinary
   record data.
5. Activate via the fenced lifecycle and a later refresh.
6. Read one allowed synthetic record and make one approved synthetic write.
7. Attempt a wider scope set; prove it requires fresh Team Admin consent.
8. Replay a spent refresh token; prove the whole family is revoked.
9. Deliver one signed v2 event; verify the allowlisted summary in the synthetic
   channel and retry dedupe.
10. Invoke `send-to-channel`; verify the remote action terminal outcome and
    replay idempotency.
11. Use **Create Simply360 record** on one synthetic Slack message; verify one
    signed/idempotent trigger and one record.
12. Rotate each signing/token family with only current+previous overlap.
13. Revoke Slack OAuth, revoke one Simply360 instance, and prove the sibling is
    unaffected.
14. Uninstall; prove callbacks, token refresh, actions, triggers, and events
    fail closed and synthetic artifacts are cleaned up.

The successful signed `app.uninstalled` response includes a sanitized cleanup
receipt only after the installation fence reaches `CLEANED`. Capture its exact
public installation ID, installation-operation ID, event ID, verified raw-body
SHA-256, and `CLEANED` or `REPLAYED` outcome. Compare those coordinates with
the dispatched lifecycle occurrence before retaining the receipt. Do not add a
receipt-read endpoint or use a Team Admin bearer to recover it, and do not
retain the raw body, signature, signing-key identity, delivery/attempt IDs,
credential values, or provider data.

The successful signed `app.account-link.revoked` response follows the same
boundary for one exact provider account-link namespace. After its durable fence
reaches `CLEANED`, `cleanupReceipt` contains schema version
`simply360.reference-slack.account-link-cleanup-receipt/v1`, the public
installation, provider-account-link, installation-operation, and event IDs,
the verified raw-body SHA-256, and `CLEANED` or `REPLAYED`. The top-level
outcome remains `CLEANED` or `DUPLICATE`. A failed, invalid, or crossed-authority
delivery returns no receipt. Verify the receipt against the dispatched event
and successful delivery hash before retaining it; do not retain the raw signed
body or add a receipt-read credential or endpoint.

## 7. Rotation and incident response

- Slack signing-secret rotation is a controlled current/previous overlap with a
  maximum of two keys. Remove the previous value after the overlap evidence.
- Slack bot-token rotation atomically replaces the one-time refresh token and
  expiring access token returned by Slack. Never retry a spent refresh token;
  revoke the installed grant on indeterminate refresh and reconnect explicitly.
- Simply360 confidential-client and webhook signing-key rotation follow the
  reviewed server lifecycle; one-time reveals are never recoverable.
- On compromise: suspend the app/version, revoke Slack and Simply360 token
  families, disable callbacks, preserve metadata/hash-only evidence, and do not
  attempt silent fallback credentials.

## Remaining selected-hello evidence

As of this repository implementation, the selected private hello proof still
needs:

- the exact private app/version/release/OAuth-client registration receipt;
- the deployed platform's narrow private-hello activation and external
  provider-account-link attestation boundary;
- the reviewed immutable Lambda artifact and stack deployment;
- two real hosted-consent installations plus account-link, read/write, signed
  event, selective-revoke, uninstall, and zero-charge evidence; and
- external Blueprint lifecycle proof against the same accepted source.

The packed Integration, Blueprint, and platform SDKs are sufficient for this
milestone; npm publication is deferred. The canonical SSM-backed publisher
test account supplies the existing approved publisher bootstrap, so no
real-member session is required.

The deferred full Slack provider proof separately remains blocked because:

- Jake has not provisioned the Slack workspace/app/credentials;
- the public HTTPS runtime stack is not provisioned;
- the two `@simply360` SDKs are not published; and
- public `REMOTE_ACTION_V1` and `REMOTE_TRIGGER_V1` wire schemas/clients are
  absent. The repository's runnable action route and trigger outbox are local
  harnesses and are not substitutes for those public contracts.
