# Simply360 Reference for Slack

Public, out-of-tree reference proof for the Simply360 Integration Marketplace.
It demonstrates a provider-neutral installation lifecycle first, then Slack as
an event destination, remote-action provider, and signed inbound-trigger
provider.

## Status

The repository is **mock-ready, not deployed**.

Implemented and tested locally:

- Direction-45 authorization-code + S256-PKCE hello lifecycle through the
  existing `/oauth/authorize` and `/oauth/token` shape;
- two isolated installation instances, two independently revocable user links
  on one instance, and one shared structural Blueprint package;
- a `PENDING_SETUP` family allowed to call setup/status and denied ordinary
  data, followed by activation through refresh;
- one read and one approved write, exact-instance isolation, widening through
  fresh consent, spent-refresh-token family revocation, and uninstall;
- byte-exact Simply360 webhook-v2 HMAC verification, current/previous key
  overlap, replay-window checks, coordinate checks, and delivery dedupe;
- an allowlisted event summary that never forwards arbitrary record payload
  fields into Slack;
- least-privilege Slack OAuth (`chat:write` only), token revocation, and a
  bounded `chat.postMessage` adapter;
- an explicit Slack message shortcut, verified over the raw Slack request with
  the v0 HMAC and replay window, which submits one idempotent
  `create-record-from-message` trigger to a durable local outbox;
- the reviewed `send-to-channel` provider behavior with strict schemas,
  concurrent idempotency, and a deterministic Slack `client_msg_id`; and
- a runnable, loopback-only HTTP service covering installation creation,
  setup/status, both OAuth callbacks, lifecycle, events, actions, triggers,
  account links, shared Blueprint association, and uninstall;
- a mode-`0600`, atomically replaced local credential/state aggregate with
  restart-safe terminal idempotency results, request-fingerprint conflict
  detection, Team-scoped shared Blueprint identity, and complete uninstall
  fences; and
- source-SHA-bound app-manifest and external-Blueprint asset generation.

Not claimed:

- no Slack workspace, app, token, signing secret, public callback, AWS stack, or
  live Simply360 installation has been provisioned;
- no hosted lifecycle or screenshots exist;
- `@simply360/integration-sdk` and `@simply360/blueprint-sdk` are not published;
  and
- the public platform declares `REMOTE_ACTION_V1` and `REMOTE_TRIGGER_V1` but
  does not yet publish their invocation/result wire schemas or client
  functions. The local HTTP action shape and file-backed trigger outbox are
  test harnesses, not a claim of conformance with those unpublished external
  wire contracts.

These are blockers, not TODO evidence. See [Provision Slack dev](docs/provisioning-slack-dev.md)
and [Security review](docs/security-review.md).

## Quick start

Requires Node 22.

```bash
npm ci
npm run check
```

The check scans the repository for internal Simply360 imports and common
credential material, type-checks, builds, and runs the local lifecycle/security
suite with minimum 85% line, 85% function, and 65% branch coverage.

### Run the local HTTP service

`npm start` runs the service on `127.0.0.1:8787` after `npm run build`.
It intentionally refuses a non-loopback `HOST`: the setup and installation
management routes do not have a published public authentication contract.
Configure these environment variables without checking values into Git:

```text
S360_AUTHORIZATION_ENDPOINT
S360_TOKEN_ENDPOINT
S360_CLIENT_ID
S360_CLIENT_SECRET
S360_REDIRECT_URI
S360_WEBHOOK_KID_CURRENT
S360_WEBHOOK_SECRET_CURRENT
SLACK_CLIENT_ID
SLACK_CLIENT_SECRET
SLACK_REDIRECT_URI
SLACK_SIGNING_SECRET_CURRENT
```

Optional rotation/state settings are
`S360_WEBHOOK_KID_PREVIOUS`, `S360_WEBHOOK_SECRET_PREVIOUS`,
`SLACK_SIGNING_SECRET_PREVIOUS`, `S360_REFERENCE_STATE_FILE`, `HOST`, and
`PORT`. Previous Simply360 key ID/secret values must be present as a pair.
The default state file is `.local/reference-state.json`; it contains OAuth
credentials and is suitable only for the single-process local proof. Never
copy it into source control, share it, or use it as a hosted credential store.

The service exposes:

```text
GET    /health
POST   /installations
GET    /setup
GET    /setup/status
POST   /setup
POST   /oauth/simply360/start
GET    /oauth/simply360/callback
POST   /oauth/simply360/refresh
POST   /oauth/slack/start
GET    /oauth/slack/callback
POST   /oauth/slack/refresh
POST   /account-links
DELETE /account-links/:linkSimplyId
POST   /blueprints/install
POST   /actions/send-to-channel
POST   /events/simply360
POST   /events/slack
POST   /lifecycle
DELETE /installations/:teamIntegrationSimplyId
```

POST callback forms are also retained for the test harness. Real OAuth
redirects use the GET callback routes and resolve the exact pending
installation from the one-time state value; callers cannot select an
installation in the callback.

Generate review assets after checking out the exact commit to submit:

```bash
npm run assets -- "$(git rev-parse HEAD)"
```

This writes ignored files under `generated/`:

- `app-manifest.json`
- `slack-message-log.blueprint.json`

The generator rejects abbreviated, uppercase, non-SHA, non-HEAD, or dirty-tree
provenance. Regenerate after every source change; never submit an asset
generated for another commit.

## Architecture

```text
Simply360 public boundary                   Slack public boundary
┌───────────────────────────┐               ┌──────────────────────┐
│ OAuth authorization code  │               │ OAuth v2 chat:write  │
│ + S256 PKCE               │               │ auth.revoke          │
│                           │               │                      │
│ webhook v2 occurrence ────┼──────────────▶│ chat.postMessage     │
│                           │               │                      │
│ local action harness ─────┼──────────────▶│ send-to-channel      │
│ local trigger outbox ◀────┼───────────────│ signed message       │
│                           │               │ shortcut             │
│ external Blueprint        │               └──────────────────────┘
└───────────────────────────┘
```

The runtime has no Simply360 internal imports, database/VPC access, or SSM E2E
credentials. The public-boundary ratchet rejects `@s360/*` and internal-source
imports. The local doubles model public authority invariants; they are not
production authorization code.

## Important security properties

- Routing fields are decoded as untrusted input only to select candidate keys
  or an installation; no side effect occurs until the exact raw bytes pass the
  appropriate HMAC verification.
- Simply360 HMAC input is exactly
  `S360-HMAC-V2<LF>t<LF>eventId<LF>deliveryId<LF>attemptId<LF>sha256(rawBody)`.
- Only a current key and one explicit overlapping previous key are accepted.
- Signed identities must match both plaintext headers and the occurrence.
- Occurrences must match the configured Team and exact installation.
- Slack interactions must match the exact workspace linked to that
  installation.
- Arbitrary event payload data is never copied to Slack.
- Slack request signatures are timing-safe and limited to ±300 seconds.
- Inbound creation requires the explicit `s360_create_record` message shortcut;
  the app does not subscribe to broad message history/events.
- Slack OAuth requests only `chat:write`; no history, admin, user-token, or
  workspace-wide scopes are declared.
- Action/trigger inputs are closed and bounded, and unknown properties fail.
- Terminal event/action/trigger/lifecycle results survive process restart, and
  reuse of an idempotency key with a different request fingerprint fails.
- Uninstall fences the exact installation before Slack revocation, removes
  both credential families from local state, deactivates its user links,
  clears its trigger outbox and operational replay records, detaches only its
  shared-Blueprint junctions, and leaves siblings active.
- HTTP clients reject redirects, bound response sizes, and use abort deadlines.
- Local secrets are constructor/environment inputs and then mode-`0600` state;
  generated assets contain references, never values.

## Repository layout

```text
src/
  assets.ts                 exact-SHA manifest and structural Blueprint source
  oauth.ts                  Simply360 authorization-code/PKCE client
  webhook-v2.ts             byte-exact webhook-v2 verifier/signer
  slack-oauth.ts            least-privilege Slack OAuth and revocation
  slack.ts                  bounded Slack Web API adapter
  runtime.ts                event/action/trigger provider behavior
  router.ts                 local Request/Response route authority
  server.ts                 bounded Node HTTP adapter
  state.ts                  local credential aggregate and durable outcomes
  public-contracts/         reviewed public-schema snapshot
  testing/                  local Simply360 and Slack provider doubles
scripts/
  check-public-boundary.mjs static internal-import/credential ratchet
  check-public-contract-snapshot.mjs
  sync-public-event-contract.mjs
  generate-reference-assets.mjs
test/                       lifecycle, crypto, isolation, and failure matrices
docs/                       provisioning, privacy, terms, review evidence
infra/README.md             approved target topology; nothing provisioned
```

## Public-contract handoff

When the two public SDKs are published:

1. add the reviewed stable package versions;
2. replace the local OAuth/webhook compatibility code with SDK imports;
3. bind `SlackReferenceRuntime.sendToChannel` to the published
   `REMOTE_ACTION_V1` invocation/result schemas;
4. implement `RemoteTriggerPublisher` with the published
   `REMOTE_TRIGGER_V1` signed-ingress client;
5. validate generated assets with the published manifest/Blueprint validators;
6. rerun `npm run check`, package conformance, and the complete hosted
   lifecycle; and
7. record the exact npm versions, repository SHA, deployment SHA, and immutable
   evidence coordinates.

No endpoint name or request shape should be guessed before steps 2–4.

The vendored event-occurrence subset is the one exception: it is generated from
the authoritative public JSON Schema and pinned by source and selected-variant
SHA-256. Refresh it only from that artifact:

```bash
node scripts/sync-public-event-contract.mjs /path/to/event-occurrence-v1.schema.json
npm run check:public-contract
```

Refreshing the snapshot also requires an intentional review of the pinned
digests in `scripts/check-public-contract-snapshot.mjs`.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
