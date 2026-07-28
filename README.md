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
  `create-record-from-message` trigger to a typed port;
- the reviewed `send-to-channel` provider behavior with strict schemas,
  concurrent idempotency, and a deterministic Slack `client_msg_id`; and
- source-SHA-bound app-manifest and external-Blueprint asset generation.

Not claimed:

- no Slack workspace, app, token, signing secret, public callback, AWS stack, or
  live Simply360 installation has been provisioned;
- no hosted lifecycle or screenshots exist;
- `@simply360/integration-sdk` and `@simply360/blueprint-sdk` are not published;
  and
- the public platform declares `REMOTE_ACTION_V1` and `REMOTE_TRIGGER_V1` but
  does not yet publish their invocation/result wire schemas or client
  functions. Provider logic is complete behind typed ports, but the external
  HTTP bindings intentionally fail closed until that public contract lands.

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
suite.

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
│ REMOTE_ACTION_V1 ─────────┼── contract ──▶│ send-to-channel      │
│                           │    blocked     │ provider behavior    │
│ REMOTE_TRIGGER_V1 ◀───────┼── contract ───│ signed message       │
│                           │    blocked     │ shortcut             │
│ external Blueprint        │               └──────────────────────┘
└───────────────────────────┘
```

The runtime has no Simply360 internal imports, database/VPC access, or SSM E2E
credentials. The public-boundary ratchet rejects `@s360/*` and internal-source
imports. The local doubles model public authority invariants; they are not
production authorization code.

## Important security properties

- Raw request bytes are verified before JSON or form decoding.
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
- HTTP clients reject redirects, bound response sizes, and use abort deadlines.
- Secrets are constructor inputs or external secret-store values; generated
  assets contain references, never values.

## Repository layout

```text
src/
  assets.ts                 exact-SHA manifest and structural Blueprint source
  oauth.ts                  Simply360 authorization-code/PKCE client
  webhook-v2.ts             byte-exact webhook-v2 verifier/signer
  slack-oauth.ts            least-privilege Slack OAuth and revocation
  slack.ts                  bounded Slack Web API adapter
  runtime.ts                event/action/trigger provider behavior
  testing/                  local Simply360 and Slack provider doubles
scripts/
  check-public-boundary.mjs static internal-import/credential ratchet
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

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
