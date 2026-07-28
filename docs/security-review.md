# Security review

Review scope: provider-neutral OAuth hello, webhook receiver, Slack OAuth/Web
API, explicit message-shortcut ingress, remote-action provider logic, local
doubles, generated assets, CI, and intended infrastructure boundary.

## Trust boundaries

1. Simply360 → reference runtime: hostile network and body; webhook-v2 HMAC is
   required over raw bytes.
2. Slack → reference runtime: hostile network and form body; Slack v0 HMAC is
   required over raw bytes.
3. Reference runtime → Slack: OAuth bot token with only `chat:write`.
4. Reference runtime → Simply360 remote trigger: blocked until the public
   signed-ingress contract exists.
5. Publisher artifacts → Simply360: generated from an exact source SHA with
   content hashes and no secrets.

## Reviewed abuse cases

| Risk | Control / result |
| --- | --- |
| Simply360 body or coordinate tampering | Timing-safe v2 HMAC, raw-byte hash, exact event/delivery/attempt IDs, plaintext-header cross-check, Team+installation match. |
| Replay | ±300-second time window plus durable-store port keyed by event+delivery; Slack provider also receives deterministic `client_msg_id`. |
| Signing-key confusion | Exactly one current and optional one unique previous key; unknown `kid` fails. |
| Cross-installation access | Every occurrence and local OAuth family binds one exact installation; Slack shortcuts must match the installation's exact configured workspace; sibling read/write/link/revoke and cross-workspace rejection tests pass. |
| Pending grant privilege | Setup/status only; ordinary read/write is denied until activation and a later refresh. |
| OAuth code interception | Exact client, redirect, installation, consent revision, single-use code, and S256 PKCE. |
| Refresh replay | Reuse of a spent refresh token revokes the whole family; subsequent access fails. |
| Scope escalation | Any wider set requires explicit fresh consent; live consent revision fences old families. |
| Slack over-collection | No history scopes or event subscriptions; only explicit message shortcut input is accepted. |
| Expired Slack bot grant | Token rotation is enabled; access + one-time refresh tokens are parsed as a closed grant and rotated together. |
| Slack request forgery/replay | v0 raw-body HMAC, timing-safe comparison, and ±300-second window. |
| Bot/message loop | No broad message event subscription; only human-invoked message shortcut. |
| Slack SSRF/redirect/response abuse | Fixed `https://slack.com/api/*` endpoints, redirects rejected, abort deadline, 64 KiB response ceiling. |
| Arbitrary data disclosure to Slack | Event destination formats only event type and public Team/installation/event coordinates; payload fields are never forwarded. |
| Action injection | Closed input schema, Slack channel-ID grammar, plain-text/control/bidi checks, 3,000-character limit, strict idempotency key. |
| Duplicate side effect | Concurrent local idempotency plus deterministic Slack `client_msg_id`; production requires a durable store implementation. |
| Secret disclosure | No values in source/generated assets; boundary scan checks common credential forms; intended Secrets Manager-only custody. |
| Internal-boundary bypass | Static ratchet rejects `@s360/*`, database/Amplify/internal-source imports. |
| Fake provenance | Asset generator requires an exact lowercase 40-character SHA equal to checked-out `HEAD`, refuses a dirty worktree, and binds the Blueprint package hash into the manifest. |

## Open blockers / residual risk

- The local idempotency store is process-local test support. A deployed adapter
  must use a durable compare-and-set implementation and must retain terminal
  results without plaintext secrets.
- The public SDKs are unpublished. Local OAuth/webhook compatibility code must
  be replaced and conformance-tested against the published packages.
- `REMOTE_ACTION_V1` and `REMOTE_TRIGGER_V1` lack public invocation/result
  schemas. HTTP endpoints are intentionally not bound; guessing would create an
  authentication/authorization ambiguity.
- No hosted stack, IAM policy, Slack app, credential rotation, CloudWatch
  evidence, penetration test, or deployed cleanup proof exists.
- Slack token rotation semantics and manifest acceptance must be verified in
  the real dedicated workspace.

No exploitable credential, internal import, cross-instance access, payload
forwarding, signature bypass, or replay acceptance was found in the local
implemented scope. The residual items above prevent a claim of deployed
completion.
