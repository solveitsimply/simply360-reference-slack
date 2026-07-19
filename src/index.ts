/**
 * Simply360 Reference App — Slack
 * Event destination / remote actions / inbound triggers proof (Proof C,
 * Ratified Direction 13).
 *
 * SCAFFOLD ONLY — no proof behavior is implemented yet. This file establishes
 * the typed surface and the integration points that MKT-12 will build on.
 *
 * Architecture sketch (per plan Proof C):
 *
 *   Simply360 public platform                  Slack
 *   ─────────────────────────                  ─────
 *   marketplace events  ─────────────▶  event destination (e.g. post to channel)
 *   remote automation actions ◀───────  approved actions (e.g. send-to-channel)
 *   signed inbound remote triggers ◀──  create-record-from-message, etc.
 *   external Blueprint package (team schema where useful)
 *
 * Boundary rules (Ratified Direction 9 / 21):
 *   - Only public boundaries: the future `@simply360/integration-sdk` and
 *     `@simply360/blueprint-sdk` packages, Simply360 OAuth, webhooks, and
 *     manifests. Runs outside the monorepo.
 *   - No Simply360 internal package imports, database access, VPC access, or
 *     SSM/E2E credentials. Slack tokens/signing secrets live only in the
 *     reference stack's Secrets Manager path — never committed here.
 *   - Dedicated synthetic workspace `Simply360 Developer Test`; app
 *     `Simply360 Reference for Slack (Dev)`.
 */

/** The three proof surfaces this reference app must demonstrate. */
export type ProvenSlackSurface =
  | 'EVENT_DESTINATION'
  | 'REMOTE_ACTION'
  | 'INBOUND_TRIGGER';

/** Acceptance scenarios V1 must demonstrate (see README "Proof scope"). */
export const PROOF_SCENARIOS = [
  'simply360-oauth-install',
  'slack-oauth-connect',
  'event-destination-delivery',
  'remote-action-send-to-channel',
  'signed-inbound-create-record-from-message',
  'external-blueprint-package',
  'credential-revocation',
  'uninstall',
] as const;

export type ProofScenario = (typeof PROOF_SCENARIOS)[number];

export interface ReferenceAppInfo {
  readonly name: string;
  readonly provenSurfaces: readonly ProvenSlackSurface[];
  readonly slackWorkspace: string;
  readonly slackApp: string;
  readonly scenarios: readonly ProofScenario[];
}

export const referenceApp: ReferenceAppInfo = {
  name: 'simply360-reference-slack',
  provenSurfaces: ['EVENT_DESTINATION', 'REMOTE_ACTION', 'INBOUND_TRIGGER'],
  slackWorkspace: 'Simply360 Developer Test',
  slackApp: 'Simply360 Reference for Slack (Dev)',
  scenarios: PROOF_SCENARIOS,
};

/**
 * Placeholder entry point. Returns the static proof descriptor so the scaffold
 * type-checks, builds, and tests green before any runtime is wired.
 */
export function describeProof(): ReferenceAppInfo {
  // TODO(MKT-12): construct the Simply360 client from the public
  //   `@simply360/integration-sdk` surface (webhook v2 signature verification,
  //   occurrence-envelope decoding, remote-action + inbound-trigger contracts)
  //   once that package is published. Do not import Simply360 internal modules.
  // TODO(MKT-12): verify Slack request signatures and wire the event
  //   destination, remote actions, and signed inbound triggers.
  // TODO(MKT-12): author the external Blueprint package via
  //   `@simply360/blueprint-sdk` where team schema is useful.
  return referenceApp;
}
