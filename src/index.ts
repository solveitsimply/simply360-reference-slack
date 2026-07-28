export * from './contracts.js';
export * from './assets.js';
export * from './oauth.js';
export * from './runtime.js';
export * from './slack.js';
export * from './slack-oauth.js';
export * from './webhook-v2.js';
export * from './testing/local-simply360.js';
export * from './testing/local-slack.js';
export * from './testing/local-slack-oauth.js';

export const PROOF_SCENARIOS = [
  'provider-neutral-simply360-oauth-install',
  'pending-setup-denial',
  'repeatable-installations',
  'per-user-link-isolation',
  'shared-external-blueprint',
  'read-and-approved-write',
  'refresh-replay-family-revocation',
  'scope-widening-reconsent',
  'slack-oauth-connect',
  'event-destination-delivery',
  'remote-action-send-to-channel',
  'signed-inbound-create-record-from-message',
  'credential-revocation',
  'uninstall',
] as const;

export const describeProof = () => ({
  name: 'simply360-reference-slack',
  provenSurfaces: ['EVENT_DESTINATION', 'REMOTE_ACTION', 'INBOUND_TRIGGER'] as const,
  slackWorkspace: 'Simply360 Developer Test',
  slackApp: 'Simply360 Reference for Slack (Dev)',
  scenarios: PROOF_SCENARIOS,
});
