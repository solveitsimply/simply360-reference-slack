import { FetchOAuthTransport, Simply360OAuthClient } from './oauth.js';
import { SlackReferenceRouter } from './router.js';
import { SlackWebApiClient } from './slack.js';
import { FetchSlackOAuthTransport, SlackOAuthClient } from './slack-oauth.js';
import {
  FileRemoteTriggerPublisher,
  JsonFileReferenceStore,
} from './state.js';
import type { WebhookSigningKey } from './webhook-v2.js';

const required = (
  environment: NodeJS.ProcessEnv,
  name: string,
): string => {
  const value = environment[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
};

const optionalPair = (
  environment: NodeJS.ProcessEnv,
  idName: string,
  secretName: string,
): WebhookSigningKey[] => {
  const id = environment[idName];
  const secret = environment[secretName];
  if ((id === undefined) !== (secret === undefined)) {
    throw new Error(`${idName} and ${secretName} must both be present or absent`);
  }
  return id && secret ? [{ kid: id, secret }] : [];
};

export const createConfiguredReferenceRouter = (
  environment: NodeJS.ProcessEnv = process.env,
): SlackReferenceRouter => {
  const stateFile =
    environment.S360_REFERENCE_STATE_FILE ?? '.local/reference-state.json';
  const store = new JsonFileReferenceStore(stateFile);
  const simply360OAuth = new Simply360OAuthClient(
    {
      authorizationEndpoint: required(environment, 'S360_AUTHORIZATION_ENDPOINT'),
      tokenEndpoint: required(environment, 'S360_TOKEN_ENDPOINT'),
      clientId: required(environment, 'S360_CLIENT_ID'),
      clientSecret: required(environment, 'S360_CLIENT_SECRET'),
      redirectUri: required(environment, 'S360_REDIRECT_URI'),
    },
    new FetchOAuthTransport(),
  );
  const currentEventKey: WebhookSigningKey = {
    kid: required(environment, 'S360_WEBHOOK_KID_CURRENT'),
    secret: required(environment, 'S360_WEBHOOK_SECRET_CURRENT'),
  };
  const eventSigningKeys = [
    currentEventKey,
    ...optionalPair(
      environment,
      'S360_WEBHOOK_KID_PREVIOUS',
      'S360_WEBHOOK_SECRET_PREVIOUS',
    ),
  ];
  const slackSigningSecrets = [
    required(environment, 'SLACK_SIGNING_SECRET_CURRENT'),
    ...(environment.SLACK_SIGNING_SECRET_PREVIOUS
      ? [environment.SLACK_SIGNING_SECRET_PREVIOUS]
      : []),
  ];
  return new SlackReferenceRouter({
    stateFile,
    store,
    simply360OAuth,
    slackOAuthForInstallation: (installation) =>
      new SlackOAuthClient(
        {
          clientId: required(environment, 'SLACK_CLIENT_ID'),
          clientSecret: required(environment, 'SLACK_CLIENT_SECRET'),
          redirectUri: required(environment, 'SLACK_REDIRECT_URI'),
          expectedTeamId: installation.expectedSlackTeamId,
        },
        new FetchSlackOAuthTransport(),
      ),
    slackClientForInstallation: (installation) => {
      const accessToken = installation.slackCredential?.accessToken;
      if (!accessToken) throw new Error('installation has no Slack access token');
      return new SlackWebApiClient(accessToken);
    },
    triggerPublisherForInstallation: (installation, sharedStore) =>
      new FileRemoteTriggerPublisher(
        sharedStore,
        installation.teamIntegrationSimplyId,
      ),
    eventSigningKeysForInstallation: () => eventSigningKeys,
    slackSigningSecretsForWorkspace: () => slackSigningSecrets,
  });
};
