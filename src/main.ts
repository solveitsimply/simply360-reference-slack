import { createConfiguredReferenceRouter } from './configured-service.js';
import { startReferenceServer } from './server.js';

const portText = process.env.PORT ?? '8787';
if (!/^[1-9][0-9]{0,4}$/u.test(portText) || Number(portText) > 65_535) {
  throw new Error('PORT must be an integer from 1 to 65535');
}
const host = process.env.HOST ?? '127.0.0.1';
if (!['127.0.0.1', '::1', 'localhost'].includes(host)) {
  throw new Error(
    'HOST must be loopback because the mock-ready reference service has no public management authentication',
  );
}
const server = await startReferenceServer(createConfiguredReferenceRouter(), {
  host,
  port: Number(portText),
});
process.stdout.write(`Simply360 Slack reference service listening at ${server.origin}\n`);
