import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

import type { SlackReferenceRouter } from './router.js';

const MAXIMUM_REQUEST_BYTES = 512 * 1024;

const readRequestBody = async (request: IncomingMessage): Promise<Buffer> => {
  const chunks: Buffer[] = [];
  let received = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    received += bytes.byteLength;
    if (received > MAXIMUM_REQUEST_BYTES) throw new Error('request exceeds the byte limit');
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, received);
};

const sendResponse = async (
  target: ServerResponse,
  response: Response,
): Promise<void> => {
  target.statusCode = response.status;
  response.headers.forEach((value, key) => target.setHeader(key, value));
  target.end(Buffer.from(await response.arrayBuffer()));
};

export const startReferenceServer = async (
  router: SlackReferenceRouter,
  options: { readonly host?: string; readonly port?: number } = {},
): Promise<{
  readonly origin: string;
  readonly close: () => Promise<void>;
}> => {
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 0;
  let origin: string | undefined;
  const server = createServer(async (incoming, outgoing) => {
    try {
      if (!origin) throw new Error('reference server is not ready');
      const target = incoming.url ?? '/';
      if (!target.startsWith('/')) throw new Error('absolute request targets are not accepted');
      const body = await readRequestBody(incoming);
      const headers = new Headers();
      for (const [key, value] of Object.entries(incoming.headers)) {
        if (Array.isArray(value)) value.forEach((entry) => headers.append(key, entry));
        else if (value !== undefined) headers.set(key, value);
      }
      const request = new Request(
        `${origin}${target}`,
        {
          method: incoming.method ?? 'GET',
          headers,
          ...(body.byteLength > 0 ? { body } : {}),
        },
      );
      await sendResponse(outgoing, await router.handle(request));
    } catch (error) {
      outgoing.statusCode = 400;
      outgoing.setHeader('content-type', 'application/json; charset=utf-8');
      outgoing.end(
        `${JSON.stringify({
          error: 'REQUEST_REJECTED',
          message: error instanceof Error ? error.message : 'request failed',
        })}\n`,
      );
    }
  });
  await new Promise<void>((resolvePromise, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolvePromise();
    });
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    server.close();
    throw new Error('reference server did not bind a TCP address');
  }
  const originHost = host.includes(':') ? `[${host}]` : host;
  origin = `http://${originHost}:${address.port}`;
  return {
    origin,
    close: () =>
      new Promise<void>((resolvePromise, reject) => {
        server.close((error) => (error ? reject(error) : resolvePromise()));
      }),
  };
};
