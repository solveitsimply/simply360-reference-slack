export const readBoundedResponseText = async (response: Response, maximumBytes = 64 * 1024): Promise<string> => {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) throw new RangeError('maximumBytes must be a positive safe integer');
  if (!response.body) {
    const text = await response.text();
    if (Buffer.byteLength(text) > maximumBytes) throw new Error('HTTP response exceeds the byte limit');
    return text;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      received += chunk.value.byteLength;
      if (received > maximumBytes) {
        await reader.cancel('response byte limit exceeded');
        throw new Error('HTTP response exceeds the byte limit');
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
};

export const assertJsonResponse = (response: Response): void => {
  const mediaType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (mediaType !== 'application/json') throw new Error('HTTP response content type is not application/json');
};
