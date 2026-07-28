import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const SELECTED_EVENT_TYPES = [
  'dataRecord.created',
  'dataRecord.updated',
  'remoteAction.completed',
  'remoteAction.failed',
  'remoteTrigger.completed',
  'remoteTrigger.failed',
  'app.install.completed',
  'app.setup.completed',
  'app.uninstalled',
];

const sourcePath = process.argv[2];
if (!sourcePath) {
  throw new Error('Usage: node scripts/sync-public-event-contract.mjs <event-occurrence-v1.schema.json>');
}

const sourceBytes = await readFile(resolve(sourcePath));
const source = JSON.parse(sourceBytes.toString('utf8'));
if (
  source?.$id !== 'https://schemas.simply360.app/app-platform/v1/event-occurrence-v1.schema.json' ||
  !Array.isArray(source.anyOf)
) {
  throw new Error('source is not the authoritative Simply360 event-occurrence-v1 JSON Schema artifact');
}

const variants = SELECTED_EVENT_TYPES.map((eventType) => {
  const matches = source.anyOf.filter((variant) => variant?.properties?.eventType?.const === eventType);
  if (matches.length !== 1) throw new Error(`expected one authoritative occurrence variant for ${eventType}`);
  return matches[0];
});
const selectedVariantsSha256 = createHash('sha256').update(JSON.stringify(variants)).digest('hex');
const snapshot = {
  schemaVersion: 'simply360.public-contract-snapshot/v1',
  source: {
    id: source.$id,
    sha256: createHash('sha256').update(sourceBytes).digest('hex'),
  },
  selectedEventTypes: SELECTED_EVENT_TYPES,
  selectedVariantsSha256,
  variants,
};

await writeFile(
  resolve('src/public-contracts/event-occurrence-v1.json'),
  `${JSON.stringify(snapshot, null, 2)}\n`,
);
console.log(
  `Wrote ${snapshot.selectedEventTypes.length} authoritative event variants (${selectedVariantsSha256}).`,
);
