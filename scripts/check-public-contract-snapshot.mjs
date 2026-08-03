import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const path = resolve('src/public-contracts/event-occurrence-v1.json');
const snapshot = JSON.parse(await readFile(path, 'utf8'));
const EXPECTED_SOURCE_SHA256 =
  '3ea2dc53020c00720446a5c86867e3d78e05328b9849e4dfbf05669288268a98';
const EXPECTED_VARIANTS_SHA256 =
  'acf270a73545fd4d61cc31d7d5fe20e4100a37e215e0b07c9a8289aac3a96684';
if (snapshot?.schemaVersion !== 'simply360.public-contract-snapshot/v1') {
  throw new Error('public event contract snapshot has an unknown schemaVersion');
}
if (
  snapshot?.source?.id !==
    'https://schemas.simply360.app/app-platform/v1/event-occurrence-v1.schema.json' ||
  snapshot?.source?.sha256 !== EXPECTED_SOURCE_SHA256
) {
  throw new Error('public event contract snapshot lacks exact authoritative source provenance');
}
if (
  !Array.isArray(snapshot.selectedEventTypes) ||
  !Array.isArray(snapshot.variants) ||
  snapshot.selectedEventTypes.length !== snapshot.variants.length
) {
  throw new Error('public event contract snapshot event and variant counts differ');
}
const actualEventTypes = snapshot.variants.map((variant) => variant?.properties?.eventType?.const);
if (JSON.stringify(actualEventTypes) !== JSON.stringify(snapshot.selectedEventTypes)) {
  throw new Error('public event contract snapshot variants do not match their declared event types');
}
const actualSha256 = createHash('sha256')
  .update(JSON.stringify(snapshot.variants))
  .digest('hex');
if (actualSha256 !== snapshot.selectedVariantsSha256) {
  throw new Error('public event contract snapshot variant digest does not match');
}
if (actualSha256 !== EXPECTED_VARIANTS_SHA256) {
  throw new Error('public event contract snapshot differs from the reviewed authoritative variants');
}
console.log(
  `Public event contract snapshot passed (${snapshot.variants.length} variants, source ${snapshot.source.sha256}).`,
);
