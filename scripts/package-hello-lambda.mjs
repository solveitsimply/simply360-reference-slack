import { createHash } from 'node:crypto';
import { readFile, rm, utimes } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';

import { build } from 'esbuild';

const root = new URL('../', import.meta.url);
const outputDirectory = new URL('dist-lambda/', root);
const output = new URL('index.mjs', outputDirectory);
const archive = new URL('hello-lambda.zip', outputDirectory);

await rm(outputDirectory, { recursive: true, force: true });
await build({
  entryPoints: [new URL('src/hello-lambda.ts', root).pathname],
  outfile: output.pathname,
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'esm',
  minify: true,
  sourcemap: false,
  legalComments: 'none',
  logLevel: 'warning',
});

// ZIP stores DOS timestamps. A fixed 1980 epoch plus `-X` produces the same
// artifact bytes from the same source and dependency graph on supported hosts.
const zipEpoch = new Date('1980-01-02T00:00:00.000Z');
await utimes(output, zipEpoch, zipEpoch);
const zipped = spawnSync('zip', ['-X', '-j', '-q', archive.pathname, output.pathname], {
  cwd: outputDirectory,
  encoding: 'utf8',
});
if (zipped.status !== 0) {
  throw new Error(`zip failed: ${zipped.stderr.trim() || `exit ${zipped.status}`}`);
}

const bytes = await readFile(archive);
const sha256 = createHash('sha256').update(bytes).digest('hex');
process.stdout.write(`hello Lambda artifact: dist-lambda/hello-lambda.zip\nsha256: ${sha256}\nbytes: ${bytes.byteLength}\n`);
