import { execFile } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { promisify } from 'node:util';

import { assertExactAssetSource, buildHelloAcceptanceBundle } from '../dist/index.js';

const [sourceCommit, semanticVersion] = process.argv.slice(2);
if (!sourceCommit || !semanticVersion) {
  throw new Error('Usage: npm run assets:hello -- <exact-source-commit> <semantic-version>');
}

const execute = promisify(execFile);
const [{ stdout: checkedOutCommit }, { stdout: worktreeStatus }] = await Promise.all([
  execute('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }),
  execute('git', ['status', '--porcelain=v1', '--untracked-files=all'], { encoding: 'utf8' }),
]);
assertExactAssetSource({
  requestedCommit: sourceCommit,
  checkedOutCommit: checkedOutCommit.trim(),
  worktreeIsClean: worktreeStatus.length === 0,
});

const bundle = await buildHelloAcceptanceBundle({ sourceCommit, semanticVersion });
const output = resolve('generated');
await mkdir(output, { recursive: true });
await Promise.all([
  writeFile(resolve(output, 'hello-app-manifest.json'), `${JSON.stringify(bundle.manifest, null, 2)}\n`),
  writeFile(resolve(output, 'hello-records.blueprint.json'), `${JSON.stringify(bundle.blueprintPackage, null, 2)}\n`),
  writeFile(resolve(output, 'hello-acceptance-bundle.json'), `${JSON.stringify({
    sourceCommit,
    semanticVersion,
    blueprintPackageSha256: bundle.blueprintPackageSha256,
  }, null, 2)}\n`),
]);
