import { execFile } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
import { assertExactAssetSource, buildReferenceAssets } from '../dist/assets.js';

const sourceCommit = process.argv[2];
if (!sourceCommit) {
  throw new Error('Usage: npm run assets -- <exact-40-character-source-commit>');
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

const output = resolve('generated');
await mkdir(output, { recursive: true });
const assets = buildReferenceAssets(sourceCommit);
await Promise.all([
  writeFile(resolve(output, 'app-manifest.json'), `${JSON.stringify(assets.appManifest, null, 2)}\n`),
  writeFile(resolve(output, 'slack-message-log.blueprint.json'), `${JSON.stringify(assets.blueprintPackage, null, 2)}\n`),
]);
