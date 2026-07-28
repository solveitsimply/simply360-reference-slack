import { readFile, readdir } from 'node:fs/promises';
import { extname, join, relative } from 'node:path';

const root = process.cwd();
const forbiddenImportPatterns = [
  /['"]@s360\//u,
  /['"][^'"]*(?:packages\/db|amplify\/functions|src\/models)/u,
  /['"](?:\.\.\/){2,}simply360(?:\/|['"])/u,
];
const secretPatterns = [
  /xox[baprs]-[A-Za-z0-9-]{10,}/u,
  /xoxe(?:\.xoxb)?-[A-Za-z0-9-]{10,}/u,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
  /AKIA[0-9A-Z]{16}/u,
];

const files = [];
const walk = async (directory) => {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'generated' || entry.name === '.git') continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await walk(path);
    else if (['.ts', '.js', '.mjs', '.json', '.md', '.yaml', '.yml'].includes(extname(entry.name))) files.push(path);
  }
};

await walk(root);
const findings = [];
for (const path of files) {
  const text = await readFile(path, 'utf8');
  const relativePath = relative(root, path);
  const codePatterns =
    relativePath !== 'scripts/check-public-boundary.mjs' && ['.ts', '.js', '.mjs'].includes(extname(path))
      ? forbiddenImportPatterns
      : [];
  for (const pattern of [...codePatterns, ...secretPatterns]) {
    if (pattern.test(text)) findings.push(`${relativePath} matches ${pattern}`);
  }
  if (path.endsWith('package.json')) {
    const manifest = JSON.parse(text);
    for (const dependencyKind of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      const dependencies = manifest[dependencyKind];
      if (typeof dependencies !== 'object' || dependencies === null) continue;
      for (const dependency of Object.keys(dependencies)) {
        if (dependency.startsWith('@s360/')) {
          findings.push(`${relativePath} has forbidden ${dependencyKind} entry ${dependency}`);
        }
      }
    }
  }
}

if (findings.length > 0) {
  throw new Error(`Public-boundary check failed:\n${findings.join('\n')}`);
}
console.log(`Public-boundary check passed (${files.length} files scanned).`);
