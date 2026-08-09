#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { packageManagerCommand } from './package-manager-command.mjs';

const repositoryRoot = path.resolve(import.meta.dirname, '..');
const packageRoot = path.join(repositoryRoot, 'packages', 'signed-in');
const manifest = JSON.parse(readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
const npm = packageManagerCommand('npm');
const pnpm = packageManagerCommand('pnpm');
const requiredMetadata = ['author', 'bugs', 'description', 'engines', 'homepage', 'license', 'repository'];
for (const field of requiredMetadata) {
  if (!manifest[field]) throw new Error(`Package metadata is missing '${field}'`);
}

execFileSync(pnpm.executable, [...pnpm.prefixArgs, '--filter', 'signed-in', 'build'], {
  cwd: repositoryRoot,
  stdio: 'inherit',
});
const result = JSON.parse(execFileSync(npm.executable, [...npm.prefixArgs, 'pack', '--dry-run', '--json', '--ignore-scripts'], {
  cwd: packageRoot,
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'inherit'],
}));
const packedFiles = new Set(result[0]?.files?.map((entry) => entry.path) ?? []);
for (const required of ['LICENSE', 'README.md', 'dist/cli.js', 'dist/daemon-entry.js', 'dist/index.d.ts', 'skill/signed-in/SKILL.md']) {
  if (!packedFiles.has(required)) throw new Error(`Publish artifact is missing '${required}'`);
}
for (const forbidden of ['src/cli.ts', 'tsconfig.build.json']) {
  if (packedFiles.has(forbidden)) throw new Error(`Publish artifact unexpectedly includes '${forbidden}'`);
}

const unpackedSize = Number(result[0]?.unpackedSize ?? 0);
if (!Number.isFinite(unpackedSize) || unpackedSize <= 0) throw new Error('Publish artifact did not report a valid unpacked size');
process.stdout.write(`Package ready · ${packedFiles.size} files · ${formatBytes(unpackedSize)} unpacked\n`);

// Keeps the package check readable while retaining exact byte accounting in npm's JSON output.
function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}
