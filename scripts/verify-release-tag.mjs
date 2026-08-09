#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import path from 'node:path';

const repositoryRoot = path.resolve(import.meta.dirname, '..');
const manifest = JSON.parse(readFileSync(path.join(repositoryRoot, 'packages', 'signed-in', 'package.json'), 'utf8'));
const tag = process.argv[2];
if (!tag) throw new Error('Usage: node scripts/verify-release-tag.mjs <tag>');
if (tag !== `v${manifest.version}`) {
  throw new Error(`Release tag '${tag}' does not match package version '${manifest.version}'`);
}
process.stdout.write(`Release tag matches signed-in ${manifest.version}\n`);
