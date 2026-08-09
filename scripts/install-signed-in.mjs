#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { packageManagerCommand } from './package-manager-command.mjs';

const repoRoot = path.resolve(import.meta.dirname, '..');
const packageRoot = path.join(repoRoot, 'packages', 'signed-in');
const packageManifest = JSON.parse(readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
const npm = packageManagerCommand('npm');
const pnpm = packageManagerCommand('pnpm');
const globalPrefix = execFileSync(npm.executable, [...npm.prefixArgs, 'prefix', '--global'], { encoding: 'utf8' }).trim();
const binaryPath = process.platform === 'win32'
  ? path.join(globalPrefix, 'signed-in.cmd')
  : path.join(globalPrefix, 'bin', 'signed-in');
const daemonBinaryPath = process.platform === 'win32'
  ? path.join(globalPrefix, 'signed-in-daemon.cmd')
  : path.join(globalPrefix, 'bin', 'signed-in-daemon');

execFileSync(pnpm.executable, [...pnpm.prefixArgs, '--filter', 'signed-in', 'build'], {
  cwd: repoRoot,
  stdio: 'inherit',
});
const stagingDirectory = mkdtempSync(path.join(tmpdir(), 'signed-in-install-'));
try {
  const archiveName = execFileSync(npm.executable, [...npm.prefixArgs, 'pack', '--pack-destination', stagingDirectory], {
    cwd: packageRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  }).trim().split('\n').at(-1);
  if (!archiveName) throw new Error('npm pack did not return a signed-in archive name');
  if (process.platform === 'win32') stopExistingDaemonIfIdle(binaryPath);
  execFileSync(npm.executable, [...npm.prefixArgs, 'install', '--global', path.join(stagingDirectory, archiveName)], {
    cwd: repoRoot,
    stdio: 'inherit',
  });
  verifyInstalledCli(binaryPath, daemonBinaryPath, packageManifest.version);
  process.stdout.write(`\n✓ signed-in ${packageManifest.version} is installed\n`);
  process.stdout.write(`  ${binaryPath}\n\n`);
  process.stdout.write('A running helper will update automatically when it is idle.\n\n');
  process.stdout.write('Next\n  signed-in login\n');
} finally {
  rmSync(stagingDirectory, { force: true, recursive: true });
}

// Asks a prior Windows install to release loaded package files only when no provider operation is active.
function stopExistingDaemonIfIdle(installedBinary) {
  if (!existsSync(installedBinary)) return;
  try {
    execFileSync(installedBinary, ['daemon', 'stop', '--if-idle'], { stdio: 'ignore', timeout: 5_000 });
  } catch {
    // An older CLI or a busy daemon remains untouched; npm reports if Windows cannot replace its files yet.
  }
}

// Proves the global binary resolves to the package just built without initializing a vault or provider session.
function verifyInstalledCli(installedBinary, installedDaemonBinary, expectedVersion) {
  const actualVersion = execFileSync(installedBinary, ['--version'], { encoding: 'utf8', timeout: 5_000 }).trim();
  if (actualVersion !== expectedVersion) {
    throw new Error(`Installed signed-in version ${actualVersion || '(empty)'} does not match ${expectedVersion}`);
  }
  const help = execFileSync(installedBinary, ['--help'], { encoding: 'utf8', timeout: 5_000 });
  if (!help.includes('signed-in login')) throw new Error('Installed signed-in did not pass its help smoke test');
  if (!existsSync(installedDaemonBinary)) throw new Error('Installed signed-in-daemon binary did not resolve');
}
