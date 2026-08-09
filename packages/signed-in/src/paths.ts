import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { homedir, tmpdir, userInfo } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

export const signedInBuild = resolveSignedInBuild();

export interface SignedInPaths {
  auditFile: string;
  configDir: string;
  daemonLogFile: string;
  dataDir: string;
  runtimeDir: string;
  socketPath: string;
  stateFile: string;
  vaultDir: string;
}

// Keeps all platform-specific filesystem choices in one place so security-sensitive callers agree.
export function resolveSignedInPaths(environment: NodeJS.ProcessEnv = process.env): SignedInPaths {
  const home = homedir();
  const configDir = resolveConfigDir(home, environment);
  const dataDir = resolveDataDir(home, environment);
  const runtimeDir = resolveRuntimeDir(environment);
  const socketPath = process.platform === 'win32'
    ? `\\\\.\\pipe\\signed-in-${stableUserId()}`
    : path.join(runtimeDir, 'daemon.sock');

  return {
    auditFile: path.join(dataDir, 'audit.jsonl'),
    configDir,
    daemonLogFile: path.join(dataDir, 'daemon.log'),
    dataDir,
    runtimeDir,
    socketPath,
    stateFile: path.join(configDir, 'state.json'),
    vaultDir: path.join(dataDir, 'vault'),
  };
}

// Creates private directories before any socket, audit, or encrypted vault artifact is written.
export function ensureSignedInDirectories(paths: SignedInPaths): void {
  for (const directory of [paths.configDir, paths.dataDir, paths.runtimeDir, paths.vaultDir]) {
    if (directory) mkdirSync(directory, { mode: 0o700, recursive: true });
  }
}

// Fingerprints the loaded package once so a resident daemon cannot impersonate newly installed code after files change beneath it.
function resolveSignedInBuild(): string {
  const directory = path.dirname(fileURLToPath(import.meta.url));
  const extension = path.extname(fileURLToPath(import.meta.url));
  const sources = readdirSync(directory).filter((entry) => {
    const candidateExtension = path.extname(entry);
    return candidateExtension === extension || candidateExtension === '.json';
  }).sort();
  const digest = createHash('sha256');
  for (const source of sources) digest.update(source).update(readFileSync(path.join(directory, source)));
  const manifest = path.resolve(directory, '..', 'package.json');
  if (existsSync(manifest)) digest.update('package.json').update(readFileSync(manifest));
  return digest.digest('hex').slice(0, 16);
}

// Follows each operating system's conventional user configuration location.
function resolveConfigDir(home: string, environment: NodeJS.ProcessEnv): string {
  if (environment.SIGNED_IN_CONFIG_HOME) return path.resolve(environment.SIGNED_IN_CONFIG_HOME);
  if (process.platform === 'darwin') return path.join(home, 'Library', 'Application Support', 'SignedIn');
  if (process.platform === 'win32') return path.join(environment.APPDATA ?? home, 'SignedIn');
  return path.join(environment.XDG_CONFIG_HOME ?? path.join(home, '.config'), 'signed-in');
}

// Separates mutable logs and encrypted records from the human-editable registry.
function resolveDataDir(home: string, environment: NodeJS.ProcessEnv): string {
  if (environment.SIGNED_IN_DATA_HOME) return path.resolve(environment.SIGNED_IN_DATA_HOME);
  if (process.platform === 'darwin') return path.join(home, 'Library', 'Application Support', 'SignedIn', 'data');
  if (process.platform === 'win32') return path.join(environment.LOCALAPPDATA ?? environment.APPDATA ?? home, 'SignedIn');
  return path.join(environment.XDG_DATA_HOME ?? path.join(home, '.local', 'share'), 'signed-in');
}

// Uses a short, private runtime path to stay within Unix-domain socket path limits.
function resolveRuntimeDir(environment: NodeJS.ProcessEnv): string {
  if (environment.SIGNED_IN_RUNTIME_DIR) return path.resolve(environment.SIGNED_IN_RUNTIME_DIR);
  if (process.platform === 'win32') return '';
  if (environment.XDG_RUNTIME_DIR) return path.join(environment.XDG_RUNTIME_DIR, 'signed-in');
  return path.join(tmpdir(), `signed-in-${stableUserId()}`);
}

// Produces a stable non-secret identifier without leaking a username into a globally visible socket name.
function stableUserId(): string {
  const identity = typeof process.getuid === 'function' ? String(process.getuid()) : userInfo().username;
  return createHash('sha256').update(identity).digest('hex').slice(0, 12);
}
