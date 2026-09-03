import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';

import type { ExistingLoginPathConfig, NativeCliConfig, SessionBundle, SessionConfig, SessionFile } from './types.js';

export interface SessionSandbox {
  cleanup: () => void;
  env: NodeJS.ProcessEnv;
  home: string;
  snapshot: () => SessionBundle;
}

export interface SpawnedCommand {
  child: ChildProcessWithoutNullStreams;
  executable: string;
}

const defaultCaptureLimitBytes = 20 * 1024 * 1024;

// Materializes an encrypted provider session into a random private directory for one subprocess lifetime.
export function createSessionSandbox(
  bundle: SessionBundle | undefined,
  config: SessionConfig | undefined,
  baseEnvironment: NodeJS.ProcessEnv = process.env,
): SessionSandbox {
  const root = mkdtempSync(path.join(resolveMemoryBackedTempRoot(), 'signed-in-session-'));
  const home = path.join(root, 'home');
  mkdirSync(home, { mode: 0o700, recursive: true });
  if (bundle) materializeBundle(home, bundle);
  const env = buildSessionEnvironment(home, config?.env, baseEnvironment);
  let cleaned = false;

  return {
    cleanup: () => {
      if (cleaned) return;
      cleaned = true;
      rmSync(root, { force: true, recursive: true });
    },
    env,
    home,
    snapshot: () => snapshotBundle(home, config?.captureLimitBytes ?? defaultCaptureLimitBytes),
  };
}

// Launches exactly the trusted executable and argv without involving a shell parser.
export function spawnProviderCommand(
  cli: NativeCliConfig,
  args: string[],
  options: { cwd: string; env: NodeJS.ProcessEnv },
): SpawnedCommand {
  if (!cli.trustedExecutable) {
    throw new Error(`Provider executable '${cli.command}' is not installed and trusted; run signed-in trust after installing it`);
  }
  const executable = cli.trustedExecutable;
  if (cli.trustedExecutableSha256) {
    const currentDigest = createHash('sha256').update(readFileSync(executable)).digest('hex');
    if (currentDigest !== cli.trustedExecutableSha256) {
      throw new Error(`Trusted provider executable changed: ${executable}. Review it, then run signed-in trust.`);
    }
  }
  const child = spawn(executable, [...expandTrustedArgs(cli.prefixArgs ?? [], options.cwd), ...args], {
    cwd: options.cwd,
    env: options.env,
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  return { child, executable };
}

// Expands only broker-owned path placeholders so portable provider declarations work from any repo subdirectory.
function expandTrustedArgs(args: string[], cwd: string): string[] {
  const workspaceRoot = findWorkspaceRoot(cwd);
  return args.map((argument) => argument
    .replaceAll('{cwd}', cwd)
    .replaceAll('{workspaceRoot}', workspaceRoot));
}

// Finds the nearest workspace or repository root without executing project-owned code.
function findWorkspaceRoot(startDirectory: string): string {
  let current = path.resolve(startDirectory);
  while (true) {
    if (existsSync(path.join(current, 'pnpm-workspace.yaml')) || existsSync(path.join(current, '.git'))) return current;
    const parent = path.dirname(current);
    if (parent === current) return path.resolve(startDirectory);
    current = parent;
  }
}

// Captures only regular files and rejects links that could smuggle unrelated machine files into the vault.
export function snapshotBundle(home: string, limitBytes = defaultCaptureLimitBytes): SessionBundle {
  const files: SessionFile[] = [];
  let totalBytes = 0;

  // Walks the private sandbox without following symbolic links or device nodes.
  function visit(directory: string): void {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const absolutePath = path.join(directory, entry.name);
      const relativePath = path.relative(home, absolutePath);
      if (entry.isSymbolicLink()) throw new Error(`Provider session created an unsupported symlink: ${relativePath}`);
      if (entry.isDirectory()) {
        if (!isDisposableSessionDirectory(relativePath)) visit(absolutePath);
        continue;
      }
      if (!entry.isFile()) continue;
      const stat = lstatSync(absolutePath);
      totalBytes += stat.size;
      if (totalBytes > limitBytes) throw new Error(`Provider session exceeded its ${limitBytes}-byte capture limit`);
      files.push({
        contents: readFileSync(absolutePath).toString('base64'),
        mode: stat.mode & 0o777,
        path: normalizeBundlePath(relativePath),
      });
    }
  }

  visit(home);
  return { files, updatedAt: new Date().toISOString() };
}

// Copies only catalog-declared local login paths while remapping them into the provider's isolated session layout.
export function snapshotDeclaredPaths(
  home: string,
  paths: ExistingLoginPathConfig[],
  limitBytes = defaultCaptureLimitBytes,
): SessionBundle {
  const files = new Map<string, SessionFile>();
  const resolvedHome = path.resolve(home);
  let totalBytes = 0;

  // Captures one file or directory without following links beyond the declared source boundary.
  function capture(sourceRoot: string, targetRoot: string): void {
    const sourceStat = lstatSync(sourceRoot);
    if (sourceStat.isSymbolicLink()) throw new Error(`Existing provider login uses an unsupported symlink: ${path.relative(resolvedHome, sourceRoot)}`);
    if (sourceStat.isFile()) {
      addFile(sourceRoot, targetRoot, sourceStat.mode, sourceStat.size);
      return;
    }
    if (!sourceStat.isDirectory()) return;
    for (const entry of readdirSync(sourceRoot, { withFileTypes: true })) {
      const sourcePath = path.join(sourceRoot, entry.name);
      const targetPath = path.posix.join(targetRoot, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`Existing provider login uses an unsupported symlink: ${path.relative(resolvedHome, sourcePath)}`);
      if (entry.isDirectory()) {
        if (!isDisposableSessionDirectory(targetPath)) capture(sourcePath, targetPath);
        continue;
      }
      if (!entry.isFile()) continue;
      const stat = lstatSync(sourcePath);
      addFile(sourcePath, targetPath, stat.mode, stat.size);
    }
  }

  // Enforces one bounded value per isolated destination so overlapping compatibility paths cannot disagree silently.
  function addFile(sourcePath: string, targetPath: string, mode: number, size: number): void {
    totalBytes += size;
    if (totalBytes > limitBytes) throw new Error(`Existing provider login exceeded its ${limitBytes}-byte capture limit`);
    const normalizedTarget = normalizeBundlePath(targetPath);
    const candidate = {
      contents: readFileSync(sourcePath).toString('base64'),
      mode: mode & 0o777,
      path: normalizedTarget,
    };
    const existing = files.get(normalizedTarget);
    if (existing && existing.contents !== candidate.contents) {
      throw new Error(`Existing provider login has conflicting files for ${normalizedTarget}`);
    }
    files.set(normalizedTarget, candidate);
  }

  for (const entry of paths) {
    if (entry.platform && entry.platform !== process.platform) continue;
    const sourcePath = path.resolve(resolvedHome, normalizeBundlePath(entry.source));
    if (sourcePath === resolvedHome || !sourcePath.startsWith(`${resolvedHome}${path.sep}`)) {
      throw new Error(`Unsafe existing provider login path: ${entry.source}`);
    }
    if (!existsSync(sourcePath)) continue;
    capture(sourcePath, normalizeBundlePath(entry.target));
  }
  return { files: [...files.values()].sort((left, right) => left.path.localeCompare(right.path)), updatedAt: new Date().toISOString() };
}

// Restores only validated relative paths beneath the freshly-created sandbox home.
export function materializeBundle(home: string, bundle: SessionBundle): void {
  for (const file of bundle.files) {
    const relativePath = normalizeBundlePath(file.path);
    const destination = path.resolve(home, relativePath);
    if (destination !== home && !destination.startsWith(`${path.resolve(home)}${path.sep}`)) {
      throw new Error(`Unsafe provider session path: ${file.path}`);
    }
    mkdirSync(path.dirname(destination), { mode: 0o700, recursive: true });
    writeFileSync(destination, Buffer.from(file.contents, 'base64'), { mode: restrictFileMode(file.mode) });
  }
}

// Removes inherited credentials and adapter-declared names or prefixes while preserving ordinary process behavior.
export function sanitizeEnvironment(
  environment: NodeJS.ProcessEnv,
  clearEnv: string[] = [],
): NodeJS.ProcessEnv {
  const cleared = new Set(clearEnv.filter((name) => !name.endsWith('*')).map((name) => name.toUpperCase()));
  const clearedPrefixes = clearEnv.filter((name) => name.endsWith('*')).map((name) => name.slice(0, -1).toUpperCase());
  return Object.fromEntries(Object.entries(environment).filter(([name, value]) => {
    const upperName = name.toUpperCase();
    if (value === undefined || cleared.has(upperName) || clearedPrefixes.some((prefix) => upperName.startsWith(prefix))) return false;
    if (/(?:^|_)(?:API_?KEY|AUTH|CREDENTIALS?|PASSWORD|PRIVATE_?KEY|SECRET|SESSION_?TOKEN|TOKEN)(?:$|_)/iu.test(name)) {
      return false;
    }
    if (['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'GOOGLE_APPLICATION_CREDENTIALS'].includes(name)) {
      return false;
    }
    return true;
  }));
}

// Gives common CLIs deterministic session paths even when their platform defaults differ.
function buildSessionEnvironment(
  home: string,
  configured: Record<string, string> | undefined,
  baseEnvironment: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const env = sanitizeEnvironment(baseEnvironment);
  Object.assign(env, {
    AWS_LOGIN_CACHE_DIRECTORY: path.join(home, '.aws', 'login', 'cache'),
    CLOUDSDK_CONFIG: path.join(home, '.config', 'gcloud'),
    GH_CONFIG_DIR: path.join(home, '.config', 'gh'),
    HOME: home,
    USERPROFILE: home,
    XDG_CACHE_HOME: path.join(home, '.cache'),
    XDG_CONFIG_HOME: path.join(home, '.config'),
    XDG_DATA_HOME: path.join(home, '.local', 'share'),
    XDG_STATE_HOME: path.join(home, '.local', 'state'),
  });
  for (const [name, value] of Object.entries(configured ?? {})) {
    env[name] = value.replaceAll('{home}', home);
  }
  return env;
}

// Prefers a memory-backed Linux temporary filesystem to reduce recoverable credential remnants.
function resolveMemoryBackedTempRoot(): string {
  if (process.platform === 'linux' && existsSync('/dev/shm')) return '/dev/shm';
  return tmpdir();
}

// Drops disposable provider noise while retaining AWS's unfortunately cache-named login authority.
function isDisposableSessionDirectory(relativePath: string): boolean {
  const segments = relativePath.split(path.sep).map((segment) => segment.toLowerCase());
  if (segments.join('/') === '.aws/login/cache') return false;
  return segments.some((segment) => ['cache', 'caches', 'logs', 'telemetry', 'tmp', 'venv', 'virtenv'].includes(segment.replace(/^\./u, '')));
}

// Converts platform separators and rejects empty, absolute, or parent-traversing paths.
function normalizeBundlePath(value: string): string {
  const normalized = value.replaceAll('\\', '/').replace(/^\.\//u, '');
  if (!normalized || normalized.startsWith('/') || normalized.split('/').includes('..')) {
    throw new Error(`Unsafe provider session path: ${value}`);
  }
  return normalized;
}

// Preserves executability while never restoring group or world access from provider-created files.
function restrictFileMode(mode: number): number {
  return mode & 0o100 ? 0o700 : 0o600;
}
