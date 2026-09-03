import { randomBytes } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { constants as osConstants } from 'node:os';
import path from 'node:path';
import { StringDecoder } from 'node:string_decoder';

import { dummyCredentialEnvironment } from './http-auth.js';
import { classifyOperation } from './policy.js';
import {
  startCredentialProxy,
  startCredentialSocketProxy,
  type CredentialProxy,
  type CredentialProxyOptions,
  type CredentialSocketProxy,
} from './proxy.js';
import { collectSensitiveStrings, StreamRedactor } from './redact.js';
import {
  createSessionSandbox,
  sanitizeEnvironment,
  snapshotDeclaredPaths,
  spawnProviderCommand,
  type SessionSandbox,
} from './session.js';
import type {
  CredentialRecord,
  ExistingLoginDiscovery,
  SignedInProjectConfig,
  ProviderConfig,
  SessionBundle,
  SessionResolverConfig,
} from './types.js';

export interface CommandCallbacks {
  onChild?: (child: ReturnType<typeof spawnProviderCommand>['child']) => void;
  onStderr: (chunk: Buffer) => void;
  onStdout: (chunk: Buffer) => void;
}

export interface CommandResult {
  clearSession?: boolean;
  credentials: CredentialRecord;
  exitCode: number;
  session?: SessionBundle;
}

export class ProviderAuthenticationError extends Error {
  // Distinguishes an expired provider session from an ordinary vendor-command failure without exposing resolver output.
  constructor(message: string) {
    super(message);
    this.name = 'ProviderAuthenticationError';
  }
}

// Probes one catalog-declared local CLI login without returning credential-bearing provider output over IPC.
export async function discoverExistingProviderLogin(options: {
  cwd: string;
  provider: ProviderConfig;
}): Promise<ExistingLoginDiscovery> {
  const existing = options.provider.existingLogin;
  if (!options.provider.cli || !existing) return { available: false, source: options.provider.cli?.command ?? 'local CLI' };
  const env = sanitizeEnvironment(process.env);
  try {
    if (!existingLoginFilesAvailable(existing)) return { available: false, source: existing.source };
    await capturePrivateCommand(options.provider.cli, existing.detectArgs, options.cwd, env, undefined, 15_000);
    const identity = existing.identityArgs
      ? normalizeExistingIdentity(await capturePrivateCommand(options.provider.cli, existing.identityArgs, options.cwd, env, undefined, 15_000, existing.identityStream), existing.identityPattern)
      : undefined;
    if (existing.identityArgs && !identity) return { available: false, source: existing.source };
    return { available: true, ...(identity ? { identity } : {}), source: existing.source };
  } catch {
    return { available: false, source: existing.source };
  }
}

// Requires at least one copyable local session file before presenting an existing-login adoption action.
function existingLoginFilesAvailable(existing: NonNullable<ProviderConfig['existingLogin']>): boolean {
  const paths = (existing.paths ?? []).filter((entry) => !entry.platform || entry.platform === process.platform);
  if (paths.length === 0) return true;
  const home = process.env.HOME ?? process.env.USERPROFILE;
  if (!home) return false;
  return paths.some((entry) => pathContainsRegularFile(path.resolve(home, entry.source), path.resolve(home)));
}

// Walks declared provider-owned roots without following symlinks or reading credential contents.
function pathContainsRegularFile(candidate: string, home: string): boolean {
  if (candidate !== home && !candidate.startsWith(`${home}${path.sep}`)) return false;
  try {
    const stats = lstatSync(candidate);
    if (stats.isSymbolicLink()) return false;
    if (stats.isFile()) return true;
    if (!stats.isDirectory()) return false;
    return readdirSync(candidate).some((entry) => pathContainsRegularFile(path.join(candidate, entry), home));
  } catch {
    return false;
  }
}

// Copies one working local CLI login into an isolated session and resolves only catalog-declared credential fields.
export async function adoptExistingProviderLogin(options: {
  cwd: string;
  provider: ProviderConfig;
}): Promise<CommandResult & { identity?: string }> {
  const existing = options.provider.existingLogin;
  if (!options.provider.cli || !options.provider.session || !existing) {
    throw new Error('Provider does not define an existing-login adoption flow');
  }
  const paths = (existing.paths ?? []).filter((entry) => !entry.platform || entry.platform === process.platform);
  const home = process.env.HOME ?? process.env.USERPROFILE;
  if (paths.length > 0 && !home) throw new ProviderAuthenticationError('Could not locate the operator home for existing provider login adoption');
  const bundle = paths.length > 0
    ? snapshotDeclaredPaths(home!, paths, options.provider.session.captureLimitBytes)
    : undefined;
  if (paths.length > 0 && bundle?.files.length === 0) {
    throw new ProviderAuthenticationError(`No ${existing.source} login files were found`);
  }
  const sandbox = bundle ? createProviderSessionSandbox(options.provider, bundle) : undefined;
  const env = sandbox?.env ?? sanitizeEnvironment(process.env);
  try {
    await capturePrivateCommand(options.provider.cli, existing.detectArgs, options.cwd, env, undefined, 30_000);
    const identity = existing.identityArgs
      ? normalizeExistingIdentity(await capturePrivateCommand(options.provider.cli, existing.identityArgs, options.cwd, env, undefined, 30_000, existing.identityStream), existing.identityPattern)
      : undefined;
    const credentials = options.provider.session.resolvers?.length
      ? (await resolveSessionCredentials({
        credentials: emptyRunnerCredentialRecord(),
        cwd: options.cwd,
        provider: options.provider,
        sandbox: sandbox ?? ambientSessionContext(env),
      })).credentials
      : emptyRunnerCredentialRecord();
    const retainSession = Boolean(bundle) && (
      options.provider.session.retain !== false
      || (options.provider.session.resolvers ?? []).some((resolver) => resolver.persist === false)
    );
    return {
      ...(retainSession && sandbox ? { session: sandbox.snapshot() } : { clearSession: true }),
      credentials,
      exitCode: 0,
      ...(identity ? { identity } : {}),
    };
  } finally {
    sandbox?.cleanup();
  }
}

// Gives direct credential resolvers the same private interface as a captured session without snapshotting ambient files.
function ambientSessionContext(env: NodeJS.ProcessEnv): SessionSandbox {
  return {
    cleanup: () => undefined,
    env,
    home: env.HOME ?? env.USERPROFILE ?? '',
    snapshot: () => ({ files: [], updatedAt: new Date().toISOString() }),
  };
}

// Starts an adoption from no prior authority so optional fields cannot leak across replaced accounts.
function emptyRunnerCredentialRecord(): CredentialRecord {
  return { fields: {}, updatedAt: new Date().toISOString() };
}

// Applies adapter-specific environment clearing before any retained provider session is materialized.
function createProviderSessionSandbox(provider: ProviderConfig, bundle?: SessionBundle): SessionSandbox {
  if (!provider.cli) throw new Error('Provider session sandbox needs a trusted CLI');
  return createSessionSandbox(
    bundle,
    provider.session,
    sanitizeEnvironment(process.env, provider.cli.clearEnv),
  );
}

// Reduces catalog-approved identity output to one bounded display value, optionally through a declared capture group.
function normalizeExistingIdentity(output: string, pattern?: string): string | undefined {
  const selected = pattern ? new RegExp(pattern, 'mu').exec(output)?.[1] : output;
  const normalized = selected?.trim().replace(/\s+/gu, ' ').slice(0, 160);
  return normalized || undefined;
}

// Refreshes command-derived API credentials without exposing resolver output or materialized session files.
export async function refreshProviderCredentials(options: {
  credentials: CredentialRecord;
  cwd: string;
  provider: ProviderConfig;
  session?: SessionBundle;
}): Promise<{ credentials: CredentialRecord; session?: SessionBundle }> {
  if (!options.provider.session?.resolvers?.length) {
    return { credentials: options.credentials, ...(options.session ? { session: options.session } : {}) };
  }
  return resolveWithFreshSandbox(options);
}

/**
 * Lets a human-started provider bootstrap consume structured control-plane responses without
 * exposing stdout, stderr, or temporary credentials through IPC.
 */
export async function runPrivateProviderJson(options: {
  args: string[];
  callbacks?: Pick<CommandCallbacks, 'onChild'>;
  credentials: CredentialRecord;
  cwd: string;
  provider: ProviderConfig;
}): Promise<unknown> {
  if (!options.provider.cli) throw new Error('Private provider command needs a trusted CLI');
  const env = sanitizeEnvironment(process.env, options.provider.cli.clearEnv);
  injectCredentialEnvironment(env, options.provider, options.credentials.fields);
  env.AWS_PAGER = '';
  const output = await capturePrivateCommand(options.provider.cli, options.args, options.cwd, env, options.callbacks?.onChild);
  if (!output) return {};
  try {
    return JSON.parse(output) as unknown;
  } catch {
    throw new Error('Provider bootstrap returned invalid JSON');
  }
}

// Runs a provider login in a private session home and captures the refreshable result into encrypted storage.
export async function runProviderLogin(options: {
  callbacks: CommandCallbacks;
  credentials: CredentialRecord;
  cwd: string;
  provider: ProviderConfig;
  remote: boolean;
  session?: SessionBundle;
}): Promise<CommandResult> {
  if (!options.provider.cli || !options.provider.session) throw new Error('Provider does not define a native login flow');
  const sandbox = createProviderSessionSandbox(options.provider, options.session);
  try {
    const args = options.remote && options.provider.session.remoteLoginArgs
      ? options.provider.session.remoteLoginArgs
      : options.provider.session.loginArgs;
    const exitCode = await executeChild(
      options.provider.cli,
      args,
      options.cwd,
      sandbox.env,
      options.callbacks,
      [...Object.values(options.credentials.fields), ...sessionSecrets(options.session)],
    );
    let credentials = options.credentials;
    if (exitCode === 0 && options.provider.session.resolvers?.length) {
      const resolved = await resolveSessionCredentials({
        credentials,
        cwd: options.cwd,
        provider: options.provider,
        sandbox,
      });
      credentials = resolved.credentials;
    }
    const retainSession = options.provider.session.retain !== false
      || (options.provider.session.resolvers ?? []).some((resolver) => resolver.persist === false);
    return {
      ...(retainSession ? { session: sandbox.snapshot() } : { clearSession: true }),
      credentials,
      exitCode,
    };
  } finally {
    sandbox.cleanup();
  }
}

// Runs a trusted provider command with proxy, env, session, or no-auth delivery selected by sealed config.
export async function runProviderCommand(options: {
  args: string[];
  callbacks: CommandCallbacks;
  commandEnvironment?: Record<string, string>;
  config: SignedInProjectConfig;
  credentials: CredentialRecord;
  cwd: string;
  provider: ProviderConfig;
  providerId: string;
  session?: SessionBundle;
}): Promise<CommandResult> {
  if (!options.provider.cli) throw new Error(`Provider '${options.providerId}' has no native CLI`);
  const resolved = options.provider.session?.resolvers?.length
    ? await resolveWithFreshSandbox(options)
    : { credentials: options.credentials, session: options.session };
  const secrets = [
    ...Object.values(resolved.credentials.fields),
    ...sessionSecrets(resolved.session),
  ];
  const delivery = options.provider.cli.delivery ?? (options.provider.http ? 'proxy' : 'environment');
  if (delivery === 'proxy') {
    return runProxyDeliveredCommand({ ...options, ...resolved, secrets });
  }
  if (delivery === 'session') {
    return runSessionDeliveredCommand({ ...options, ...resolved, secrets });
  }
  const env = sanitizeEnvironment(process.env, options.provider.cli.clearEnv);
  if (delivery === 'environment') injectCredentialEnvironment(env, options.provider, resolved.credentials.fields);
  applyCommandEnvironment(env, options.commandEnvironment);
  const exitCode = await executeChild(
    options.provider.cli,
    options.args,
    options.cwd,
    env,
    options.callbacks,
    secrets,
  );
  return { credentials: resolved.credentials, exitCode, ...(resolved.session ? { session: resolved.session } : {}) };
}

// Resolves expiring credentials inside a session sandbox and re-seals any provider refresh state.
async function resolveWithFreshSandbox(options: {
  credentials: CredentialRecord;
  cwd: string;
  provider: ProviderConfig;
  session?: SessionBundle;
}): Promise<{ credentials: CredentialRecord; session?: SessionBundle }> {
  if (!options.provider.session || !options.session) return { credentials: options.credentials, session: options.session };
  const sandbox = createProviderSessionSandbox(options.provider, options.session);
  try {
    const resolved = await resolveSessionCredentials({
      credentials: options.credentials,
      cwd: options.cwd,
      provider: options.provider,
      sandbox,
    });
    return {
      credentials: resolved.credentials,
      session: sandbox.snapshot(),
    };
  } finally {
    sandbox.cleanup();
  }
}

// Uses dummy child credentials plus a private local broker while real auth stays inside signed-in.
async function runProxyDeliveredCommand(options: {
  args: string[];
  callbacks: CommandCallbacks;
  commandEnvironment?: Record<string, string>;
  config: SignedInProjectConfig;
  credentials: CredentialRecord;
  cwd: string;
  provider: ProviderConfig;
  providerId: string;
  secrets: string[];
  session?: SessionBundle;
}): Promise<CommandResult> {
  if (!options.provider.cli || !options.provider.http) {
    throw new Error('Proxy delivery needs both native CLI and HTTP gateway configuration');
  }
  const sandbox = createSessionSandbox(
    undefined,
    undefined,
    sanitizeEnvironment(process.env, options.provider.cli.clearEnv),
  );
  let proxy: CredentialProxy | CredentialSocketProxy | undefined;
  try {
    const proxyOptions: CredentialProxyOptions = {
      credentials: options.credentials.fields,
      gateway: options.provider.http,
      onRequest: (request) => {
        const classification = classifyOperation({
          environment: options.config.environment,
          interface: 'http',
          method: request.method,
          path: request.path,
          projectId: options.config.project.id,
          providerId: options.providerId,
        }, options.provider);
        if (classification === 'credential-control') {
          throw new Error('Credential-control endpoint denied inside native CLI operation');
        }
      },
      secrets: options.secrets,
    };
    if (options.provider.cli.proxySocket && process.platform !== 'win32') {
      const socketPath = path.join(sandbox.home, 'provider-http.sock');
      proxy = await startCredentialSocketProxy(proxyOptions, socketPath);
      materializeProxySocketConfig(sandbox.home, options.provider.cli.proxySocket, socketPath);
      clearProxyEnvironment(sandbox.env);
    } else {
      proxy = await startCredentialProxy(proxyOptions);
      const caPath = path.join(sandbox.home, 'provider-ca.pem');
      writeFileSync(caPath, proxy.caCertificate, { mode: 0o600 });
      Object.assign(sandbox.env, {
        AWS_CA_BUNDLE: caPath,
        CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE: caPath,
        CURL_CA_BUNDLE: caPath,
        GIT_SSL_CAINFO: caPath,
        HTTPS_PROXY: proxy.url,
        HTTP_PROXY: proxy.url,
        NODE_EXTRA_CA_CERTS: caPath,
        NO_PROXY: '',
        REQUESTS_CA_BUNDLE: caPath,
        SSL_CERT_FILE: caPath,
        https_proxy: proxy.url,
        http_proxy: proxy.url,
        no_proxy: '',
      });
    }
    Object.assign(sandbox.env, dummyCredentialEnvironment(
      options.provider.http.auth,
      options.provider.credentials ?? [],
      randomBytes(18).toString('base64url'),
    ));
    applyAwsSafetyEnvironment(sandbox.env, options.provider);
    applyCommandEnvironment(sandbox.env, options.commandEnvironment);
    const exitCode = await executeChild(
      options.provider.cli,
      options.args,
      options.cwd,
      sandbox.env,
      options.callbacks,
      options.secrets,
    );
    return {
      credentials: options.credentials,
      exitCode,
      ...(options.session ? { session: options.session } : {}),
    };
  } finally {
    if (proxy) await proxy.close();
    sandbox.cleanup();
  }
}

// Writes only sealed provider metadata into the disposable command home and expands the broker-owned socket path.
function materializeProxySocketConfig(
  home: string,
  config: NonNullable<NonNullable<ProviderConfig['cli']>['proxySocket']>,
  socketPath: string,
): void {
  const relativePath = config.configPath.replaceAll('\\', '/');
  const destination = path.resolve(home, relativePath);
  if (destination === home || !destination.startsWith(`${home}${path.sep}`)) {
    throw new Error('Unsafe native proxy socket config path');
  }
  mkdirSync(path.dirname(destination), { mode: 0o700, recursive: true });
  writeFileSync(destination, config.configTemplate.replaceAll('{socket}', socketPath), { mode: 0o600 });
}

// Prevents machine-level proxy settings from competing with a CLI's explicit private socket transport.
function clearProxyEnvironment(env: NodeJS.ProcessEnv): void {
  for (const name of ['ALL_PROXY', 'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'all_proxy', 'https_proxy', 'http_proxy', 'no_proxy']) {
    delete env[name];
  }
}

// Materializes actual session files only for providers that cannot accept brokered network authentication.
async function runSessionDeliveredCommand(options: {
  args: string[];
  callbacks: CommandCallbacks;
  commandEnvironment?: Record<string, string>;
  credentials: CredentialRecord;
  cwd: string;
  provider: ProviderConfig;
  secrets: string[];
  session?: SessionBundle;
}): Promise<CommandResult> {
  if (!options.provider.cli || !options.provider.session || !options.session) {
    throw new Error('Provider session is not available');
  }
  const sandbox = createProviderSessionSandbox(options.provider, options.session);
  try {
    applyCommandEnvironment(sandbox.env, options.commandEnvironment);
    const exitCode = await executeChild(
      options.provider.cli,
      options.args,
      options.cwd,
      sandbox.env,
      options.callbacks,
      options.secrets,
    );
    return { credentials: options.credentials, exitCode, session: sandbox.snapshot() };
  } finally {
    sandbox.cleanup();
  }
}

// Applies only environment values derived from catalog-declared project targets after ambient values are sanitized.
function applyCommandEnvironment(env: NodeJS.ProcessEnv, commandEnvironment?: Record<string, string>): void {
  if (commandEnvironment) Object.assign(env, commandEnvironment);
}

// Executes refresh-token resolvers privately and maps only declared output fields into daemon memory.
async function resolveSessionCredentials(options: {
  credentials: CredentialRecord;
  cwd: string;
  provider: ProviderConfig;
  sandbox: SessionSandbox;
}): Promise<{ credentials: CredentialRecord }> {
  if (!options.provider.cli || !options.provider.session) return { credentials: options.credentials };
  const fields = { ...options.credentials.fields };
  for (const resolver of options.provider.session.resolvers ?? []) {
    if (resolver.format === 'json-file-key') {
      Object.assign(fields, resolveJsonFileKeys(resolver, options.sandbox.snapshot()));
      continue;
    }
    const output = await capturePrivateCommand(
      options.provider.cli,
      resolver.args,
      options.cwd,
      options.sandbox.env,
      undefined,
      120_000,
    );
    Object.assign(fields, parseResolverOutput(resolver, output));
  }
  return { credentials: { fields, updatedAt: new Date().toISOString() } };
}

// Extracts declared key names from captured JSON files while rejecting ambiguous multiple credential values.
function resolveJsonFileKeys(resolver: SessionResolverConfig, bundle: SessionBundle): Record<string, string> {
  if (!resolver.fieldMap) throw new Error('JSON-file session resolver needs fieldMap');
  const documents = bundle.files.flatMap((file) => {
    if (!file.path.toLowerCase().endsWith('.json')) return [];
    try {
      return [JSON.parse(Buffer.from(file.contents, 'base64').toString('utf8')) as unknown];
    } catch {
      return [];
    }
  });
  return Object.fromEntries(Object.entries(resolver.fieldMap).map(([field, key]) => {
    const matches = [...new Set(documents.flatMap((document) => findJsonKeyValues(document, key)))];
    if (matches.length !== 1) {
      throw new ProviderAuthenticationError(`Provider session did not contain exactly one '${key}' value for '${field}'`);
    }
    return [field, matches[0]!];
  }));
}

// Searches structured session documents by exact key without interpreting filenames or arbitrary pointers.
function findJsonKeyValues(value: unknown, targetKey: string): string[] {
  if (Array.isArray(value)) return value.flatMap((item) => findJsonKeyValues(item, targetKey));
  if (typeof value !== 'object' || value === null) return [];
  return Object.entries(value as Record<string, unknown>).flatMap(([key, item]) => [
    ...(key === targetKey && typeof item === 'string' && item !== '' ? [item] : []),
    ...findJsonKeyValues(item, targetKey),
  ]);
}

// Captures resolver stdout without streaming tokens or provider session errors to the invoking agent.
function capturePrivateCommand(
  cli: NonNullable<ProviderConfig['cli']>,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  onChild?: CommandCallbacks['onChild'],
  timeoutMs?: number,
  outputStream: 'stderr' | 'stdout' = 'stdout',
): Promise<string> {
  return new Promise((resolve, reject) => {
    const { child } = spawnProviderCommand(cli, args, { cwd, env });
    onChild?.(child);
    const output: Buffer[] = [];
    let size = 0;
    let overflow = false;
    let timedOut = false;
    const timeout = timeoutMs ? setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
    }, timeoutMs) : undefined;
    const selected = outputStream === 'stderr' ? child.stderr : child.stdout;
    const discarded = outputStream === 'stderr' ? child.stdout : child.stderr;
    selected.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > 2 * 1024 * 1024) {
        overflow = true;
        child.kill('SIGTERM');
      }
      else output.push(chunk);
    });
    discarded.resume();
    child.on('error', (error) => {
      if (timeout) clearTimeout(timeout);
      reject(error);
    });
    child.on('close', (code) => {
      if (timeout) clearTimeout(timeout);
      if (timedOut) {
        reject(new ProviderAuthenticationError('Provider login check timed out'));
        return;
      }
      if (overflow) {
        reject(new Error('Provider credential refresh exceeded the private output limit'));
        return;
      }
      if (code !== 0) {
        reject(new ProviderAuthenticationError(`Provider credential refresh failed with exit code ${code ?? 1}`));
        return;
      }
      resolve(Buffer.concat(output).toString('utf8').trim());
    });
  });
}

// Supports durable text tokens, arbitrary JSON pointers, and AWS process-credential output.
function parseResolverOutput(resolver: SessionResolverConfig, output: string): Record<string, string> {
  if (resolver.format === 'text') {
    if (!resolver.targetField) throw new Error('Text session resolver needs targetField');
    if (!output) throw new ProviderAuthenticationError('Provider credential resolver returned an empty value');
    return { [resolver.targetField]: output };
  }
  let parsed: unknown;
  try { parsed = JSON.parse(output) as unknown; }
  catch { throw new ProviderAuthenticationError('Provider credential resolver returned invalid JSON'); }
  const defaultMap = resolver.format === 'aws-process-json'
    ? { accessKeyId: '/AccessKeyId', secretAccessKey: '/SecretAccessKey', sessionToken: '/SessionToken' }
    : undefined;
  const fieldMap = resolver.fieldMap ?? defaultMap;
  if (!fieldMap) throw new Error('JSON session resolver needs fieldMap');
  return Object.fromEntries(Object.entries(fieldMap).flatMap(([field, pointer]) => {
    const value = readJsonPointer(parsed, pointer);
    if (resolver.format === 'aws-process-json' && field === 'sessionToken' && (value === undefined || value === null || value === '')) return [];
    if (typeof value !== 'string' || value === '') throw new ProviderAuthenticationError(`Credential resolver did not return '${field}'`);
    return [[field, value]];
  }));
}

// Reads simple RFC 6901 pointers without evaluating property names as code.
function readJsonPointer(value: unknown, pointer: string): unknown {
  if (pointer === '') return value;
  if (!pointer.startsWith('/')) throw new Error(`Invalid JSON pointer '${pointer}'`);
  return pointer.slice(1).split('/').reduce<unknown>((current, segment) => {
    if (typeof current !== 'object' || current === null) return undefined;
    const key = segment.replaceAll('~1', '/').replaceAll('~0', '~');
    return (current as Record<string, unknown>)[key];
  }, value);
}

// Streams provider output through chunk-safe exact redactors and returns only its numeric exit status.
function executeChild(
  cli: NonNullable<ProviderConfig['cli']>,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  callbacks: CommandCallbacks,
  secrets: string[],
): Promise<number> {
  return new Promise((resolve, reject) => {
    const { child } = spawnProviderCommand(cli, args, { cwd, env });
    callbacks.onChild?.(child);
    const stdoutRedactor = new StreamRedactor(secrets);
    const stderrRedactor = new StreamRedactor(secrets);
    const stdoutDecoder = new StringDecoder('utf8');
    const stderrDecoder = new StringDecoder('utf8');
    child.stdout.on('data', (chunk: Buffer) => {
      const safe = `${stdoutRedactor.push(stdoutDecoder.write(chunk))}${stdoutRedactor.flushPrompt()}`;
      if (safe) callbacks.onStdout(Buffer.from(safe, 'utf8'));
    });
    child.stderr.on('data', (chunk: Buffer) => {
      const safe = `${stderrRedactor.push(stderrDecoder.write(chunk))}${stderrRedactor.flushPrompt()}`;
      if (safe) callbacks.onStderr(Buffer.from(safe, 'utf8'));
    });
    child.on('error', reject);
    child.on('close', (code, signal) => {
      const finalStdout = `${stdoutRedactor.push(stdoutDecoder.end())}${stdoutRedactor.finish()}`;
      const finalStderr = `${stderrRedactor.push(stderrDecoder.end())}${stderrRedactor.finish()}`;
      if (finalStdout) callbacks.onStdout(Buffer.from(finalStdout, 'utf8'));
      if (finalStderr) callbacks.onStderr(Buffer.from(finalStderr, 'utf8'));
      resolve(code ?? signalExitCode(signal));
    });
  });
}

// Preserves the conventional shell status for provider processes terminated by an operating-system signal.
function signalExitCode(signal: NodeJS.Signals | null): number {
  if (!signal) return 1;
  return 128 + (osConstants.signals[signal] ?? 0);
}

// Injects real fields only for explicitly lower-isolation provider adapters.
function injectCredentialEnvironment(
  env: NodeJS.ProcessEnv,
  provider: ProviderConfig,
  fields: Record<string, string>,
): void {
  for (const field of provider.credentials ?? []) {
    if (field.env && fields[field.id]) env[field.env] = fields[field.id];
  }
}

// Prevents the AWS CLI from falling back to ordinary plaintext credential files or metadata services.
function applyAwsSafetyEnvironment(env: NodeJS.ProcessEnv, provider: ProviderConfig): void {
  if (provider.http?.auth.type !== 'aws-sigv4') return;
  const emptyCredentialsFile = path.join(env.HOME ?? '', '.aws', 'empty-credentials');
  const parent = path.dirname(emptyCredentialsFile);
  if (!existsSync(parent)) mkdirSync(parent, { mode: 0o700, recursive: true });
  writeFileSync(emptyCredentialsFile, '', { mode: 0o600 });
  env.AWS_EC2_METADATA_DISABLED = 'true';
  env.AWS_SHARED_CREDENTIALS_FILE = emptyCredentialsFile;
}

// Extracts token-like values from captured JSON and text session files for output redaction.
function sessionSecrets(session: SessionBundle | undefined): string[] {
  if (!session) return [];
  return session.files.flatMap((file) => {
    const buffer = Buffer.from(file.contents, 'base64');
    if (buffer.includes(0)) return [];
    const text = buffer.toString('utf8');
    try {
      return collectSensitiveStrings(JSON.parse(text));
    } catch {
      const values = [...text.matchAll(/(?:token|secret|password|key)\s*[:=]\s*["']?([^\s"']{8,})/giu)]
        .map((match) => match[1])
        .filter((value): value is string => Boolean(value));
      return values;
    }
  });
}
