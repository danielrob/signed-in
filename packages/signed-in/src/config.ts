import { createHash } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import {
  LEGACY_SIGNED_IN_SCHEMA_VERSION,
  SIGNED_IN_SCHEMA_VERSION,
  type LegacySignedInProjectConfig,
  type ProjectServiceBinding,
  type ServiceCatalog,
  type ServiceConfig,
  type SignedInProjectConfig,
  type MachineState,
  type ProviderConfig,
} from './types.js';

const projectIdPattern = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const providerIdPattern = /^[a-z0-9][a-z0-9-]{0,62}$/u;
export const accountNamePattern = /^[a-z0-9][a-z0-9-]{0,31}$/u;
export const reservedAccountNames: ReadonlySet<string> = new Set(['all', 'default', 'list', 'new', 'none']);

// Keeps aliases safe for CLI grammar, project config, and future collection subcommands.
export function isSafeAccountName(value: string): boolean {
  return accountNamePattern.test(value) && !reservedAccountNames.has(value);
}

// Loads a project declaration without trusting it; sealing into the vault is a separate daemon action.
export function loadProjectConfig(configPath: string): SignedInProjectConfig {
  const absolutePath = path.resolve(configPath);
  const parsed = JSON.parse(readFileSync(absolutePath, 'utf8')) as unknown;
  return validateProjectConfig(parsed, absolutePath);
}

// Rejects unsafe or ambiguous declarations before they can become a trusted gateway snapshot.
export function validateProjectConfig(value: unknown, source = 'config'): SignedInProjectConfig {
  if (!isRecord(value)) throw new Error(`${source}: expected a JSON object`);
  if (value.schemaVersion === LEGACY_SIGNED_IN_SCHEMA_VERSION) return upgradeLegacyProjectConfig(value, source);
  if (value.schemaVersion !== SIGNED_IN_SCHEMA_VERSION) throw new Error(`${source}: schemaVersion must be 1 or 2`);
  if (!isRecord(value.project)) throw new Error(`${source}: project is required`);
  const projectId = requireString(value.project.id, `${source}: project.id`);
  const projectName = requireString(value.project.name, `${source}: project.name`);
  if (!projectIdPattern.test(projectId)) throw new Error(`${source}: project.id is not a safe slug`);
  if (!isRecord(value.services) || Object.keys(value.services).length === 0) {
    throw new Error(`${source}: at least one service binding is required`);
  }
  for (const [serviceId, binding] of Object.entries(value.services)) {
    if (!providerIdPattern.test(serviceId)) throw new Error(`${source}: invalid service id '${serviceId}'`);
    validateProjectBinding(serviceId, binding, source);
  }
  const extensions = value.providers === undefined ? {} : value.providers;
  if (!isRecord(extensions)) throw new Error(`${source}: providers must be an object when present`);
  for (const [providerId, providerValue] of Object.entries(extensions)) {
    if (!providerIdPattern.test(providerId)) throw new Error(`${source}: invalid provider id '${providerId}'`);
    validateService(providerId, providerValue, source);
  }
  validatePolicies(value.policies, source);

  return {
    ...(typeof value.environment === 'string' ? { environment: value.environment } : {}),
    ...(Array.isArray(value.policies) ? { policies: value.policies as SignedInProjectConfig['policies'] } : {}),
    project: { id: projectId, name: projectName },
    providers: extensions as Record<string, ServiceConfig>,
    schemaVersion: SIGNED_IN_SCHEMA_VERSION,
    services: value.services as Record<string, ProjectServiceBinding>,
  };
}

// Validates the packaged service catalog once so login can trust its interaction and credential metadata.
export function validateServiceCatalog(value: unknown, source = 'catalog'): ServiceCatalog {
  if (!isRecord(value) || value.schemaVersion !== 1 || !isRecord(value.services)) {
    throw new Error(`${source}: expected schemaVersion 1 and a services object`);
  }
  for (const [serviceId, service] of Object.entries(value.services)) {
    if (!providerIdPattern.test(serviceId)) throw new Error(`${source}: invalid service id '${serviceId}'`);
    validateService(serviceId, service, source);
    if (!isRecord(service) || service.ping === undefined) throw new Error(`${source}: ${serviceId}.ping is required`);
  }
  return value as unknown as ServiceCatalog;
}

// Hashes canonicalized declarations so edited repo files cannot silently change trusted behavior.
export function fingerprintProjectConfig(config: SignedInProjectConfig): string {
  return createHash('sha256').update(stableStringify(config)).digest('hex');
}

// Loads only non-secret discovery metadata; the daemon independently obtains the trusted snapshot.
export function loadMachineState(statePath: string): MachineState {
  if (!existsSync(statePath)) return { projects: {}, schemaVersion: SIGNED_IN_SCHEMA_VERSION };
  const parsed = JSON.parse(readFileSync(statePath, 'utf8')) as unknown;
  if (!isRecord(parsed) || (parsed.schemaVersion !== LEGACY_SIGNED_IN_SCHEMA_VERSION && parsed.schemaVersion !== SIGNED_IN_SCHEMA_VERSION) || !isRecord(parsed.projects)) {
    throw new Error(`Invalid signed-in state file: ${statePath}`);
  }
  return parsed as unknown as MachineState;
}

// Writes discovery metadata atomically enough for one user while keeping it unreadable to other accounts.
export function saveMachineState(statePath: string, state: MachineState): void {
  const temporaryPath = `${statePath}.${process.pid}.tmp`;
  writeFileSync(temporaryPath, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporaryPath, statePath);
}

// Finds the nearest repo declaration for pleasant zero-flag use inside a configured project.
export function discoverProjectConfig(startDirectory: string): string | undefined {
  let current = path.resolve(startDirectory);
  while (true) {
    const candidate = path.join(current, 'signed-in.config.json');
    if (existsSync(candidate)) return candidate;
    const parent = path.dirname(current);
    if (parent === current) return undefined;
    current = parent;
  }
}

// Chooses the registered project whose root most specifically contains the current working directory.
export function selectRegisteredProject(state: MachineState, cwd: string): string | undefined {
  const normalizedCwd = path.resolve(cwd);
  const matches = Object.values(state.projects)
    .flatMap((project) => project.roots.map((root) => ({ project, root: path.resolve(root) })))
    .filter(({ root }) => normalizedCwd === root || normalizedCwd.startsWith(`${root}${path.sep}`))
    .sort((left, right) => right.root.length - left.root.length);
  if (matches[0]) return matches[0].project.id;
  return state.schemaVersion === LEGACY_SIGNED_IN_SCHEMA_VERSION
    ? (state as MachineState & { activeProject?: string }).activeProject
    : undefined;
}

// Converts one legacy project into bindings plus catalog-compatible extensions without touching credentials.
function upgradeLegacyProjectConfig(value: Record<string, unknown>, source: string): SignedInProjectConfig {
  if (!isRecord(value.project)) throw new Error(`${source}: project is required`);
  const projectId = requireString(value.project.id, `${source}: project.id`);
  const projectName = requireString(value.project.name, `${source}: project.name`);
  if (!projectIdPattern.test(projectId)) throw new Error(`${source}: project.id is not a safe slug`);
  if (!isRecord(value.providers) || Object.keys(value.providers).length === 0) {
    throw new Error(`${source}: at least one provider is required`);
  }
  const providers: Record<string, ServiceConfig> = {};
  const services: Record<string, ProjectServiceBinding> = {};
  for (const [providerId, providerValue] of Object.entries(value.providers)) {
    if (!providerIdPattern.test(providerId)) throw new Error(`${source}: invalid provider id '${providerId}'`);
    validateProvider(providerId, providerValue, source);
    const provider = providerValue as unknown as ProviderConfig;
    providers[providerId] = {
      ...provider,
      signIn: provider.session?.loginArgs.length ? 'interactive' : 'manual',
    };
    services[providerId] = { account: 'default', required: provider.required !== false };
  }
  validatePolicies(value.policies, source);
  return {
    ...(typeof value.environment === 'string' ? { environment: value.environment } : {}),
    ...(Array.isArray(value.policies) ? { policies: value.policies as SignedInProjectConfig['policies'] } : {}),
    project: { id: projectId, name: projectName },
    providers,
    schemaVersion: SIGNED_IN_SCHEMA_VERSION,
    services,
  };
}

// Keeps project binding shorthand strict so alias resolution never has to interpret arbitrary values.
function validateProjectBinding(serviceId: string, value: unknown, source: string): void {
  if (value === true) return;
  if (typeof value === 'string') {
    if (!isSafeAccountName(value)) throw new Error(`${source}: ${serviceId} account is not a safe slug`);
    return;
  }
  if (!isRecord(value)) throw new Error(`${source}: services.${serviceId} must be true, an alias, or an object`);
  if (value.alias !== undefined && value.account !== undefined) throw new Error(`${source}: services.${serviceId} cannot set both alias and legacy account`);
  if (value.alias !== undefined && (typeof value.alias !== 'string' || !isSafeAccountName(value.alias))) {
    throw new Error(`${source}: services.${serviceId}.alias is not a safe slug`);
  }
  if (value.account !== undefined && (typeof value.account !== 'string' || !isSafeAccountName(value.account))) {
    throw new Error(`${source}: services.${serviceId}.account is not a safe legacy alias`);
  }
  if (value.expectedIdentity !== undefined) {
    const identity = requireString(value.expectedIdentity, `${source}: services.${serviceId}.expectedIdentity`);
    if (identity.length > 160 || /[\r\n]/u.test(identity)) throw new Error(`${source}: services.${serviceId}.expectedIdentity is too long or contains a newline`);
  }
  if (value.target !== undefined) {
    const target = requireString(value.target, `${source}: services.${serviceId}.target`);
    if (target.length > 256 || /[\r\n\0]/u.test(target)) throw new Error(`${source}: services.${serviceId}.target is unsafe`);
  }
  if (value.checks !== undefined) validateProjectChecks(serviceId, value.checks, source);
  validateOptionalBoolean(value.required, `${source}: services.${serviceId}.required`);
}

// Restricts project capability probes to named, read-only paths on the provider's sealed HTTP origin.
function validateProjectChecks(serviceId: string, value: unknown, source: string): void {
  if (!Array.isArray(value) || value.length === 0) throw new Error(`${source}: services.${serviceId}.checks must contain at least one check`);
  const ids = new Set<string>();
  for (const [index, check] of value.entries()) {
    if (!isRecord(check)) throw new Error(`${source}: services.${serviceId}.checks[${index}] must be an object`);
    const id = requireString(check.id, `${source}: services.${serviceId}.checks[${index}].id`);
    if (!providerIdPattern.test(id) || ids.has(id)) throw new Error(`${source}: services.${serviceId}.checks contains an invalid or duplicate id '${id}'`);
    ids.add(id);
    if (check.label !== undefined) requireString(check.label, `${source}: services.${serviceId}.checks[${index}].label`);
    if (check.method !== undefined && !['GET', 'HEAD'].includes(String(check.method))) {
      throw new Error(`${source}: services.${serviceId}.checks[${index}].method must be GET or HEAD`);
    }
    const requestPath = requireString(check.path, `${source}: services.${serviceId}.checks[${index}].path`);
    if (!requestPath.startsWith('/') || requestPath.startsWith('//') || /[\r\n]/u.test(requestPath)) {
      throw new Error(`${source}: services.${serviceId}.checks[${index}].path must be a relative HTTP path`);
    }
  }
}

// Canonicalizes object keys recursively so fingerprints do not depend on formatting or insertion order.
function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

// Validates the credential boundary and ensures each provider exposes at least one useful surface.
function validateProvider(providerId: string, value: unknown, source: string): void {
  if (!isRecord(value)) throw new Error(`${source}: provider '${providerId}' must be an object`);
  requireString(value.label, `${source}: providers.${providerId}.label`);
  if (!value.cli && !value.http) {
    throw new Error(`${source}: provider '${providerId}' needs cli or http configuration`);
  }
  if (value.category !== undefined && !['operator', 'runtime'].includes(String(value.category))) {
    throw new Error(`${source}: ${providerId}.category must be operator or runtime`);
  }
  if (value.credentialMode !== undefined && !['independent', 'shared'].includes(String(value.credentialMode))) {
    throw new Error(`${source}: ${providerId}.credentialMode must be independent or shared`);
  }
  validateOptionalBoolean(value.required, `${source}: ${providerId}.required`);
  if (value.cli) validateCli(providerId, value.cli, source);
  if (value.http) validateHttp(providerId, value.http, source);
  const fieldIds = new Set<string>();
  if (value.credentials !== undefined) {
    if (!Array.isArray(value.credentials)) throw new Error(`${source}: ${providerId}.credentials must be an array`);
    for (const [index, field] of value.credentials.entries()) {
      if (!isRecord(field)) throw new Error(`${source}: ${providerId}.credentials[${index}] must be an object`);
      const fieldId = requireString(field.id, `${source}: ${providerId}.credentials[${index}].id`);
      requireString(field.label, `${source}: ${providerId}.credentials[${index}].label`);
      if (field.input !== undefined && !['file', 'secret', 'text'].includes(String(field.input))) {
        throw new Error(`${source}: ${providerId}.credentials[${index}].input must be file, secret, or text`);
      }
      validateOptionalBoolean(field.portable, `${source}: ${providerId}.credentials[${index}].portable`);
      validateOptionalBoolean(field.required, `${source}: ${providerId}.credentials[${index}].required`);
      validateOptionalBoolean(field.secret, `${source}: ${providerId}.credentials[${index}].secret`);
      if (field.prefixes !== undefined && (!isStringArray(field.prefixes) || field.prefixes.length === 0 || field.prefixes.some((prefix) => prefix.length === 0))) {
        throw new Error(`${source}: ${providerId}.credentials[${index}].prefixes must contain non-empty strings`);
      }
      if (fieldIds.has(fieldId)) throw new Error(`${source}: duplicate credential field '${fieldId}'`);
      fieldIds.add(fieldId);
    }
  }
  if (value.session !== undefined) {
    if (!value.cli) throw new Error(`${source}: ${providerId}.session requires a CLI`);
    validateSession(providerId, value.session, source, fieldIds);
  }
  if (isRecord(value.cli)) {
    if (value.cli.delivery === 'proxy' && !value.http) throw new Error(`${source}: ${providerId} proxy delivery requires HTTP config`);
    if (value.cli.delivery === 'session' && !value.session) throw new Error(`${source}: ${providerId} session delivery requires session config`);
  }
  if (isRecord(value.http)) validateHttpCredentialReferences(providerId, value.http, source, fieldIds);
  if (value.policy !== undefined) validateProviderPolicy(providerId, value.policy, source);
}

// Adds catalog interaction guarantees on top of the existing credential and execution validation.
function validateService(providerId: string, value: unknown, source: string): void {
  validateProvider(providerId, value, source);
  if (!isRecord(value) || !['interactive', 'manual'].includes(String(value.signIn))) {
    throw new Error(`${source}: ${providerId}.signIn must be interactive or manual`);
  }
  if (value.installHint !== undefined) requireString(value.installHint, `${source}: ${providerId}.installHint`);
  if (value.existingLogin !== undefined) validateExistingLogin(providerId, value.existingLogin, source);
  if (value.identityArgs !== undefined && !isStringArray(value.identityArgs)) {
    throw new Error(`${source}: ${providerId}.identityArgs must be an array of strings`);
  }
  if (value.identityJsonField !== undefined) {
    requireString(value.identityJsonField, `${source}: ${providerId}.identityJsonField`);
    if (!value.identityArgs) throw new Error(`${source}: ${providerId}.identityJsonField requires identityArgs`);
  }
  if (value.ping !== undefined) validateServicePing(providerId, value.ping, value, source);
  if (value.target !== undefined) validateServiceTarget(providerId, value.target, value, source);
  if (value.signIn === 'interactive' && (!isRecord(value.session) || !isStringArray(value.session.loginArgs) || value.session.loginArgs.length === 0)) {
    throw new Error(`${source}: interactive ${providerId} needs non-empty session.loginArgs`);
  }
  if (value.signIn === 'manual') {
    const fields = Array.isArray(value.credentials) ? value.credentials : [];
    const hasHelp = fields.some((field) => isRecord(field) && typeof field.helpUrl === 'string' && field.helpUrl.length > 0);
    if (!hasHelp) throw new Error(`${source}: manual ${providerId} needs a credential helpUrl`);
  }
}

// Allows a project target to reach a CLI through one catalog-owned environment variable only.
function validateServiceTarget(providerId: string, value: unknown, service: Record<string, unknown>, source: string): void {
  if (!isRecord(value)) throw new Error(`${source}: ${providerId}.target must be an object`);
  if (!service.cli) throw new Error(`${source}: ${providerId}.target requires CLI configuration`);
  const env = requireString(value.env, `${source}: ${providerId}.target.env`);
  requireString(value.label, `${source}: ${providerId}.target.label`);
  if (!/^[A-Z][A-Z0-9_]*$/u.test(env)) throw new Error(`${source}: ${providerId}.target.env must be an uppercase environment variable`);
  if (/^(?:BASH_ENV|DYLD_.*|LD_.*|NODE_OPTIONS|PERL5OPT|PYTHONPATH|RUBYOPT)$/u.test(env)) {
    throw new Error(`${source}: ${providerId}.target.env cannot inject runtime loader options`);
  }
  const credentialEnvironment = Array.isArray(service.credentials)
    ? service.credentials.filter(isRecord).map((field) => field.env)
    : [];
  if (credentialEnvironment.includes(env)) throw new Error(`${source}: ${providerId}.target.env cannot replace credential delivery`);
  if (value.pattern !== undefined) {
    const pattern = requireString(value.pattern, `${source}: ${providerId}.target.pattern`);
    try { new RegExp(pattern, 'u'); } catch { throw new Error(`${source}: ${providerId}.target.pattern must be a valid regular expression`); }
  }
}

// Keeps local-login adoption limited to catalog-owned argv and explicit paths beneath the operator's home.
function validateExistingLogin(providerId: string, value: unknown, source: string): void {
  if (!isRecord(value)) throw new Error(`${source}: ${providerId}.existingLogin must be an object`);
  requireString(value.source, `${source}: ${providerId}.existingLogin.source`);
  if (!isStringArray(value.detectArgs) || value.detectArgs.length === 0 || value.detectArgs.some((argument) => argument.length === 0)) {
    throw new Error(`${source}: ${providerId}.existingLogin.detectArgs must contain non-empty strings`);
  }
  if (value.identityArgs !== undefined && (!isStringArray(value.identityArgs) || value.identityArgs.length === 0)) {
    throw new Error(`${source}: ${providerId}.existingLogin.identityArgs must contain non-empty strings`);
  }
  if (value.identityPattern !== undefined) {
    const pattern = requireString(value.identityPattern, `${source}: ${providerId}.existingLogin.identityPattern`);
    try { new RegExp(pattern, 'u'); } catch { throw new Error(`${source}: ${providerId}.existingLogin.identityPattern must be a valid regular expression`); }
  }
  if (value.identityStream !== undefined && !['stderr', 'stdout'].includes(String(value.identityStream))) {
    throw new Error(`${source}: ${providerId}.existingLogin.identityStream must be stderr or stdout`);
  }
  if (value.paths === undefined) return;
  if (!Array.isArray(value.paths) || value.paths.length === 0) {
    throw new Error(`${source}: ${providerId}.existingLogin.paths must contain at least one path`);
  }
  for (const [index, entry] of value.paths.entries()) {
    if (!isRecord(entry)) throw new Error(`${source}: ${providerId}.existingLogin.paths[${index}] must be an object`);
    validateHomeRelativePath(requireString(entry.source, `${source}: ${providerId}.existingLogin.paths[${index}].source`), `${source}: ${providerId}.existingLogin.paths[${index}].source`);
    validateHomeRelativePath(requireString(entry.target, `${source}: ${providerId}.existingLogin.paths[${index}].target`), `${source}: ${providerId}.existingLogin.paths[${index}].target`);
    if (entry.platform !== undefined && !['darwin', 'linux', 'win32'].includes(String(entry.platform))) {
      throw new Error(`${source}: ${providerId}.existingLogin.paths[${index}].platform is unsupported`);
    }
  }
}

// Rejects absolute and parent-traversing adoption paths before any daemon filesystem access is possible.
function validateHomeRelativePath(value: string, label: string): void {
  const normalized = value.replaceAll('\\', '/').replace(/^\.\//u, '');
  if (!normalized || normalized.startsWith('/') || /^[A-Za-z]:\//u.test(normalized) || normalized.split('/').includes('..')) {
    throw new Error(`${label} must stay beneath the home directory`);
  }
}

// Keeps health probes read-only, argv-only, and bound to a surface the service actually exposes.
function validateServicePing(providerId: string, value: unknown, service: Record<string, unknown>, source: string): void {
  if (!isRecord(value)) throw new Error(`${source}: ${providerId}.ping must be an object`);
  if (value.interface === 'http') {
    if (!service.http) throw new Error(`${source}: ${providerId}.ping requires HTTP configuration`);
    if (value.method !== undefined && !['GET', 'HEAD'].includes(String(value.method))) {
      throw new Error(`${source}: ${providerId}.ping HTTP method must be GET or HEAD`);
    }
    requireString(value.path, `${source}: ${providerId}.ping.path`);
    return;
  }
  if (value.interface === 'native') {
    if (!service.cli) throw new Error(`${source}: ${providerId}.ping requires CLI configuration`);
    if (!isStringArray(value.args) || value.args.length === 0 || value.args.some((argument) => argument.length === 0)) {
      throw new Error(`${source}: ${providerId}.ping.args must contain non-empty strings`);
    }
    return;
  }
  throw new Error(`${source}: ${providerId}.ping.interface must be http or native`);
}

// Blocks shell commands at the schema boundary; signed-in may launch only one declared executable with argv.
function validateCli(providerId: string, value: unknown, source: string): void {
  if (!isRecord(value)) throw new Error(`${source}: ${providerId}.cli must be an object`);
  if (value.adapter !== undefined) {
    if (value.adapter !== 'gws-gmail') throw new Error(`${source}: ${providerId}.cli.adapter is unsupported`);
    if (value.delivery !== 'session' || (value.prefixArgs !== undefined && (!isStringArray(value.prefixArgs) || value.prefixArgs.length > 0))) {
      throw new Error(`${source}: ${providerId}.cli.adapter requires session delivery without prefixArgs`);
    }
  }
  const command = requireString(value.command, `${source}: ${providerId}.cli.command`);
  const forbidden = new Set([
    'bash', 'bun', 'cmd', 'deno', 'env', 'node', 'npm', 'npx', 'pnpm', 'powershell', 'pwsh',
    'python', 'python3', 'sh', 'yarn', 'zsh',
  ]);
  if (forbidden.has(path.basename(command).toLowerCase())) {
    throw new Error(`${source}: ${providerId}.cli.command cannot be a general-purpose interpreter or package runner`);
  }
  if (value.prefixArgs !== undefined && !isStringArray(value.prefixArgs)) {
    throw new Error(`${source}: ${providerId}.cli.prefixArgs must be an array of strings`);
  }
  for (const key of ['clearEnv', 'verifyArgs']) {
    if (value[key] !== undefined && !isStringArray(value[key])) {
      throw new Error(`${source}: ${providerId}.cli.${key} must be an array of strings`);
    }
  }
  if (value.delivery !== undefined && !['environment', 'none', 'proxy', 'session'].includes(String(value.delivery))) {
    throw new Error(`${source}: ${providerId}.cli.delivery is unsupported`);
  }
  if (value.proxySocket !== undefined) {
    if (!isRecord(value.proxySocket)) throw new Error(`${source}: ${providerId}.cli.proxySocket must be an object`);
    const configPath = requireString(value.proxySocket.configPath, `${source}: ${providerId}.cli.proxySocket.configPath`);
    const configTemplate = requireString(value.proxySocket.configTemplate, `${source}: ${providerId}.cli.proxySocket.configTemplate`);
    const normalizedPath = configPath.replaceAll('\\', '/');
    if (path.posix.isAbsolute(normalizedPath) || normalizedPath.split('/').includes('..')) {
      throw new Error(`${source}: ${providerId}.cli.proxySocket.configPath must stay inside the command sandbox`);
    }
    if (!configTemplate.includes('{socket}') || /\{(?!socket\})[^}]+\}/u.test(configTemplate)) {
      throw new Error(`${source}: ${providerId}.cli.proxySocket.configTemplate must contain only the {socket} placeholder`);
    }
    if (value.delivery !== 'proxy') {
      throw new Error(`${source}: ${providerId}.cli.proxySocket requires proxy delivery`);
    }
  }
}

// Ensures authenticated HTTP calls can only target a fixed HTTPS origin and supported injection scheme.
function validateHttp(providerId: string, value: unknown, source: string): void {
  if (!isRecord(value)) throw new Error(`${source}: ${providerId}.http must be an object`);
  const baseUrl = new URL(requireString(value.baseUrl, `${source}: ${providerId}.http.baseUrl`));
  if (baseUrl.protocol !== 'https:' && baseUrl.hostname !== '127.0.0.1' && baseUrl.hostname !== 'localhost') {
    throw new Error(`${source}: ${providerId}.http.baseUrl must use HTTPS`);
  }
  if (!isRecord(value.auth)) throw new Error(`${source}: ${providerId}.http.auth is required`);
  const authTypes = new Set(['apple-connect-jwt', 'aws-sigv4', 'basic', 'bearer', 'header', 'none']);
  if (!authTypes.has(String(value.auth.type))) throw new Error(`${source}: unsupported ${providerId} HTTP auth type`);
  if (value.auth.type === 'basic') {
    const hasPasswordField = typeof value.auth.passwordField === 'string' && value.auth.passwordField.length > 0;
    const hasEmptyPassword = value.auth.password === 'empty';
    if (hasPasswordField === hasEmptyPassword) {
      throw new Error(`${source}: ${providerId} Basic auth needs exactly one of passwordField or password: empty`);
    }
  }
  validateHttpAuthFields(providerId, value.auth, source);
  for (const key of ['allowHosts', 'egressHosts']) {
    if (value[key] !== undefined && !isStringArray(value[key])) {
      throw new Error(`${source}: ${providerId}.http.${key} must be an array of strings`);
    }
  }
  if (value.defaultHeaders !== undefined) {
    const headers = requireStringRecord(value.defaultHeaders, `${source}: ${providerId}.http.defaultHeaders`);
    const forbiddenHeaders = /^(?:authorization|cookie|proxy-authorization|x-api-key|x-auth-token)$/iu;
    if (Object.keys(headers).some((name) => forbiddenHeaders.test(name))) {
      throw new Error(`${source}: ${providerId}.http.defaultHeaders cannot contain authentication`);
    }
  }
}

// Verifies session subprocesses remain argv-only and have explicit resolver output formats.
function validateSession(providerId: string, value: unknown, source: string, fieldIds: Set<string>): void {
  if (!isRecord(value) || !isStringArray(value.loginArgs)) {
    throw new Error(`${source}: ${providerId}.session.loginArgs must be an array of strings`);
  }
  for (const key of ['remoteLoginArgs', 'verifyArgs']) {
    if (value[key] !== undefined && !isStringArray(value[key])) {
      throw new Error(`${source}: ${providerId}.session.${key} must be an array of strings`);
    }
  }
  validateOptionalBoolean(value.retain, `${source}: ${providerId}.session.retain`);
  if (value.captureLimitBytes !== undefined && (!Number.isSafeInteger(value.captureLimitBytes) || Number(value.captureLimitBytes) <= 0)) {
    throw new Error(`${source}: ${providerId}.session.captureLimitBytes must be a positive integer`);
  }
  if (value.env !== undefined) {
    const environment = requireStringRecord(value.env, `${source}: ${providerId}.session.env`);
    const dangerousEnvironment = /^(?:BASH_ENV|DYLD_.*|LD_.*|NODE_OPTIONS|PERL5OPT|PYTHONPATH|RUBYOPT)$/iu;
    if (Object.keys(environment).some((name) => dangerousEnvironment.test(name))) {
      throw new Error(`${source}: ${providerId}.session.env cannot inject runtime loader options`);
    }
  }
  if (value.resolvers !== undefined) {
    if (!Array.isArray(value.resolvers)) throw new Error(`${source}: ${providerId}.session.resolvers must be an array`);
    for (const resolver of value.resolvers) {
      if (!isRecord(resolver) || !isStringArray(resolver.args)) {
        throw new Error(`${source}: ${providerId} session resolver needs string args`);
      }
      if (!['aws-process-json', 'json', 'json-file-key', 'text'].includes(String(resolver.format))) {
        throw new Error(`${source}: ${providerId} session resolver has an unsupported format`);
      }
      validateOptionalBoolean(resolver.persist, `${source}: ${providerId} resolver.persist`);
      if (resolver.targetField !== undefined) requireDeclaredField(providerId, resolver.targetField, source, fieldIds);
      if (resolver.fieldMap !== undefined) {
        const fieldMap = requireStringRecord(resolver.fieldMap, `${source}: ${providerId} resolver.fieldMap`);
        for (const field of Object.keys(fieldMap)) requireDeclaredField(providerId, field, source, fieldIds);
      }
    }
  }
}

// Validates each auth variant's required field names before checking those names against credential declarations.
function validateHttpAuthFields(providerId: string, auth: Record<string, unknown>, source: string): void {
  const fieldsByType: Record<string, string[]> = {
    'apple-connect-jwt': ['issuerField', 'keyIdField', 'privateKeyField'],
    'aws-sigv4': ['accessKeyField', 'secretKeyField'],
    basic: ['usernameField'],
    bearer: ['field'],
    header: ['field', 'header'],
    none: [],
  };
  for (const field of fieldsByType[String(auth.type)] ?? []) requireString(auth[field], `${source}: ${providerId}.http.auth.${field}`);
  if (auth.type === 'aws-sigv4' && auth.sessionTokenField !== undefined) {
    requireString(auth.sessionTokenField, `${source}: ${providerId}.http.auth.sessionTokenField`);
  }
  if (auth.type === 'aws-sigv4') {
    if (auth.defaultRegion !== undefined) requireString(auth.defaultRegion, `${source}: ${providerId}.http.auth.defaultRegion`);
    if (auth.defaultService !== undefined) requireString(auth.defaultService, `${source}: ${providerId}.http.auth.defaultService`);
  }
}

// Prevents auth adapters from depending on misspelled or undeclared credential fields.
function validateHttpCredentialReferences(
  providerId: string,
  http: Record<string, unknown>,
  source: string,
  fieldIds: Set<string>,
): void {
  const auth = http.auth;
  if (!isRecord(auth)) return;
  const referenceNames = ['accessKeyField', 'field', 'issuerField', 'keyIdField', 'passwordField', 'privateKeyField', 'secretKeyField', 'sessionTokenField', 'usernameField'];
  for (const name of referenceNames) {
    if (auth[name] !== undefined) requireDeclaredField(providerId, auth[name], source, fieldIds);
  }
}

// Validates provider-local command classifiers as arrays of argv token arrays.
function validateProviderPolicy(providerId: string, value: unknown, source: string): void {
  if (!isRecord(value)) throw new Error(`${source}: ${providerId}.policy must be an object`);
  for (const key of ['confirmCliPatterns', 'denyCliPatterns', 'destructiveCliPatterns', 'mutatingCliPatterns']) {
    if (value[key] !== undefined && !isStringMatrix(value[key])) {
      throw new Error(`${source}: ${providerId}.policy.${key} must be an array of string arrays`);
    }
  }
}

// Validates declarative policy rules before they are sealed into the trusted snapshot.
function validatePolicies(value: unknown, source: string): void {
  if (value === undefined) return;
  if (!Array.isArray(value)) throw new Error(`${source}: policies must be an array`);
  for (const [index, policy] of value.entries()) {
    if (!isRecord(policy)) throw new Error(`${source}: policies[${index}] must be an object`);
    requireString(policy.id, `${source}: policies[${index}].id`);
    requireString(policy.reason, `${source}: policies[${index}].reason`);
    if (!['allow', 'confirm', 'deny'].includes(String(policy.effect))) {
      throw new Error(`${source}: policies[${index}].effect must be allow, confirm, or deny`);
    }
    for (const key of ['commandPattern', 'environments', 'interfaces', 'methods', 'operationClasses', 'providers']) {
      if (policy[key] !== undefined && !isStringArray(policy[key])) {
        throw new Error(`${source}: policies[${index}].${key} must be an array of strings`);
      }
    }
    if (policy.pathPattern !== undefined) requireString(policy.pathPattern, `${source}: policies[${index}].pathPattern`);
  }
}

// Rejects credential references that would otherwise leave a provider permanently incomplete at runtime.
function requireDeclaredField(providerId: string, value: unknown, source: string, fieldIds: Set<string>): void {
  const field = requireString(value, `${source}: ${providerId} credential reference`);
  if (!fieldIds.has(field)) throw new Error(`${source}: ${providerId} references undeclared credential field '${field}'`);
}

// Narrows optional booleans without treating strings such as "false" as enabled.
function validateOptionalBoolean(value: unknown, label: string): void {
  if (value !== undefined && typeof value !== 'boolean') throw new Error(`${label} must be a boolean`);
}

// Reuses one strict map guard for headers, environment overrides, and resolver field maps.
function requireStringRecord(value: unknown, label: string): Record<string, string> {
  if (!isRecord(value) || !Object.values(value).every((item) => typeof item === 'string')) {
    throw new Error(`${label} must be an object containing only strings`);
  }
  return value as Record<string, string>;
}

// Validates nested argv patterns without accepting empty non-array values.
function isStringMatrix(value: unknown): value is string[][] {
  return Array.isArray(value) && value.every(isStringArray);
}

// Narrows arbitrary JSON objects without weakening strict validation through `any`.
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// Gives validation errors the exact missing field instead of a downstream type failure.
function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${label} must be a non-empty string`);
  return value;
}

// Reuses one precise guard for all argv-like config arrays.
function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}
