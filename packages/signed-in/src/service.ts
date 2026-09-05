import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, realpathSync, statSync, unlinkSync } from 'node:fs';
import { delimiter, dirname, isAbsolute, resolve } from 'node:path';
import process from 'node:process';

import { AuditLog } from './audit.js';
import { allocateAlias, deriveConnectionAlias, normalizeAlias, type AliasSource } from './aliases.js';
import { bootstrapAwsCredentials, type AwsBootstrapResult } from './aws-bootstrap.js';
import { builtInServices } from './catalog.js';
import {
  fingerprintProjectConfig,
  isSafeAccountName,
  loadMachineState,
  reservedAccountNames,
  saveMachineState,
  validateProjectConfig,
} from './config.js';
import { credentialValidationMessage } from './credential-validation.js';
import { performGatewayRequest, type GatewayResponse } from './http-gateway.js';
import {
  createMachineIdentity,
  decodePublicIdentity,
  decryptPairingEnvelope,
  encryptPairingPayload,
  publicMachineIdentity,
} from './pairing.js';
import { evaluatePolicy } from './policy.js';
import { redactText } from './redact.js';
import {
  adoptExistingProviderLogin,
  discoverExistingProviderLogin,
  refreshProviderCredentials,
  ProviderAuthenticationError,
  runProviderCommand,
  runProviderLogin,
  runPrivateProviderJson,
  type CommandCallbacks,
  type CommandResult,
} from './runner.js';
import {
  accountCredentialStoreKey,
  accountSessionStoreKey,
  binaryPinStoreKey,
  connectionCredentialStoreKey,
  connectionMigrationStoreKey,
  connectionSessionStoreKey,
  credentialStoreKey,
  machineAccountsStoreKey,
  machineIdentityStoreKey,
  migrationStoreKey,
  sessionStoreKey,
  trustedProjectStoreKey,
  type SecretStore,
} from './secrets.js';
import type {
  BinaryPin,
  ConnectionMetadata,
  CredentialRecord,
  ConnectionOrigin,
  ExistingLoginDiscovery,
  HttpRequestParams,
  LegacySignedInProjectConfig,
  LegacyMachineAccounts,
  MachineConnections,
  MachineIdentityPrivate,
  MachineIdentityPublic,
  MachineState,
  NativeRunParams,
  PairingEnvelope,
  PairingPayload,
  PolicyDecision,
  ProjectServiceVerificationResult,
  ProjectServiceBinding,
  ProjectVerificationResult,
  ProviderConfig,
  ProviderStatus,
  ServiceConfig,
  ServicePingResult,
  ServiceStatus,
  SessionBundle,
  SignedInProjectConfig,
  TrustedProject,
} from './types.js';
import type { SignedInPaths } from './paths.js';

export class SignedInError extends Error {
  readonly code: string;
  readonly details?: unknown;

  // Carries stable machine-readable failure codes across IPC without serializing stack traces.
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = 'SignedInError';
    this.code = code;
    this.details = details;
  }
}

// Owns every operation that may read credentials so IPC handlers never manipulate secret material directly.
export class SignedInService {
  readonly #audit: AuditLog;
  readonly #connectionOperations = new Map<string, Promise<void>>();
  readonly #paths: SignedInPaths;
  readonly #store: SecretStore;

  // Wires the encrypted store, machine connection registry, and audit log into one daemon-owned boundary.
  constructor(store: SecretStore, paths: SignedInPaths) {
    this.#store = store;
    this.#paths = paths;
    this.#audit = new AuditLog(paths.auditFile);
    this.#migrateLegacyState();
    this.#migrateConnections();
    // Removes the obsolete memorized-approval record as soon as the phrase-free runtime opens a vault.
    this.#store.delete('machine/operator/verifier');
  }

  // Seals only project bindings and restrictive policy; credentials remain machine connection records.
  trustProject(input: {
    approved?: boolean;
    config: unknown;
    configPath: string;
    roots: string[];
  }): { binaries: string[]; fingerprint: string; missing: Array<{ alias?: string; service: string }>; projectId: string; services: string[] } {
    const config = normalizeProjectConfig(validateProjectConfig(input.config, input.configPath));
    const services = Object.keys(config.services).map((serviceId) => {
      const service = config.providers[serviceId] ?? builtInServices[serviceId];
      if (!service) throw new SignedInError('UNKNOWN_SERVICE', `Unknown service '${serviceId}' in ${input.configPath}`);
      const binding = projectBinding(config.services[serviceId])!;
      if (binding.target) {
        if (!service.target) throw new SignedInError('TARGET_UNSUPPORTED', `${service.label} does not define a project target`);
        if (service.target.pattern && !new RegExp(service.target.pattern, 'u').test(binding.target)) {
          throw new SignedInError('INVALID_TARGET', `${service.label} ${service.target.label} '${binding.target}' is invalid`);
        }
      }
      if (binding.checks.length > 0 && !service.http) {
        throw new SignedInError('CHECKS_UNSUPPORTED', `${service.label} cannot run HTTP capability checks`);
      }
      return { id: serviceId, service };
    });
    if (!input.approved) throw new SignedInError('APPROVAL_REQUIRED', `Trust reviewed bindings and policy for ${config.project.name}?`);
    const pins = services.flatMap(({ id, service }) => {
      if (!service.cli) return [];
      const executable = resolveExecutable(service.cli.command);
      return executable ? [{ id, pin: binaryPin(executable) }] : [];
    });
    const fingerprint = fingerprintProjectConfig(config);
    const key = trustedProjectStoreKey(config.project.id);
    const trustedAt = new Date().toISOString();
    const { connections, pendingConnections } = this.#resolveTrustedConnections(config);
    this.#store.set<TrustedProject>(key, { config, connections, fingerprint, ...(pendingConnections.length > 0 ? { pendingConnections } : {}), trustedAt });
    const state = this.#machineStateV2();
    state.projects[config.project.id] = {
      configPath: resolve(input.configPath),
      fingerprint,
      id: config.project.id,
      name: config.project.name,
      roots: [...new Set(input.roots.map((root) => resolve(root)))],
      trustedAt,
    };
    const identity = this.#ensureMachineIdentity();
    state.identity = publicMachineIdentity(identity);
    this.#syncStateAccounts(state);
    this.#saveState(state);
    for (const { id, pin } of pins) this.#store.set(binaryPinStoreKey(id), pin);
    this.#auditControl('project.trust', 'credential-control', 'allow', 'Reviewed project bindings and policy sealed.', undefined, config.project.id);
    const missing = pendingConnections.map((service) => {
      const account = projectBinding(config.services[service])?.account;
      return { ...(account ? { alias: account } : {}), service };
    });
    return { binaries: pins.map(({ id }) => id), fingerprint, missing, projectId: config.project.id, services: Object.keys(config.services) };
  }

  // Returns safe project roots and connection aliases while trusted config remains in the encrypted vault.
  listProjects(): MachineState {
    return this.#machineStateV2();
  }

  // Returns one sealed non-secret project declaration for status, prompts, and drift inspection.
  describeProject(projectId: string): TrustedProject {
    return this.#trustedProject(projectId);
  }

  // Removes one project's bindings and roots without touching any machine-wide connection.
  forgetProject(input: { approved?: boolean; projectId: string }): { projectId: string } {
    if (!input.approved) throw new SignedInError('APPROVAL_REQUIRED', `Forget project '${input.projectId}'?`);
    const state = this.#machineStateV2();
    if (!state.projects[input.projectId]) throw new SignedInError('PROJECT_NOT_TRUSTED', `Project '${input.projectId}' is not trusted`);
    this.#store.delete(trustedProjectStoreKey(input.projectId));
    delete state.projects[input.projectId];
    this.#saveState(state);
    this.#auditControl('project.forget', 'credential-control', 'allow', 'Project bindings removed; machine connections retained.', undefined, input.projectId);
    return { projectId: input.projectId };
  }

  // Reports every catalog service and its connection aliases without returning any credential value.
  serviceStatuses(projectId?: string): ServiceStatus[] {
    const project = projectId ? this.#trustedProject(projectId) : undefined;
    const index = this.#accounts();
    const serviceIds = new Set([
      ...Object.keys(builtInServices),
      ...Object.keys(project?.config.providers ?? {}),
      ...Object.keys(index.services),
      ...Object.keys(project?.config.services ?? {}),
    ]);
    return [...serviceIds].sort().map((serviceId) => {
      const service = this.#service(serviceId, project);
      const binding = project ? projectBinding(project.config.services[serviceId]) : undefined;
      const serviceConnections = index.services[serviceId];
      const accounts = Object.entries(serviceConnections?.connections ?? {})
        .sort(([, left], [, right]) => left.alias.localeCompare(right.alias))
        .map(([connectionId]) => this.#providerStatus(serviceId, connectionId, service, binding?.required ?? false));
      const projectConnectionId = project?.connections?.[serviceId];
      const projectConnectionPending = Boolean(project?.pendingConnections?.includes(serviceId));
      const projectConnectionMissing = Boolean(projectConnectionId && !serviceConnections?.connections[projectConnectionId]);
      const projectAlias = projectConnectionId
        ? serviceConnections?.connections[projectConnectionId]?.alias ?? binding?.account
        : binding?.account === 'default'
          ? serviceConnections?.connections[serviceConnections.default ?? '']?.alias
          : binding?.account;
      const selectedConnection = projectAlias
        ? accounts.find((account) => account.account === projectAlias)
        : accounts.find((account) => account.default) ?? accounts[0];
      const connectionNeedingAttention = selectedConnection && !selectedConnection.ready ? selectedConnection : undefined;
      const state = projectConnectionMissing || projectConnectionPending || connectionNeedingAttention
        ? 'needs-you'
        : accounts.length > 0 ? 'connected' : 'not-connected';
      const remedy = projectConnectionPending
        ? `signed-in login ${serviceId}${binding?.account ? `@${binding.account}` : ''}`
        : projectConnectionMissing
        ? 'signed-in project trust'
        : connectionNeedingAttention?.remedy ?? (accounts.length === 0 ? `signed-in login ${serviceId}` : undefined);
      return {
        accounts,
        ...(service.description ? { description: service.description } : {}),
        ...(service.docsUrl ? { docsUrl: service.docsUrl } : {}),
        id: serviceId,
        label: service.label,
        ...(projectAlias ? { projectAccount: projectAlias } : {}),
        ...(projectConnectionMissing ? { projectConnectionMissing: true } : {}),
        ...(projectConnectionPending ? { projectConnectionPending: true } : {}),
        required: binding?.required ?? false,
        ...(remedy ? { remedy } : {}),
        signIn: service.signIn,
        state,
      };
    });
  }

  // Stores only declared fields while assigning new authority an immutable connection and human alias.
  putCredentials(input: {
    account?: string;
    approved?: boolean;
    fields: Record<string, string>;
    projectId?: string;
    providerId: string;
    replace?: boolean;
  }): ProviderStatus {
    if (input.account && input.account !== 'default') validateAccountName(input.account);
    const project = input.projectId ? this.#trustedProject(input.projectId) : undefined;
    const service = this.#service(input.providerId, project);
    const existing = input.account ? this.#connectionByAlias(input.providerId, input.account) : undefined;
    if (existing && !input.approved) throw new SignedInError('APPROVAL_REQUIRED', `Replace ${input.providerId}@${existing.alias}?`);
    const allowed = new Set((service.credentials ?? []).map((field) => field.id));
    for (const [field, value] of Object.entries(input.fields)) {
      if (!allowed.has(field)) throw new SignedInError('INVALID_FIELD', `Unknown credential field '${field}'`);
      if (!value) throw new SignedInError('INVALID_FIELD', `Credential field '${field}' is empty`);
      const fieldConfig = service.credentials?.find((candidate) => candidate.id === field);
      const validation = fieldConfig ? credentialValidationMessage(fieldConfig, value) : undefined;
      if (validation) throw new SignedInError('INVALID_FIELD', validation);
    }
    const connectionId = existing?.id ?? createConnectionId();
    const key = connectionCredentialStoreKey(input.providerId, connectionId);
    const existingRecord = this.#store.get<CredentialRecord>(key);
    const record = {
      fields: input.replace ? { ...input.fields } : { ...(existingRecord?.fields ?? {}), ...input.fields },
      updatedAt: new Date().toISOString(),
    };
    this.#store.set<CredentialRecord>(key, record);
    const requestedAlias = input.account && input.account !== 'default' ? input.account : undefined;
    const alias = existing?.metadata.alias ?? (requestedAlias ? this.#allocateOperatorAlias(input.providerId, requestedAlias) : deriveConnectionAlias(undefined, 'primary', this.#connectionAliases(input.providerId)).alias);
    const aliasSource = existing?.metadata.aliasSource ?? (requestedAlias ? 'operator' : 'fallback');
    this.#upsertConnection(input.providerId, connectionId, alias, aliasSource, record, this.#store.has(connectionSessionStoreKey(input.providerId, connectionId)), { kind: 'manual' });
    this.#auditControl('credential.put', 'credential-control', 'allow', `Credential fields updated for ${input.providerId}; values omitted.`, input.providerId, input.projectId);
    return this.#providerStatus(input.providerId, connectionId, service, false);
  }

  // Runs provider-owned sign-in and derives a durable alias only after provider identity becomes available.
  async loginProvider(input: {
    account?: string;
    alias?: string;
    approved?: boolean;
    callbacks: CommandCallbacks;
    cwd: string;
    projectId?: string;
    providerId: string;
    remote?: boolean;
  }): Promise<{ exitCode: number; pinned?: BinaryPin; status?: ProviderStatus }> {
    if (input.account && input.account !== 'default') validateAccountName(input.account);
    const project = input.projectId ? this.#trustedProject(input.projectId) : undefined;
    const service = this.#service(input.providerId, project);
    if (!service.session || service.signIn !== 'interactive') {
      throw new SignedInError('MANUAL_CREDENTIALS_REQUIRED', `${service.label} uses guided credential entry`);
    }
    const existing = input.account ? this.#connectionByAlias(input.providerId, input.account) : undefined;
    if (existing && !input.approved) throw new SignedInError('APPROVAL_REQUIRED', `Reconnect ${input.providerId}@${existing.alias}?`);
    const connectionId = existing?.id ?? createConnectionId();
    return this.#withConnectionOperation(input.providerId, connectionId, async () => {
    const prepared = this.#prepareExecutable(input.providerId, service);
    const credentialKey = connectionCredentialStoreKey(input.providerId, connectionId);
    const sessionKey = connectionSessionStoreKey(input.providerId, connectionId);
    const credentials = this.#store.get<CredentialRecord>(credentialKey) ?? emptyCredentialRecord();
    const session = this.#store.get<SessionBundle>(sessionKey);
    const receipt = this.#audit.start({
      cwd: input.cwd,
      interface: 'control',
      path: 'provider.login',
      ...(input.projectId ? { projectId: input.projectId } : {}),
      providerId: input.providerId,
    }, allowDecision('mutation', 'Provider login explicitly initiated.'));
    try {
      let result = await runProviderLogin({
        callbacks: input.callbacks,
        credentials,
        cwd: input.cwd,
        provider: prepared.provider,
        remote: input.remote ?? false,
        ...(session ? { session } : {}),
      });
      let awsBootstrap: AwsBootstrapResult | undefined;
      if (result.exitCode === 0 && input.providerId === 'aws') {
        input.callbacks.onStdout(Buffer.from('\nSecuring durable AWS access…\n'));
        awsBootstrap = await bootstrapAwsCredentials({
          browserCredentials: result.credentials,
          ...(credentials.fields.accessKeyId ? { previousCredentials: credentials } : {}),
          run: (args, privateCredentials) => runPrivateProviderJson({
            args,
            callbacks: input.callbacks,
            credentials: privateCredentials,
            cwd: input.cwd,
            provider: prepared.provider,
          }),
        });
        result = { clearSession: true, credentials: awsBootstrap.credentials, exitCode: result.exitCode };
        input.callbacks.onStdout(Buffer.from(`Durable AWS access is ready as ${awsBootstrap.userName}.\n`));
      }
      if (result.exitCode === 0) {
        if (prepared.pin && !prepared.wasPinned) this.#store.set(binaryPinStoreKey(input.providerId), prepared.pin);
        this.#persistCommandResult(input.providerId, connectionId, result);
        const identity = awsBootstrap?.identity ?? await this.#captureIdentity(input.providerId, connectionId, service, project, input.cwd, input.callbacks);
        const occupiedAliases = this.#connectionAliases(input.providerId).filter((alias) => alias !== existing?.metadata.alias);
        const derived = awsBootstrap
          ? { alias: allocateAlias(awsBootstrap.alias, occupiedAliases), source: 'identity' as const }
          : deriveConnectionAlias(identity, input.alias ?? 'primary', occupiedAliases);
        const upgradeFallbackAlias = Boolean(existing && existing.metadata.aliasSource === 'fallback' && awsBootstrap);
        const alias = upgradeFallbackAlias
          ? derived.alias
          : existing?.metadata.alias
            ?? (input.account && input.account !== 'default' ? this.#allocateOperatorAlias(input.providerId, input.account) : derived.alias);
        const aliasSource = upgradeFallbackAlias
          ? derived.source
          : existing?.metadata.aliasSource
            ?? (input.account && input.account !== 'default' ? 'operator' : derived.source);
        const stored = this.#store.get<CredentialRecord>(credentialKey) ?? emptyCredentialRecord();
        this.#upsertConnection(input.providerId, connectionId, alias, aliasSource, stored, this.#store.has(sessionKey), { kind: 'provider-login' });
        if (identity) this.#setConnectionIdentity(input.providerId, connectionId, identity);
      }
      this.#audit.complete(receipt, { exitCode: result.exitCode, status: result.exitCode === 0 ? 'completed' : 'failed' });
      return {
        exitCode: result.exitCode,
        ...(!prepared.wasPinned && result.exitCode === 0 && prepared.pin ? { pinned: prepared.pin } : {}),
        ...(result.exitCode === 0 ? { status: this.#providerStatus(input.providerId, connectionId, service, false) } : {}),
      };
    } catch (error) {
      this.#audit.complete(receipt, { errorCode: errorCode(error), status: 'failed' });
      if (error instanceof ProviderAuthenticationError) {
        if (existing) this.#markConnectionNeedsLogin(input.providerId, connectionId);
        throw providerAuthenticationRequired(service, input.providerId, existing?.metadata.alias ?? input.account);
      }
      throw error;
    }
    });
  }

  // Reports only whether a catalog-supported local CLI login is usable and the non-secret identity it represents.
  async discoverExistingLogin(input: { cwd: string; projectId?: string; providerId: string }): Promise<ExistingLoginDiscovery> {
    const project = input.projectId ? this.#trustedProject(input.projectId) : undefined;
    const service = this.#service(input.providerId, project);
    if (!service.existingLogin || !service.cli || !resolveExecutable(service.cli.command)) {
      return { available: false, source: service.existingLogin?.source ?? service.cli?.command ?? service.label };
    }
    const prepared = this.#prepareExecutable(input.providerId, service);
    return discoverExistingProviderLogin({ cwd: input.cwd, provider: prepared.provider });
  }

  // Adopts a selected local CLI login into encrypted daemon authority, verifies it, and rolls back every local write on failure.
  async adoptExistingLogin(input: {
    account?: string;
    alias?: string;
    approved?: boolean;
    callbacks: CommandCallbacks;
    cwd: string;
    projectId?: string;
    providerId: string;
  }): Promise<{ status: ProviderStatus }> {
    if (input.account && input.account !== 'default') validateAccountName(input.account);
    const project = input.projectId ? this.#trustedProject(input.projectId) : undefined;
    const service = this.#service(input.providerId, project);
    if (!service.existingLogin || !service.session || !service.cli) {
      throw new SignedInError('ADOPTION_UNAVAILABLE', `${service.label} cannot import an existing CLI login`);
    }
    if (!input.approved) throw new SignedInError('APPROVAL_REQUIRED', `Use the existing ${service.existingLogin.source} login for ${service.label}?`);
    const existing = input.account ? this.#connectionByAlias(input.providerId, input.account) : undefined;
    const connectionId = existing?.id ?? createConnectionId();
    const credentialKey = connectionCredentialStoreKey(input.providerId, connectionId);
    const sessionKey = connectionSessionStoreKey(input.providerId, connectionId);
    const pinKey = binaryPinStoreKey(input.providerId);
    const previousCredentials = this.#store.get<CredentialRecord>(credentialKey);
    const previousSession = this.#store.get<SessionBundle>(sessionKey);
    const previousPin = this.#store.get<BinaryPin>(pinKey);
    const previousAccounts = structuredClone(this.#accounts());
    const prepared = this.#prepareExecutable(input.providerId, service);
    const receipt = this.#audit.start({
      cwd: input.cwd,
      interface: 'control',
      path: 'provider.adopt',
      ...(input.projectId ? { projectId: input.projectId } : {}),
      providerId: input.providerId,
    }, allowDecision('mutation', 'Existing local CLI login explicitly selected.'));
    try {
      let result = await adoptExistingProviderLogin({ cwd: input.cwd, provider: prepared.provider });
      let awsBootstrap: AwsBootstrapResult | undefined;
      if (input.providerId === 'aws') {
        input.callbacks.onStdout(Buffer.from('\nSecuring durable AWS access…\n'));
        awsBootstrap = await bootstrapAwsCredentials({
          browserCredentials: result.credentials,
          ...(previousCredentials?.fields.accessKeyId ? { previousCredentials } : {}),
          run: (args, privateCredentials) => runPrivateProviderJson({
            args,
            callbacks: input.callbacks,
            credentials: privateCredentials,
            cwd: input.cwd,
            provider: prepared.provider,
          }),
        });
        result = { clearSession: true, credentials: awsBootstrap.credentials, exitCode: 0, identity: awsBootstrap.identity };
        input.callbacks.onStdout(Buffer.from(`Durable AWS access is ready as ${awsBootstrap.userName}.\n`));
      }
      if (prepared.pin && !prepared.wasPinned) this.#store.set(pinKey, prepared.pin);
      this.#persistCommandResult(input.providerId, connectionId, result);
      const identity = awsBootstrap?.identity ?? result.identity;
      const occupiedAliases = this.#connectionAliases(input.providerId).filter((alias) => alias !== existing?.metadata.alias);
      const derived = awsBootstrap
        ? { alias: allocateAlias(awsBootstrap.alias, occupiedAliases), source: 'identity' as const }
        : deriveConnectionAlias(identity, input.alias ?? 'primary', occupiedAliases);
      const upgradeFallbackAlias = Boolean(existing && existing.metadata.aliasSource === 'fallback' && identity);
      const alias = upgradeFallbackAlias
        ? derived.alias
        : existing?.metadata.alias
          ?? (input.account && input.account !== 'default' ? this.#allocateOperatorAlias(input.providerId, input.account) : derived.alias);
      const aliasSource = upgradeFallbackAlias
        ? derived.source
        : existing?.metadata.aliasSource
          ?? (input.account && input.account !== 'default' ? 'operator' : derived.source);
      const stored = this.#store.get<CredentialRecord>(credentialKey) ?? emptyCredentialRecord();
      this.#upsertConnection(input.providerId, connectionId, alias, aliasSource, stored, this.#store.has(sessionKey), {
        kind: 'adopted',
        source: service.existingLogin.source,
      });
      const protectedIdentity = await this.#captureIdentity(input.providerId, connectionId, service, project, input.cwd, input.callbacks);
      if (protectedIdentity ?? identity) this.#setConnectionIdentity(input.providerId, connectionId, protectedIdentity ?? identity!);
      await this.pingService({
        account: alias,
        cwd: input.cwd,
        ...(input.projectId ? { projectId: input.projectId } : {}),
        providerId: input.providerId,
      }, { onChild: input.callbacks.onChild });
      this.#audit.complete(receipt, { exitCode: 0, status: 'completed' });
      return { status: this.#providerStatus(input.providerId, connectionId, service, false) };
    } catch (error) {
      if (previousCredentials) this.#store.set(credentialKey, previousCredentials); else this.#store.delete(credentialKey);
      if (previousSession) this.#store.set(sessionKey, previousSession); else this.#store.delete(sessionKey);
      if (previousPin) this.#store.set(pinKey, previousPin); else this.#store.delete(pinKey);
      this.#saveAccounts(previousAccounts);
      this.#audit.complete(receipt, { errorCode: errorCode(error), status: 'failed' });
      if (error instanceof ProviderAuthenticationError) {
        throw new SignedInError('ADOPTION_FAILED', `The existing ${service.existingLogin.source} login could not be copied and verified`, {
          remedy: `signed-in login ${input.providerId}${input.account ? `@${input.account}` : ''}`,
        });
      }
      throw error;
    }
  }

  // Executes one service CLI after alias resolution, policy, binary pinning, isolation, and audit.
  async runNative(input: NativeRunParams, callbacks: CommandCallbacks): Promise<{ account: string; exitCode: number; receiptId: string }> {
    const project = input.projectId ? this.#trustedProject(input.projectId) : undefined;
    const service = this.#service(input.providerId, project);
    if (!service.cli) throw new SignedInError('NO_NATIVE_CLI', `${service.label} has no native CLI`);
    if (project && !this.#store.has(binaryPinStoreKey(input.providerId))) {
      throw new SignedInError('BINARY_NOT_APPROVED', `The ${service.cli.command} command was not installed when this project was approved`, {
        remedy: `signed-in trust ${input.providerId}`,
      });
    }
    const connection = this.#resolveConnection(input.providerId, input.account, project);
    const config = effectivePolicyConfig(input.providerId, service, project);
    const operation = {
      args: input.args,
      cwd: input.cwd,
      environment: project?.config.environment,
      interface: 'native' as const,
      ...(input.projectId ? { projectId: input.projectId } : {}),
      providerId: input.providerId,
    };
    const decision = evaluatePolicy(config, operation);
    assertPolicyDecision(decision, input.approved);
    return this.#withConnectionOperation(input.providerId, connection.id, async () => {
    const prepared = this.#prepareExecutable(input.providerId, service);
    const credentials = this.#store.get<CredentialRecord>(connectionCredentialStoreKey(input.providerId, connection.id)) ?? emptyCredentialRecord();
    const session = this.#store.get<SessionBundle>(connectionSessionStoreKey(input.providerId, connection.id));
    assertSurfaceReady(service, credentials, session, input.providerId, connection.alias, 'native');
    const receipt = this.#audit.start(operation, decision, Object.values(credentials.fields));
    try {
      const result = await runProviderCommand({
        args: input.args,
        callbacks,
        ...projectCommandEnvironment(service, projectBinding(project?.config.services[input.providerId])),
        config,
        credentials,
        cwd: input.cwd,
        provider: prepared.provider,
        providerId: input.providerId,
        ...(session ? { session } : {}),
      });
      if (prepared.pin && !prepared.wasPinned) this.#store.set(binaryPinStoreKey(input.providerId), prepared.pin);
      this.#persistCommandResult(input.providerId, connection.id, result);
      this.#audit.complete(receipt, { exitCode: result.exitCode, status: result.exitCode === 0 ? 'completed' : 'failed' });
      return { account: connection.alias, exitCode: result.exitCode, receiptId: receipt.id };
    } catch (error) {
      this.#audit.complete(receipt, { errorCode: errorCode(error), status: 'failed' });
      if (error instanceof ProviderAuthenticationError) {
        this.#markConnectionNeedsLogin(input.providerId, connection.id);
        throw providerAuthenticationRequired(service, input.providerId, connection.alias, 'credential-rejected');
      }
      throw error;
    }
    });
  }

  // Proves one stored connection against a catalog-owned read probe while discarding every provider response byte.
  async pingService(input: {
    account?: string;
    cwd: string;
    projectId?: string;
    providerId: string;
  }, callbacks: Pick<CommandCallbacks, 'onChild'> = {}, signal?: AbortSignal): Promise<ServicePingResult> {
    const project = input.projectId ? this.#trustedProject(input.projectId) : undefined;
    const service = this.#service(input.providerId, project);
    if (!service.ping) throw new SignedInError('PING_UNAVAILABLE', `${service.label} does not define an authentication probe`);
    const binding = projectBinding(project?.config.services[input.providerId]);
    const target = service.target ? { label: service.target.label, value: binding?.target ?? null } : undefined;
    const startedAt = Date.now();
    if (service.ping.interface === 'native') {
      const result = await this.runNative({
        ...(input.account ? { account: input.account } : {}),
        args: service.ping.args,
        cwd: input.cwd,
        ...(input.projectId ? { projectId: input.projectId } : {}),
        providerId: input.providerId,
      }, {
        ...(callbacks.onChild ? { onChild: callbacks.onChild } : {}),
        onStderr: () => undefined,
        onStdout: () => undefined,
      });
      if (result.exitCode !== 0) throw providerAuthenticationRequired(service, input.providerId, result.account);
      return {
        account: result.account,
        durationMs: Date.now() - startedAt,
        exitCode: result.exitCode,
        interface: 'native',
        ok: result.exitCode === 0,
        providerId: input.providerId,
        ...(target ? { target } : {}),
      };
    }
    const result = await this.request({
      ...(input.account ? { account: input.account } : {}),
      method: service.ping.method ?? 'GET',
      path: service.ping.path,
      ...(input.projectId ? { projectId: input.projectId } : {}),
      providerId: input.providerId,
    }, signal);
    return {
      account: result.account,
      durationMs: Date.now() - startedAt,
      interface: 'http',
      ok: result.response.status >= 200 && result.response.status < 300,
      providerId: input.providerId,
      status: result.response.status,
      ...(target ? { target } : {}),
    };
  }

  // Verifies a sealed project's identity, ordinary auth probe, and declared read capabilities without returning provider bodies.
  async verifyProject(input: {
    cwd: string;
    projectId: string;
    providerId?: string;
  }, callbacks: Pick<CommandCallbacks, 'onChild'> = {}, signal?: AbortSignal): Promise<ProjectVerificationResult> {
    const project = this.#trustedProject(input.projectId);
    const providerIds = input.providerId ? [input.providerId] : Object.keys(project.config.services);
    if (input.providerId && !project.config.services[input.providerId]) {
      throw new SignedInError('SERVICE_NOT_IN_PROJECT', `${input.providerId} is not configured for ${project.config.project.name}`);
    }
    const services: ProjectServiceVerificationResult[] = [];
    for (const providerId of providerIds) {
      const service = this.#service(providerId, project);
      const binding = projectBinding(project.config.services[providerId])!;
      const connection = this.#resolveConnection(providerId, undefined, project);
      const ping = await this.pingService({ cwd: input.cwd, projectId: input.projectId, providerId }, callbacks, signal);
      const checks = [];
      for (const check of binding.checks) {
        const startedAt = Date.now();
        const method = check.method ?? 'GET';
        const result = await this.request({ method, path: check.path, projectId: input.projectId, providerId }, signal);
        checks.push({
          durationMs: Date.now() - startedAt,
          id: check.id,
          label: check.label ?? check.id,
          method,
          ok: result.response.status >= 200 && result.response.status < 300,
          path: check.path,
          status: result.response.status,
        });
      }
      services.push({
        account: connection.alias,
        checks,
        ...(connection.metadata.identity ? { identity: connection.metadata.identity } : {}),
        ok: ping.ok && checks.every((check) => check.ok),
        ping,
        providerId,
        ...(ping.target ? { target: ping.target } : {}),
      });
    }
    return { ok: services.every((service) => service.ok), projectId: input.projectId, services };
  }

  // Calls one allowlisted service endpoint with daemon-side authentication and project policy when present.
  async request(input: HttpRequestParams, signal?: AbortSignal): Promise<{ account: string; receiptId: string; response: GatewayResponse }> {
    const project = input.projectId ? this.#trustedProject(input.projectId) : undefined;
    const service = this.#service(input.providerId, project);
    if (!service.http) throw new SignedInError('NO_HTTP_GATEWAY', `${service.label} has no HTTP gateway`);
    const gateway = service.http;
    const connection = this.#resolveConnection(input.providerId, input.account, project);
    const method = input.method.toUpperCase();
    const config = effectivePolicyConfig(input.providerId, service, project);
    const operation = {
      environment: project?.config.environment,
      interface: 'http' as const,
      method,
      path: input.path,
      ...(input.projectId ? { projectId: input.projectId } : {}),
      providerId: input.providerId,
    };
    const decision = evaluatePolicy(config, operation);
    assertPolicyDecision(decision, input.approved);
    return this.#withConnectionOperation(input.providerId, connection.id, async () => {
    const credentialKey = connectionCredentialStoreKey(input.providerId, connection.id);
    const sessionKey = connectionSessionStoreKey(input.providerId, connection.id);
    const storedCredentials = this.#store.get<CredentialRecord>(credentialKey) ?? emptyCredentialRecord();
    const storedSession = this.#store.get<SessionBundle>(sessionKey);
    assertSurfaceReady(service, storedCredentials, storedSession, input.providerId, connection.alias, 'http');
    const refreshExecutable = service.cli && service.session?.resolvers?.length
      ? this.#prepareExecutable(input.providerId, service)
      : undefined;
    const receipt = this.#audit.start(operation, decision, Object.values(storedCredentials.fields));
    try {
      const refreshed = await refreshProviderCredentials({
        credentials: storedCredentials,
        cwd: process.cwd(),
        provider: refreshExecutable?.provider ?? service,
        ...(storedSession ? { session: storedSession } : {}),
      });
      this.#store.set(credentialKey, refreshed.credentials);
      if (refreshed.session) this.#store.set(sessionKey, refreshed.session);
      this.#refreshConnection(input.providerId, connection.id, refreshed.credentials, Boolean(refreshed.session ?? storedSession));
      const secrets = Object.values(refreshed.credentials.fields);
      const body = Buffer.from(input.body ?? '', input.bodyEncoding === 'base64' ? 'base64' : 'utf8');
      const response = await performGatewayRequest({
        body,
        credentials: refreshed.credentials.fields,
        gateway,
        headers: input.headers ?? {},
        method,
        path: input.path,
        secrets,
        ...(signal ? { signal } : {}),
      });
      if (response.status === 401 && await this.#authenticationProbeRejects({
        credentials: refreshed.credentials.fields,
        gateway,
        originalMethod: method,
        originalPath: input.path,
        secrets,
        service,
        ...(signal ? { signal } : {}),
      })) {
        throw new ProviderAuthenticationError('Provider rejected the stored authentication');
      }
      if (refreshExecutable?.pin && !refreshExecutable.wasPinned) this.#store.set(binaryPinStoreKey(input.providerId), refreshExecutable.pin);
      this.#audit.complete(receipt, { status: 'completed' });
      return { account: connection.alias, receiptId: receipt.id, response };
    } catch (error) {
      this.#audit.complete(receipt, { errorCode: errorCode(error), status: 'failed' });
      if (error instanceof ProviderAuthenticationError) {
        this.#markConnectionNeedsLogin(input.providerId, connection.id);
        throw providerAuthenticationRequired(service, input.providerId, connection.alias, 'credential-rejected');
      }
      throw error;
    }
    });
  }

  // Returns the exact account-independent policy result plus the alias runtime resolution would use.
  explainPolicy(input: {
    account?: string;
    args?: string[];
    interface: 'http' | 'native';
    method?: string;
    path?: string;
    projectId?: string;
    providerId: string;
  }): PolicyDecision & { account?: string } {
    const project = input.projectId ? this.#trustedProject(input.projectId) : undefined;
    const service = this.#service(input.providerId, project);
    const decision = evaluatePolicy(effectivePolicyConfig(input.providerId, service, project), {
      ...(input.args ? { args: input.args } : {}),
      environment: project?.config.environment,
      interface: input.interface,
      ...(input.method ? { method: input.method } : {}),
      ...(input.path ? { path: input.path } : {}),
      ...(input.projectId ? { projectId: input.projectId } : {}),
      providerId: input.providerId,
    });
    try {
      return { ...decision, account: this.#resolveConnection(input.providerId, input.account, project).alias };
    } catch {
      return decision;
    }
  }

  // Removes one connection only after the caller records explicit interactive confirmation.
  logoutProvider(input: { account?: string; approved?: boolean; projectId?: string; providerId: string }): ServiceStatus {
    const project = input.projectId ? this.#trustedProject(input.projectId) : undefined;
    this.#service(input.providerId, project);
    const connection = this.#resolveConnectionForRemoval(input.providerId, input.account);
    if (!input.approved) throw new SignedInError('APPROVAL_REQUIRED', `Disconnect ${input.providerId}@${connection.alias} from this machine?`);
    this.#store.delete(connectionCredentialStoreKey(input.providerId, connection.id));
    this.#store.delete(connectionSessionStoreKey(input.providerId, connection.id));
    const index = this.#accounts();
    const serviceConnections = index.services[input.providerId];
    if (serviceConnections) {
      delete serviceConnections.connections[connection.id];
      const remaining = Object.keys(serviceConnections.connections);
      if (remaining.length === 0) delete index.services[input.providerId];
      else if (serviceConnections.default === connection.id || !serviceConnections.default) serviceConnections.default = remaining.length === 1 ? remaining[0] : undefined;
      this.#saveAccounts(index);
    }
    this.#auditControl('provider.logout', 'destructive', 'confirm', 'Service authentication removed from this machine.', input.providerId, input.projectId);
    return this.serviceStatuses(input.projectId).find((status) => status.id === input.providerId)!;
  }

  // Changes the machine default pointer without changing the selected connection's alias or storage identity.
  useAccount(input: { account: string; approved?: boolean; providerId: string }): { changed: boolean; previous?: string } {
    const index = this.#accounts();
    const connection = this.#connectionByAlias(input.providerId, input.account);
    if (!connection) throw accountMissingError(input.providerId, input.account, this.#connectionAliases(input.providerId));
    const serviceConnections = index.services[input.providerId]!;
    if (serviceConnections.default === connection.id) return { changed: false, previous: connection.alias };
    if (!input.approved) throw new SignedInError('APPROVAL_REQUIRED', `Use ${input.providerId}@${connection.alias} by default?`);
    const previous = serviceConnections.default ? serviceConnections.connections[serviceConnections.default]?.alias : undefined;
    serviceConnections.default = connection.id;
    this.#saveAccounts(index);
    this.#auditControl('account.use', 'credential-control', 'allow', `Machine default changed for ${input.providerId}.`, input.providerId);
    return { changed: true, ...(previous ? { previous } : {}) };
  }

  // Renames only the human alias while immutable connection records and sealed project targets stay stable.
  renameAccount(input: { account: string; approved?: boolean; newName: string; preview?: boolean; providerId: string }): { projects: Array<{ configPath: string; id: string; name: string }> } {
    validateAccountName(input.account);
    validateAccountName(input.newName);
    const index = this.#accounts();
    const connection = this.#connectionByAlias(input.providerId, input.account);
    if (!connection) throw accountMissingError(input.providerId, input.account, this.#connectionAliases(input.providerId));
    if (this.#connectionByAlias(input.providerId, input.newName)) {
      throw new SignedInError('ACCOUNT_EXISTS', `Cannot rename ${input.providerId}@${input.account} to ${input.providerId}@${input.newName}; ${input.providerId}@${input.newName} already exists`, {
        remedy: `signed-in logout ${input.providerId}@${input.newName}`,
      });
    }
    const state = this.#machineStateV2();
    const projects = Object.values(state.projects).flatMap((registered) => {
      const binding = this.#trustedProject(registered.id).config.services[input.providerId];
      return bindingReferencesAccount(binding, input.account)
        ? [{ configPath: registered.configPath, id: registered.id, name: registered.name }]
        : [];
    });
    if (input.preview) return { projects };
    if (!input.approved) throw new SignedInError('APPROVAL_REQUIRED', `Rename ${input.providerId}@${connection.alias} to ${input.newName}?`);
    const metadata = index.services[input.providerId]!.connections[connection.id]!;
    metadata.alias = input.newName;
    metadata.aliasSource = 'operator';
    this.#saveAccounts(index, state);
    this.#auditControl('account.rename', 'credential-control', 'allow', `Connection alias renamed for ${input.providerId}.`, input.providerId);
    return { projects };
  }

  // Re-pins an installed service executable after a reviewed package-manager upgrade.
  trustService(input: { approved?: boolean; providerId: string }): BinaryPin {
    if (!input.approved) throw new SignedInError('APPROVAL_REQUIRED', `Trust the installed ${input.providerId} executable?`);
    const service = this.#service(input.providerId);
    if (!service.cli) throw new SignedInError('NO_NATIVE_CLI', `${service.label} has no native CLI`);
    const executable = resolveExecutable(service.cli.command);
    if (!executable) throw new SignedInError('CLI_NOT_INSTALLED', `${service.label} CLI is not installed`, { remedy: service.installHint });
    const pin = binaryPin(executable);
    this.#store.set(binaryPinStoreKey(input.providerId), pin);
    this.#auditControl('service.trust', 'credential-control', 'allow', `Executable re-pinned for ${input.providerId}.`, input.providerId);
    return pin;
  }

  // Returns a public pairing card while private machine keys remain sealed.
  publicIdentity(): MachineIdentityPublic {
    return publicMachineIdentity(this.#ensureMachineIdentity());
  }

  // Produces destination-bound ciphertext containing portable fields and aliases without exporting local connection IDs.
  exportPairing(input: { approved?: boolean; recipient: string }): { envelope: PairingEnvelope; skipped: PairingPayload['skipped'] } {
    if (!input.approved) throw new SignedInError('APPROVAL_REQUIRED', 'Share portable connections with this machine?');
    const recipient = decodePublicIdentity(input.recipient);
    const payload: PairingPayload = { credentials: [], skipped: [] };
    for (const [providerId, serviceConnections] of Object.entries(this.#accounts().services)) {
      const service = this.#service(providerId);
      for (const [connectionId, metadata] of Object.entries(serviceConnections.connections)) {
        if (service.credentialMode !== 'shared') {
          payload.skipped.push({ account: metadata.alias, providerId, reason: 'service requires independent machine authentication' });
          continue;
        }
        const stored = this.#store.get<CredentialRecord>(connectionCredentialStoreKey(providerId, connectionId));
        if (!stored) continue;
        const portable = new Set((service.credentials ?? []).filter((field) => field.portable === true).map((field) => field.id));
        const fields = Object.fromEntries(Object.entries(stored.fields).filter(([field]) => portable.has(field)));
        if (Object.keys(fields).length > 0) payload.credentials.push({ account: metadata.alias, fields, providerId, updatedAt: stored.updatedAt });
      }
    }
    const envelope = encryptPairingPayload(this.#ensureMachineIdentity(), recipient, payload);
    this.#auditControl('pair.export', 'credential-control', 'allow', `Portable connections encrypted for ${recipient.fingerprint}.`);
    return { envelope, skipped: payload.skipped };
  }

  // Imports destination-bound portable connections and refuses silent replacement.
  importPairing(input: { approved?: boolean; envelope: PairingEnvelope }): { imported: string[]; sender: MachineIdentityPublic; skipped: PairingPayload['skipped'] } {
    const payload = decryptPairingEnvelope(this.#ensureMachineIdentity(), input.envelope);
    const conflicts = payload.credentials.filter(({ account, providerId }) => Boolean(this.#connectionByAlias(providerId, account === 'default' ? 'primary' : account)));
    if (conflicts.length > 0 && !input.approved) {
      throw new SignedInError('APPROVAL_REQUIRED', `Pairing would replace: ${conflicts.map((item) => `${item.providerId}@${item.account}`).join(', ')}`);
    }
    const imported: string[] = [];
    for (const entry of payload.credentials) {
      const service = this.#service(entry.providerId);
      if (service.credentialMode !== 'shared') continue;
      const allowed = new Set((service.credentials ?? []).filter((field) => field.portable === true).map((field) => field.id));
      const fields = Object.fromEntries(Object.entries(entry.fields).filter(([field]) => allowed.has(field)));
      const record = { fields, importedFrom: input.envelope.sender.fingerprint, updatedAt: new Date().toISOString() };
      const requestedAlias = normalizeAlias(entry.account === 'default' ? 'primary' : entry.account) ?? 'primary';
      const existing = this.#connectionByAlias(entry.providerId, requestedAlias);
      const connectionId = existing?.id ?? createConnectionId();
      const alias = existing?.alias ?? allocateAlias(requestedAlias, this.#connectionAliases(entry.providerId));
      this.#store.set<CredentialRecord>(connectionCredentialStoreKey(entry.providerId, connectionId), record);
      this.#upsertConnection(entry.providerId, connectionId, alias, 'operator', record, false, { kind: 'paired', source: input.envelope.sender.fingerprint });
      imported.push(`${entry.providerId}@${alias}`);
    }
    this.#auditControl('pair.import', 'credential-control', 'allow', `Portable connections imported from ${input.envelope.sender.fingerprint}.`);
    return { imported, sender: input.envelope.sender, skipped: payload.skipped };
  }

  // Exercises the vault and reports project and executable drift without authenticating to a vendor.
  doctor(projectId?: string): {
    machine: MachineIdentityPublic;
    project?: { configDrift: boolean; id: string };
    services: Array<{
      configured: boolean;
      executable?: string;
      id: string;
      label: string;
      remedy?: string;
      state: 'changed' | 'not-installed' | 'not-used' | 'ready';
      trusted: boolean;
    }>;
    vault: 'ok';
  } {
    const probeKey = `doctor/${randomBytes(12).toString('hex')}`;
    const probeValue = randomBytes(24).toString('base64');
    try {
      this.#store.set(probeKey, { value: probeValue });
      if (this.#store.get<{ value: string }>(probeKey)?.value !== probeValue) throw new Error('Encrypted vault round trip failed');
    } finally {
      this.#store.delete(probeKey);
    }
    const project = projectId ? this.#trustedProject(projectId) : undefined;
    let configDrift = false;
    const registered = projectId ? this.#machineStateV2().projects[projectId] : undefined;
    if (project && registered?.configPath) {
      if (!existsSync(registered.configPath)) configDrift = true;
      else try {
        configDrift = fingerprintProjectConfig(normalizeProjectConfig(validateProjectConfig(JSON.parse(readFileSync(registered.configPath, 'utf8')), registered.configPath))) !== project.fingerprint;
      } catch {
        configDrift = true;
      }
    }
    const connections = this.#accounts();
    return {
      machine: this.publicIdentity(),
      ...(projectId ? { project: { configDrift, id: projectId } } : {}),
      services: Object.entries(builtInServices).flatMap(([id, service]) => {
        if (!service.cli) return [];
        const pin = this.#store.get<BinaryPin>(binaryPinStoreKey(id));
        const executable = resolveExecutable(service.cli.command);
        const configured = Object.keys(connections.services[id]?.connections ?? {}).length > 0;
        const trusted = Boolean(pin && binaryPinMatches(pin));
        const state = trusted
          ? 'ready'
          : pin
            ? executable ? 'changed' : 'not-installed'
            : configured && !executable ? 'not-installed' : 'not-used';
        const remedy = state === 'changed'
          ? `signed-in trust ${id}`
          : state === 'not-installed' ? service.installHint : undefined;
        return [{
          configured,
          ...(executable ? { executable } : {}),
          id,
          label: service.label,
          ...(remedy ? { remedy } : {}),
          state,
          trusted,
        }];
      }),
      vault: 'ok',
    };
  }

  // Reports executable availability from the daemon's trusted global search path rather than the caller's project shell.
  cliAvailability(input: { projectId?: string; providerId: string }): { available: boolean; command?: string; executable?: string } {
    const project = input.projectId ? this.#trustedProject(input.projectId) : undefined;
    const service = this.#service(input.providerId, project);
    if (!service.cli) return { available: false };
    const executable = resolveExecutable(service.cli.command);
    return {
      available: Boolean(executable),
      command: service.cli.command,
      ...(executable ? { executable } : {}),
    };
  }

  // Returns a one-time migration notice after v1 records have moved wholly inside the daemon.
  migrationNotice(): { migrated: boolean } {
    const journal = this.#store.get<MigrationJournal>(migrationStoreKey());
    if (!journal?.noticePending) return { migrated: false };
    journal.noticePending = false;
    this.#store.set(migrationStoreKey(), journal);
    return { migrated: true };
  }

  // Removes every known signed-in record after the frontend completes deliberate interactive confirmation.
  resetAll(): { accounts: number; projects: number; services: number } {
    const index = this.#accounts();
    const state = this.#machineStateV2();
    const accountCount = Object.values(index.services).reduce((total, item) => total + Object.keys(item.connections).length, 0);
    for (const [serviceId, item] of Object.entries(index.services)) {
      for (const connectionId of Object.keys(item.connections)) {
        this.#store.delete(connectionCredentialStoreKey(serviceId, connectionId));
        this.#store.delete(connectionSessionStoreKey(serviceId, connectionId));
      }
      this.#store.delete(binaryPinStoreKey(serviceId));
    }
    for (const project of Object.values(state.projects)) {
      const trusted = this.#store.get<{ config?: LegacySignedInProjectConfig | SignedInProjectConfig }>(trustedProjectStoreKey(project.id));
      for (const providerId of Object.keys(trusted?.config && 'providers' in trusted.config ? trusted.config.providers : {})) {
        this.#store.delete(credentialStoreKey(project.id, providerId));
        this.#store.delete(sessionStoreKey(project.id, providerId));
      }
      this.#store.delete(trustedProjectStoreKey(project.id));
    }
    for (const serviceId of Object.keys(builtInServices)) this.#store.delete(binaryPinStoreKey(serviceId));
    this.#store.delete(machineAccountsStoreKey());
    this.#store.delete(connectionMigrationStoreKey());
    this.#store.delete(machineIdentityStoreKey());
    this.#store.delete(migrationStoreKey());
    if (existsSync(this.#paths.auditFile)) unlinkSync(this.#paths.auditFile);
    if (existsSync(this.#paths.stateFile)) unlinkSync(this.#paths.stateFile);
    this.#store.reset();
    return { accounts: accountCount, projects: Object.keys(state.projects).length, services: Object.keys(index.services).length };
  }

  // Returns recent already-redacted JSONL receipts for local operational inspection.
  readAudit(limit = 50): unknown[] {
    if (!existsSync(this.#paths.auditFile)) return [];
    return readFileSync(this.#paths.auditFile, 'utf8').trim().split('\n').filter(Boolean)
      .slice(-Math.max(1, Math.min(limit, 1000))).map((line) => JSON.parse(line) as unknown);
  }

  // Resolves built-in catalog services first and project-local extension services only in their project.
  #service(serviceId: string, project?: TrustedProject): ServiceConfig {
    let service = builtInServices[serviceId] ?? project?.config.providers[serviceId];
    if (!service) {
      for (const registered of Object.values(this.#machineStateV2().projects)) {
        const candidate = this.#store.get<TrustedProject>(trustedProjectStoreKey(registered.id))?.config.providers[serviceId];
        if (candidate) { service = candidate; break; }
      }
    }
    if (!service) throw new SignedInError('UNKNOWN_SERVICE', `Unknown service '${serviceId}'`, { remedy: 'signed-in status --all' });
    return service;
  }

  // Resolves a human alias, including the compatibility keyword default, without exposing connection IDs to callers.
  #connectionByAlias(serviceId: string, alias: string): ConnectionRef | undefined {
    const serviceConnections = this.#accounts().services[serviceId];
    if (!serviceConnections) return undefined;
    if (alias === 'default' && serviceConnections.default) {
      const metadata = serviceConnections.connections[serviceConnections.default];
      if (metadata) return { alias: metadata.alias, id: serviceConnections.default, metadata };
    }
    const match = Object.entries(serviceConnections.connections).find(([, metadata]) => metadata.alias === alias);
    return match ? { alias: match[1].alias, id: match[0], metadata: match[1] } : undefined;
  }

  // Supplies stable human vocabulary for errors, completion, collision handling, and guided selection.
  #connectionAliases(serviceId: string): string[] {
    return Object.values(this.#accounts().services[serviceId]?.connections ?? {}).map((metadata) => metadata.alias).sort();
  }

  // Turns one explicit human label into a safe unique alias without allowing default to become stored identity.
  #allocateOperatorAlias(serviceId: string, value: string): string {
    const normalized = normalizeAlias(value);
    if (!normalized || normalized === 'default') {
      throw new SignedInError('INVALID_ACCOUNT', `'${value}' is not a valid connection alias`, {
        pattern: 'lowercase letters, digits, and hyphens; up to 32 characters',
      });
    }
    return allocateAlias(normalized, this.#connectionAliases(serviceId));
  }

  // Pins explicit project aliases to immutable connections while true and default continue following the machine default.
  #resolveTrustedConnections(config: SignedInProjectConfig): { connections: Record<string, string>; pendingConnections: string[] } {
    const pendingConnections: string[] = [];
    const connections = Object.fromEntries(Object.entries(config.services).flatMap(([serviceId, value]) => {
      const binding = projectBinding(value);
      if (!binding || (!binding.account && !binding.expectedIdentity)) return [];
      const connection = binding.account
        ? this.#connectionByAlias(serviceId, binding.account)
        : this.#connectionByAlias(serviceId, 'default') ?? this.#onlyConnection(serviceId);
      if (!connection) {
        pendingConnections.push(serviceId);
        return [];
      }
      this.#assertExpectedIdentity(serviceId, connection, binding, config.project.name);
      return [[serviceId, connection.id]];
    }));
    return { connections, pendingConnections };
  }

  // Resolves explicit alias, sealed project target, project alias, then machine default in stated precedence.
  #resolveConnection(serviceId: string, explicit: string | undefined, project?: TrustedProject): ConnectionRef {
    const serviceConnections = this.#accounts().services[serviceId];
    const aliases = this.#connectionAliases(serviceId);
    if (explicit) {
      const selected = this.#connectionByAlias(serviceId, explicit);
      if (!selected) throw accountMissingError(serviceId, explicit, aliases);
      return this.#assertProjectConnection(serviceId, selected, project);
    }
    if (project?.pendingConnections?.includes(serviceId)) {
      const binding = projectBinding(project.config.services[serviceId]);
      throw new SignedInError('AUTH_REQUIRED', `${project.config.project.name} needs ${serviceId}${binding?.account ? `@${binding.account}` : ''}, which is not signed in here`, {
        ...(binding?.account ? { account: binding.account } : {}),
        remedy: `signed-in login ${serviceId}${binding?.account ? `@${binding.account}` : ''}`,
        service: serviceId,
      });
    }
    const trustedConnectionId = project?.connections?.[serviceId];
    const trustedMetadata = trustedConnectionId ? serviceConnections?.connections[trustedConnectionId] : undefined;
    if (trustedConnectionId && trustedMetadata) return this.#assertProjectConnection(serviceId, { alias: trustedMetadata.alias, id: trustedConnectionId, metadata: trustedMetadata }, project);
    if (trustedConnectionId) {
      throw new SignedInError('PROJECT_CONNECTION_MISSING', `${project!.config.project.name}'s sealed ${serviceId} connection was removed from this machine`, {
        remedy: `signed-in project trust --config ${JSON.stringify(this.#machineStateV2().projects[project!.config.project.id]?.configPath ?? 'signed-in.config.json')}`,
        service: serviceId,
      });
    }
    const binding = projectBinding(project?.config.services[serviceId]);
    if (binding?.account && binding.account !== 'default') {
      const selected = this.#connectionByAlias(serviceId, binding.account);
      if (!selected) {
        throw new SignedInError('AUTH_REQUIRED', `${project!.config.project.name} uses ${serviceId}@${binding.account}, which is not signed in here`, {
          account: binding.account,
          remedy: `signed-in login ${serviceId}@${binding.account}`,
          service: serviceId,
        });
      }
      return this.#assertProjectConnection(serviceId, selected, project);
    }
    if (serviceConnections?.default && serviceConnections.connections[serviceConnections.default]) {
      const metadata = serviceConnections.connections[serviceConnections.default]!;
      return this.#assertProjectConnection(serviceId, { alias: metadata.alias, id: serviceConnections.default, metadata }, project);
    }
    const entries = Object.entries(serviceConnections?.connections ?? {});
    if (entries.length === 1) return this.#assertProjectConnection(serviceId, { alias: entries[0]![1].alias, id: entries[0]![0], metadata: entries[0]![1] }, project);
    if (entries.length > 1) {
      throw new SignedInError('ACCOUNT_AMBIGUOUS', `${serviceId} has multiple connections and no default here: ${aliases.join(', ')}`, {
        accounts: aliases,
        remedy: `signed-in use ${serviceId}@${aliases[0]}`,
        service: serviceId,
      });
    }
    throw new SignedInError('AUTH_REQUIRED', `${serviceId} is not signed in`, { remedy: `signed-in login ${serviceId}`, service: serviceId });
  }

  // Finds the sole connection only when no machine default exists, avoiding arbitrary selection among multiple authorities.
  #onlyConnection(serviceId: string): ConnectionRef | undefined {
    const entries = Object.entries(this.#accounts().services[serviceId]?.connections ?? {});
    return entries.length === 1 ? { alias: entries[0]![1].alias, id: entries[0]![0], metadata: entries[0]![1] } : undefined;
  }

  // Applies a project's exact identity expectation to every route, including explicit alias overrides.
  #assertProjectConnection(serviceId: string, connection: ConnectionRef, project?: TrustedProject): ConnectionRef {
    const binding = projectBinding(project?.config.services[serviceId]);
    if (binding && project) this.#assertExpectedIdentity(serviceId, connection, binding, project.config.project.name);
    return connection;
  }

  // Stops a wrong tenant or cloud account before any provider operation is allowed to run.
  #assertExpectedIdentity(
    serviceId: string,
    connection: ConnectionRef,
    binding: NonNullable<ReturnType<typeof projectBinding>>,
    projectName: string,
  ): void {
    if (!binding.expectedIdentity) return;
    if (connection.metadata.identity && identityContainsExpectedValue(connection.metadata.identity, binding.expectedIdentity)) return;
    const reason = connection.metadata.identity
      ? `is '${connection.metadata.identity}', not '${binding.expectedIdentity}'`
      : `has no verified identity; expected '${binding.expectedIdentity}'`;
    throw new SignedInError('AUTH_REQUIRED', `${projectName} requires ${serviceId} identity '${binding.expectedIdentity}', but ${serviceId}@${connection.alias} ${reason}`, {
      account: connection.alias,
      cause: 'identity-mismatch',
      expectedIdentity: binding.expectedIdentity,
      remedy: `signed-in login ${serviceId}@${connection.alias}`,
      service: serviceId,
    });
  }

  // Resolves a logout target without silently choosing among multiple connections.
  #resolveConnectionForRemoval(serviceId: string, explicit?: string): ConnectionRef {
    const aliases = this.#connectionAliases(serviceId);
    if (explicit) {
      const selected = this.#connectionByAlias(serviceId, explicit);
      if (!selected) throw accountMissingError(serviceId, explicit, aliases);
      return selected;
    }
    if (aliases.length === 1) return this.#connectionByAlias(serviceId, aliases[0]!)!;
    if (aliases.length === 0) throw accountMissingError(serviceId, 'default', aliases);
    throw new SignedInError('ACCOUNT_AMBIGUOUS', `${serviceId} has multiple connections: ${aliases.join(', ')}`, {
      remedy: `signed-in logout ${serviceId}@${aliases[0]}`,
    });
  }

  // Computes one connection row from record presence, declared auth requirements, and the current binary pin.
  #providerStatus(serviceId: string, connectionId: string, service: ServiceConfig, required: boolean): ProviderStatus {
    const credentialRecord = this.#store.get<CredentialRecord>(connectionCredentialStoreKey(serviceId, connectionId));
    const configuredFields = Object.keys(credentialRecord?.fields ?? {});
    const requiredFields = requiredCredentialFieldIds(service);
    const missingFields = [...requiredFields].filter((field) => !credentialRecord?.fields[field]);
    const invalidFields = (service.credentials ?? []).filter((field) => {
      const value = credentialRecord?.fields[field.id];
      return Boolean(value && credentialValidationMessage(field, value));
    }).map((field) => field.id);
    const sessionReady = this.#store.has(connectionSessionStoreKey(serviceId, connectionId));
    const delivery = service.cli?.delivery ?? (service.http ? 'proxy' : 'environment');
    const serviceConnections = this.#accounts().services[serviceId];
    const metadata = serviceConnections?.connections[connectionId];
    if (!metadata) throw new SignedInError('CONNECTION_MISSING', `Connection metadata is missing for ${serviceId}`);
    const needsLogin = metadata?.needsLogin === true;
    const executableReady = !service.cli || this.#binaryTrusted(serviceId) || (!this.#store.has(binaryPinStoreKey(serviceId)) && Boolean(resolveExecutable(service.cli.command)));
    const credentialReady = invalidFields.length === 0 && (missingFields.length === 0 || sessionCanResolveMissing(service, missingFields));
    const refreshReady = hasDurableAwsCredentials(service, credentialRecord)
      || !service.session?.resolvers?.some((resolver) => resolver.persist === false)
      || sessionReady;
    const nativeReady = !needsLogin && executableReady && Boolean(service.cli) && (delivery === 'none' || (delivery === 'session' ? sessionReady : credentialReady && refreshReady));
    const httpReady = !needsLogin && Boolean(service.http) && credentialReady && refreshReady;
    const ready = nativeReady || httpReady;
    const pin = service.cli ? this.#store.get<BinaryPin>(binaryPinStoreKey(serviceId)) : undefined;
    const state = ready
      ? 'connected'
      : needsLogin || (service.session && !sessionReady && !hasDurableAwsCredentials(service, credentialRecord))
        ? 'needs-sign-in'
        : missingFields.length > 0 || invalidFields.length > 0 ? 'needs-fields'
          : service.cli && pin && !binaryPinMatches(pin) ? 'needs-trust'
            : service.cli && !resolveExecutable(service.cli.command) ? 'needs-cli' : 'needs-sign-in';
    const remedy = state === 'needs-trust'
      ? `signed-in trust ${serviceId}`
      : state === 'connected' ? undefined : `signed-in login ${serviceId}@${metadata.alias}`;
    const nativeRemedy = service.cli && !nativeReady
      ? !resolveExecutable(service.cli.command)
        ? service.installHint ?? `signed-in login ${serviceId}@${metadata.alias}`
        : pin && !binaryPinMatches(pin)
          ? `signed-in trust ${serviceId}`
          : `signed-in login ${serviceId}@${metadata.alias}`
      : undefined;
    const httpRemedy = service.http && !httpReady ? `signed-in login ${serviceId}@${metadata.alias}` : undefined;
    return {
      account: metadata.alias,
      aliasSource: metadata.aliasSource,
      configuredFields,
      connectionId,
      default: serviceConnections?.default === connectionId,
      ...(service.description ? { description: service.description } : {}),
      httpReady,
      id: serviceId,
      ...(metadata?.identity ? { identity: metadata.identity } : {}),
      ...(invalidFields.length > 0 ? { invalidFields } : {}),
      isolation: delivery === 'proxy' ? 'brokered' : delivery === 'session' ? 'ephemeral-session' : delivery === 'environment' ? 'injected' : 'none',
      label: service.label,
      missingFields,
      nativeReady,
      ...(nativeRemedy ? { nativeRemedy } : {}),
      ...(metadata.origin ? { origin: metadata.origin } : {}),
      ready,
      ...(remedy ? { remedy } : {}),
      required,
      signIn: service.signIn,
      sessionReady,
      state,
      ...(httpRemedy ? { httpRemedy } : {}),
    };
  }

  // Loads a trusted snapshot by project ID and never consults its editable source file at runtime.
  #trustedProject(projectId: string): TrustedProject {
    const trusted = this.#store.get<TrustedProject>(trustedProjectStoreKey(projectId));
    if (!trusted) throw new SignedInError('PROJECT_NOT_TRUSTED', `Project '${projectId}' is not trusted`, { remedy: 'signed-in project trust' });
    return trusted;
  }

  // Resolves and verifies one executable pin, returning a provisional first pin for the caller to commit.
  #prepareExecutable(serviceId: string, service: ServiceConfig): { pin?: BinaryPin; provider: ServiceConfig; wasPinned: boolean } {
    if (!service.cli) return { provider: service, wasPinned: true };
    const existing = this.#store.get<BinaryPin>(binaryPinStoreKey(serviceId));
    if (existing) {
      if (!binaryPinMatches(existing)) {
        throw new SignedInError('BINARY_CHANGED', `${service.label} CLI changed since it was trusted`, { remedy: `signed-in trust ${serviceId}` });
      }
      return { provider: withBinaryPin(service, existing), wasPinned: true };
    }
    const executable = resolveExecutable(service.cli.command);
    if (!executable) throw new SignedInError('CLI_NOT_INSTALLED', `${service.label} CLI is not installed`, { remedy: service.installHint });
    const pin = binaryPin(executable);
    return { pin, provider: withBinaryPin(service, pin), wasPinned: false };
  }

  // Captures only a short non-secret identity label after login and discards every other provider byte.
  async #captureIdentity(
    serviceId: string,
    connectionId: string,
    service: ServiceConfig,
    project: TrustedProject | undefined,
    cwd: string,
    callbacks: CommandCallbacks,
  ): Promise<string | undefined> {
    if (!service.identityArgs || !service.cli) return undefined;
    const stdout: Buffer[] = [];
    try {
      const prepared = this.#prepareExecutable(serviceId, service);
      const credentials = this.#store.get<CredentialRecord>(connectionCredentialStoreKey(serviceId, connectionId)) ?? emptyCredentialRecord();
      const session = this.#store.get<SessionBundle>(connectionSessionStoreKey(serviceId, connectionId));
      const result = await runProviderCommand({
        args: service.identityArgs,
        callbacks: { onChild: callbacks.onChild, onStderr: () => undefined, onStdout: (chunk) => stdout.push(chunk) },
        config: effectivePolicyConfig(serviceId, service, project),
        credentials,
        cwd,
        provider: prepared.provider,
        providerId: serviceId,
        ...(session ? { session } : {}),
      });
      this.#persistCommandResult(serviceId, connectionId, result);
      if (result.exitCode !== 0) return undefined;
      const output = Buffer.concat(stdout).toString('utf8');
      const value: unknown = service.identityJsonField ? JSON.parse(output)?.[service.identityJsonField] : output;
      const identity = typeof value === 'string' ? value.trim().replace(/\s+/gu, ' ').slice(0, 160) : '';
      return identity || undefined;
    } catch {
      return undefined;
    }
  }

  // Serializes one connection's rotating refresh state while leaving unrelated providers and aliases concurrent.
  async #withConnectionOperation<T>(serviceId: string, connectionId: string, operation: () => Promise<T>): Promise<T> {
    const key = `${serviceId}/${connectionId}`;
    const previous = this.#connectionOperations.get(key) ?? Promise.resolve();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const tail = previous.catch(() => undefined).then(() => gate);
    this.#connectionOperations.set(key, tail);
    await previous.catch(() => undefined);
    try {
      return await operation();
    } finally {
      release();
      if (this.#connectionOperations.get(key) === tail) this.#connectionOperations.delete(key);
    }
  }

  // Requires a catalog-owned auth probe to corroborate an endpoint 401 before invalidating the whole connection.
  async #authenticationProbeRejects(options: {
    credentials: Record<string, string>;
    gateway: NonNullable<ServiceConfig['http']>;
    originalMethod: string;
    originalPath: string;
    secrets: string[];
    service: ServiceConfig;
    signal?: AbortSignal;
  }): Promise<boolean> {
    const ping = options.service.ping;
    if (!ping || ping.interface !== 'http') return true;
    const pingMethod = (ping.method ?? 'GET').toUpperCase();
    if (pingMethod === options.originalMethod && ping.path === options.originalPath) return true;
    try {
      const response = await performGatewayRequest({
        body: Buffer.alloc(0),
        credentials: options.credentials,
        gateway: options.gateway,
        headers: {},
        method: pingMethod,
        path: ping.path,
        secrets: options.secrets,
        ...(options.signal ? { signal: options.signal } : {}),
      });
      return response.status === 401;
    } catch {
      return false;
    }
  }

  // Persists refreshed authority under its immutable ID and updates metadata only after alias assignment.
  #persistCommandResult(serviceId: string, connectionId: string, result: CommandResult): void {
    this.#store.set(connectionCredentialStoreKey(serviceId, connectionId), result.credentials);
    if (result.session) this.#store.set(connectionSessionStoreKey(serviceId, connectionId), result.session);
    if (result.clearSession) this.#store.delete(connectionSessionStoreKey(serviceId, connectionId));
    if (this.#accounts().services[serviceId]?.connections[connectionId]) {
      this.#refreshConnection(serviceId, connectionId, result.credentials, Boolean(result.session) || (!result.clearSession && this.#store.has(connectionSessionStoreKey(serviceId, connectionId))));
    }
  }

  // Adds one aliased connection and establishes the first default without conflating either with its ID.
  #upsertConnection(
    serviceId: string,
    connectionId: string,
    alias: string,
    aliasSource: AliasSource,
    credentials: CredentialRecord,
    hasSession: boolean,
    origin: Omit<ConnectionOrigin, 'recordedAt'>,
  ): void {
    const index = this.#accounts();
    const now = new Date().toISOString();
    const serviceConnections = index.services[serviceId] ?? { connections: {} };
    const existing = serviceConnections.connections[connectionId];
    serviceConnections.connections[connectionId] = {
      alias,
      aliasSource,
      configuredFields: Object.keys(credentials.fields),
      createdAt: existing?.createdAt ?? now,
      hasSession,
      ...(existing?.identity ? { identity: existing.identity } : {}),
      lastVerifiedAt: now,
      origin: { ...origin, recordedAt: now },
      updatedAt: now,
    };
    serviceConnections.default ??= connectionId;
    index.services[serviceId] = serviceConnections;
    this.#saveAccounts(index);
  }

  // Refreshes one existing connection without changing the alias chosen for project routing.
  #refreshConnection(serviceId: string, connectionId: string, credentials: CredentialRecord, hasSession: boolean): void {
    const index = this.#accounts();
    const metadata = index.services[serviceId]?.connections[connectionId];
    if (!metadata) return;
    metadata.configuredFields = Object.keys(credentials.fields);
    metadata.hasSession = hasSession;
    metadata.lastVerifiedAt = new Date().toISOString();
    metadata.needsLogin = false;
    metadata.updatedAt = metadata.lastVerifiedAt;
    this.#saveAccounts(index);
  }

  // Updates only the non-secret display identity captured through a catalog-owned command.
  #setConnectionIdentity(serviceId: string, connectionId: string, identity: string): void {
    const index = this.#accounts();
    const metadata = index.services[serviceId]?.connections[connectionId];
    if (!metadata) return;
    metadata.identity = identity;
    this.#saveAccounts(index);
  }

  // Marks a failed refresh for the next login while retaining the encrypted session for provider-led repair.
  #markConnectionNeedsLogin(serviceId: string, connectionId: string): void {
    const index = this.#accounts();
    const metadata = index.services[serviceId]?.connections[connectionId];
    if (!metadata || metadata.needsLogin) return;
    metadata.needsLogin = true;
    this.#saveAccounts(index);
  }

  // Loads the encrypted authoritative connection index after constructor migration has completed.
  #accounts(): MachineConnections {
    return this.#store.get<MachineConnections>(machineAccountsStoreKey()) ?? { schemaVersion: 2, services: {} };
  }

  // Commits the encrypted index first, then its non-authoritative alias completion mirror.
  #saveAccounts(index: MachineConnections, providedState?: MachineState): void {
    this.#store.set(machineAccountsStoreKey(), index);
    const state = providedState ?? this.#machineStateV2();
    this.#syncStateAccounts(state, index);
    this.#saveState(state);
  }

  // Mirrors aliases only so completion works with the daemon stopped without revealing connection IDs.
  #syncStateAccounts(state: MachineState, index = this.#accounts()): void {
    state.services = Object.fromEntries(Object.entries(index.services).map(([serviceId, item]) => [serviceId, {
      aliases: Object.values(item.connections).map((metadata) => metadata.alias).sort(),
      ...(item.default && item.connections[item.default] ? { default: item.connections[item.default]!.alias } : {}),
    }]));
  }

  // Creates the local device identity on first use and keeps private keys solely in the encrypted vault.
  #ensureMachineIdentity(): MachineIdentityPrivate {
    const existing = this.#store.get<MachineIdentityPrivate>(machineIdentityStoreKey());
    if (existing) return existing;
    const created = createMachineIdentity();
    this.#store.set(machineIdentityStoreKey(), created);
    return created;
  }

  // Loads only a completed v2 discovery registry after constructor migration has run.
  #machineStateV2(): MachineState {
    const state = loadMachineState(this.#paths.stateFile);
    if (state.schemaVersion !== 2) throw new SignedInError('MIGRATION_INCOMPLETE', 'signed-in account migration is incomplete', { remedy: 'signed-in doctor' });
    return state;
  }

  // Updates the public registry after encrypted authority state has been safely committed.
  #saveState(state: MachineState): void {
    saveMachineState(this.#paths.stateFile, state);
  }

  // Records protected control actions in the same secret-free receipt stream as runtime calls.
  #auditControl(action: string, classification: PolicyDecision['classification'], effect: PolicyDecision['effect'], reason: string, providerId?: string, projectId?: string): void {
    const receipt = this.#audit.start({
      interface: 'control',
      path: action,
      ...(projectId ? { projectId } : {}),
      ...(providerId ? { providerId } : {}),
    }, { classification, effect, matchedRules: ['signed-in:operator-control'], reason });
    this.#audit.complete(receipt, { status: 'completed' });
  }

  // Checks a stored machine pin without resolving PATH or mutating trust.
  #binaryTrusted(serviceId: string): boolean {
    const pin = this.#store.get<BinaryPin>(binaryPinStoreKey(serviceId));
    return Boolean(pin && binaryPinMatches(pin));
  }

  // Re-keys alias-addressed authority into immutable connections before any runtime operation can resolve it.
  #migrateConnections(): void {
    const stored = this.#store.get<LegacyMachineAccounts | MachineConnections>(machineAccountsStoreKey());
    const existingJournal = this.#store.get<ConnectionMigrationJournal>(connectionMigrationStoreKey());
    if (!stored) return;
    if (stored.schemaVersion === 2) {
      if (existingJournal) {
        const state = this.#machineStateV2();
        this.#syncStateAccounts(state, stored);
        this.#saveState(state);
        cleanupConnectionMigration(existingJournal, this.#store);
      }
      return;
    }
    const journal = existingJournal ?? createConnectionMigration(stored);
    if (!existingJournal) this.#store.set(connectionMigrationStoreKey(), journal);
    for (const entry of Object.values(journal.entries)) {
      copyAndVerifyRecord(this.#store, entry.sourceCredentialKey, entry.targetCredentialKey);
      copyAndVerifyRecord(this.#store, entry.sourceSessionKey, entry.targetSessionKey);
    }
    const state = this.#machineStateV2();
    for (const registered of Object.values(state.projects)) {
      const trusted = this.#store.get<TrustedProject>(trustedProjectStoreKey(registered.id));
      if (!trusted) continue;
      const connections = { ...(trusted.connections ?? {}) };
      for (const [serviceId, value] of Object.entries(trusted.config.services)) {
        const alias = projectBinding(value)?.account;
        if (!alias || alias === 'default') continue;
        const entry = Object.values(journal.entries).find((candidate) => candidate.serviceId === serviceId && candidate.legacyAlias === alias);
        if (entry) connections[serviceId] = entry.connectionId;
      }
      this.#store.set<TrustedProject>(trustedProjectStoreKey(registered.id), { ...trusted, connections });
    }
    const index = buildConnectionsFromMigration(journal);
    this.#store.set(machineAccountsStoreKey(), index);
    this.#syncStateAccounts(state, index);
    this.#saveState(state);
    cleanupConnectionMigration(journal, this.#store);
  }

  // Re-keys every v1 project record through a crash-resumable encrypted journal before normal service starts.
  #migrateLegacyState(): void {
    const state = loadMachineState(this.#paths.stateFile);
    if (state.schemaVersion !== 1) return;
    const journal = this.#store.get<MigrationJournal>(migrationStoreKey()) ?? { entries: {}, noticePending: true, projects: {}, version: 1 };
    const registered = Object.values(state.projects).sort((left, right) => left.trustedAt.localeCompare(right.trustedAt) || left.id.localeCompare(right.id));
    for (const project of registered) {
      const stored = this.#store.get<LegacyTrustedProject | TrustedProject>(trustedProjectStoreKey(project.id));
      if (!stored) continue;
      if (!journal.projects[project.id]) {
        const normalized = normalizeProjectConfig(validateProjectConfig(stored.config, project.configPath));
        journal.projects[project.id] = { config: normalized, trustedAt: stored.trustedAt };
        this.#store.set(migrationStoreKey(), journal);
      }
      const legacyProviders = stored.config.schemaVersion === 1 ? stored.config.providers : {};
      for (const [serviceId, legacyProvider] of Object.entries(legacyProviders)) {
        this.#migrateLegacyPair(journal, project.id, serviceId, stored.trustedAt);
        const cli = legacyProvider.cli;
        if (cli?.trustedExecutable && cli.trustedExecutableSha256 && !this.#store.has(binaryPinStoreKey(serviceId))) {
          this.#store.set<BinaryPin>(binaryPinStoreKey(serviceId), {
            path: cli.trustedExecutable,
            pinnedAt: stored.trustedAt,
            sha256: cli.trustedExecutableSha256,
          });
        }
      }
    }
    const index = buildAccountsFromJournal(journal, this.#store);
    this.#store.set(machineAccountsStoreKey(), index);
    for (const project of registered) {
      const record = journal.projects[project.id];
      if (!record) continue;
      const services = { ...record.config.services };
      for (const entry of Object.values(journal.entries).filter((candidate) => candidate.projectId === project.id)) {
        const previous = projectBinding(services[entry.serviceId]);
        services[entry.serviceId] = { account: entry.account, required: previous?.required ?? true };
      }
      const config = normalizeProjectConfig({ ...record.config, services });
      const fingerprint = fingerprintProjectConfig(config);
      this.#store.set<TrustedProject>(trustedProjectStoreKey(project.id), { config, fingerprint, trustedAt: record.trustedAt });
      project.fingerprint = fingerprint;
    }
    const nextState: MachineState = { projects: state.projects, schemaVersion: 2 };
    if (state.identity) nextState.identity = state.identity;
    this.#saveState(nextState);
  }

  // Advances one legacy service record through RESERVED, COMMITTED, and DELETED without a loss window.
  #migrateLegacyPair(journal: MigrationJournal, projectId: string, serviceId: string, trustedAt: string): void {
    const entryKey = `${projectId}\u0000${serviceId}`;
    let entry = journal.entries[entryKey];
    const sourceCredentialKey = credentialStoreKey(projectId, serviceId);
    const sourceSessionKey = sessionStoreKey(projectId, serviceId);
    const credentials = this.#store.get<CredentialRecord>(sourceCredentialKey);
    const session = this.#store.get<SessionBundle>(sourceSessionKey);
    if (!entry) {
      const credId = credentialIdentity(credentials);
      const shared = credId ? Object.values(journal.entries).find((candidate) => candidate.serviceId === serviceId && candidate.credId === credId) : undefined;
      const account = shared?.account ?? allocateMigrationAccount(journal, serviceId, projectId);
      entry = {
        account,
        credId,
        projectId,
        serviceId,
        sessId: recordDigest(session),
        sourceCredentialKey,
        sourceSessionKey,
        state: 'RESERVED',
        targetCredentialKey: accountCredentialStoreKey(serviceId, account),
        targetSessionKey: accountSessionStoreKey(serviceId, account),
        trustedAt,
      };
      journal.entries[entryKey] = entry;
      this.#store.set(migrationStoreKey(), journal);
    }
    if (entry.state === 'RESERVED') {
      if (credentials) this.#store.set(entry.targetCredentialKey, credentials);
      if (session) this.#store.set(entry.targetSessionKey, session);
      verifyMigratedRecord(this.#store, entry, credentials, session);
      entry.state = 'COMMITTED';
      this.#store.set(migrationStoreKey(), journal);
    }
    if (entry.state === 'COMMITTED') {
      this.#store.delete(entry.sourceCredentialKey);
      this.#store.delete(entry.sourceSessionKey);
      entry.state = 'DELETED';
      this.#store.set(migrationStoreKey(), journal);
    }
  }
}

interface ConnectionRef {
  alias: string;
  id: string;
  metadata: ConnectionMetadata;
}

interface ConnectionMigrationEntry {
  alias: string;
  aliasSource: AliasSource;
  connectionId: string;
  default: boolean;
  legacyAlias: string;
  metadata: Omit<ConnectionMetadata, 'alias' | 'aliasSource'>;
  serviceId: string;
  sourceCredentialKey: string;
  sourceSessionKey: string;
  targetCredentialKey: string;
  targetSessionKey: string;
}

interface ConnectionMigrationJournal {
  entries: Record<string, ConnectionMigrationEntry>;
  version: 1;
}

interface LegacyTrustedProject {
  config: LegacySignedInProjectConfig;
  fingerprint: string;
  trustedAt: string;
}

interface MigrationEntry {
  account: string;
  credId: string | null;
  projectId: string;
  serviceId: string;
  sessId: string | null;
  sourceCredentialKey: string;
  sourceSessionKey: string;
  state: 'COMMITTED' | 'DELETED' | 'RESERVED';
  targetCredentialKey: string;
  targetSessionKey: string;
  trustedAt: string;
}

interface MigrationJournal {
  entries: Record<string, MigrationEntry>;
  noticePending: boolean;
  projects: Record<string, { config: SignedInProjectConfig; trustedAt: string }>;
  version: 1;
}

// Rejects ambiguous or visually special aliases before they enter routing or project config.
function validateAccountName(account: string): void {
  if (!isSafeAccountName(account)) {
    throw new SignedInError('INVALID_ACCOUNT', `'${account}' is not a valid connection alias`, {
      pattern: 'lowercase letters, digits, and hyphens; up to 32 characters',
      reserved: [...reservedAccountNames],
    });
  }
}

// Converts project shorthand into one exact alias requirement without leaking storage concerns upward.
function projectBinding(binding: ProjectServiceBinding | undefined): {
  account?: string;
  checks: NonNullable<Exclude<ProjectServiceBinding, boolean | string>['checks']>;
  expectedIdentity?: string;
  required: boolean;
  target?: string;
} | undefined {
  if (binding === undefined) return undefined;
  if (binding === true) return { checks: [], required: true };
  if (typeof binding === 'string') return { account: binding, checks: [], required: true };
  const alias = binding.alias ?? binding.account;
  return {
    ...(alias ? { account: alias } : {}),
    checks: binding.checks ?? [],
    ...(binding.expectedIdentity ? { expectedIdentity: binding.expectedIdentity } : {}),
    required: binding.required === true,
    ...(binding.target ? { target: binding.target } : {}),
  };
}

// Converts a sealed project target into the catalog-owned environment variable accepted by the provider CLI.
function projectCommandEnvironment(
  service: ServiceConfig,
  binding: ReturnType<typeof projectBinding>,
): { commandEnvironment?: Record<string, string> } {
  if (!binding?.target || !service.target) return {};
  return { commandEnvironment: { [service.target.env]: binding.target } };
}

// Recognizes exact provider identities and structured display identities without allowing arbitrary substring matches.
function identityContainsExpectedValue(identity: string, expected: string): boolean {
  return identity === expected || identity.split('·').some((part) => part.trim() === expected);
}

// Drops built-in provider copies from upgraded v1 files and prevents project policy from widening defaults.
function normalizeProjectConfig(config: SignedInProjectConfig): SignedInProjectConfig {
  for (const rule of config.policies ?? []) {
    if (rule.effect === 'allow') throw new SignedInError('POLICY_WIDENING', `Project policy '${rule.id}' cannot use allow`);
  }
  const providers = Object.fromEntries(Object.entries(config.providers).filter(([serviceId]) => !builtInServices[serviceId]));
  for (const serviceId of Object.keys(config.services)) {
    if (!builtInServices[serviceId] && !providers[serviceId]) throw new SignedInError('UNKNOWN_SERVICE', `Project references unknown service '${serviceId}'`);
  }
  return { ...config, providers };
}

// Builds the minimal effective config expected by the unchanged policy and native proxy layers.
function effectivePolicyConfig(serviceId: string, service: ServiceConfig, project?: TrustedProject): SignedInProjectConfig {
  return {
    ...(project?.config.environment ? { environment: project.config.environment } : {}),
    ...(project?.config.policies ? { policies: project.config.policies } : {}),
    project: project?.config.project ?? { id: 'machine', name: 'This machine' },
    providers: { [serviceId]: service },
    schemaVersion: 2,
    services: { [serviceId]: true },
  };
}

// Treats resolver-produced fields as ready when a retained session can mint them just in time.
function sessionCanResolveMissing(provider: ProviderConfig, missingFields: string[]): boolean {
  const resolvedFields = new Set((provider.session?.resolvers ?? []).flatMap((resolver) => [
    ...(resolver.targetField ? [resolver.targetField] : []),
    ...Object.keys(resolver.fieldMap ?? {}),
    ...(resolver.format === 'aws-process-json' ? ['accessKeyId', 'secretAccessKey', 'sessionToken'] : []),
  ]));
  return missingFields.every((field) => resolvedFields.has(field));
}

/** Prevents discarded AWS browser state from making a sealed, non-expiring connection look stale. */
function hasDurableAwsCredentials(provider: ProviderConfig, credentials: CredentialRecord | undefined): boolean {
  const auth = provider.http?.auth;
  if (auth?.type !== 'aws-sigv4') return false;
  return Boolean(
    credentials?.fields[auth.accessKeyField]
    && credentials.fields[auth.secretKeyField]
    && (!auth.sessionTokenField || !credentials.fields[auth.sessionTokenField]),
  );
}

// Derives real auth requirements so optional prompt metadata cannot make a gateway falsely ready.
function requiredCredentialFieldIds(provider: ProviderConfig): Set<string> {
  const required = new Set((provider.credentials ?? []).filter((field) => field.required !== false).map((field) => field.id));
  const auth = provider.http?.auth;
  if (!auth || auth.type === 'none') return required;
  if (auth.type === 'bearer' || auth.type === 'header') required.add(auth.field);
  if (auth.type === 'basic') {
    required.add(auth.usernameField);
    if (auth.passwordField) required.add(auth.passwordField);
  }
  if (auth.type === 'aws-sigv4') {
    required.add(auth.accessKeyField);
    required.add(auth.secretKeyField);
  }
  if (auth.type === 'apple-connect-jwt') {
    required.add(auth.issuerField);
    required.add(auth.keyIdField);
    required.add(auth.privateKeyField);
  }
  return required;
}

// Stops runtime calls with an agent-actionable sign-in remedy before provider errors become opaque.
function assertSurfaceReady(service: ServiceConfig, credentials: CredentialRecord, session: SessionBundle | undefined, serviceId: string, account: string, surface: 'http' | 'native'): void {
  const missing = [...requiredCredentialFieldIds(service)].filter((field) => !credentials.fields[field]);
  const resolvable = session && sessionCanResolveMissing(service, missing);
  const delivery = service.cli?.delivery ?? (service.http ? 'proxy' : 'environment');
  const sessionRequired = surface === 'native' && delivery === 'session';
  if ((!resolvable && missing.length > 0) || (sessionRequired && !session)) {
    throw new SignedInError('AUTH_REQUIRED', `${service.label} is not signed in`, {
      account,
      remedy: `signed-in login ${serviceId}${account === 'default' ? '' : `@${account}`}`,
      service: serviceId,
    });
  }
}

// Constructs an empty credential record without undefined secret maps throughout the service.
function emptyCredentialRecord(): CredentialRecord {
  return { fields: {}, updatedAt: new Date(0).toISOString() };
}

// Turns operator-initiated login into an explicit audit decision.
function allowDecision(classification: PolicyDecision['classification'], reason: string): PolicyDecision {
  return { classification, effect: 'allow', matchedRules: ['signed-in:operator-login'], reason };
}

// Stops denied or unconfirmed operations before execution reaches a provider boundary.
function assertPolicyDecision(decision: PolicyDecision, approved: boolean | undefined): void {
  if (decision.effect === 'deny') throw new SignedInError('POLICY_DENIED', decision.reason, decision);
  if (decision.effect === 'confirm' && !approved) throw new SignedInError('APPROVAL_REQUIRED', decision.reason, decision);
}

// Converts private authentication failures and arbitrary internals into stable receipt metadata without exposing provider output.
function errorCode(error: unknown): string {
  if (error instanceof ProviderAuthenticationError) return 'AUTH_REQUIRED';
  return error instanceof SignedInError ? error.code : 'PROVIDER_ERROR';
}

// Resolves executables without invoking shell aliases or project-owned code.
function resolveExecutable(command: string): string | undefined {
  const searchDirectories = [...new Set([...(process.env.PATH ?? '').split(delimiter), dirname(process.execPath)])]
    .filter((directory) => directory && !projectOwnedExecutableDirectory(directory));
  const candidates = isAbsolute(command)
    ? projectOwnedExecutableDirectory(dirname(command)) ? [] : [command]
    : searchDirectories.flatMap((directory) => {
      if (process.platform !== 'win32') return [resolve(directory, command)];
      return (process.env.PATHEXT ?? '.EXE;.CMD;.BAT').split(';').map((extension) => resolve(directory, `${command}${extension.toLowerCase()}`));
    });
  const match = candidates.find((candidate) => {
    try { return statSync(candidate).isFile(); } catch { return false; }
  });
  return match ? realpathSync(match) : undefined;
}

// Excludes dependency-manager shims so a repository cannot become trusted merely by changing the operator's shell PATH.
function projectOwnedExecutableDirectory(directory: string): boolean {
  const normalized = resolve(directory).replaceAll('\\', '/').replace(/\/$/u, '');
  return normalized.endsWith('/node_modules/.bin') || normalized.includes('/node_modules/.bin/');
}

// Creates one immutable digest pin for an already-resolved executable.
function binaryPin(executable: string): BinaryPin {
  return { path: executable, pinnedAt: new Date().toISOString(), sha256: createHash('sha256').update(readFileSync(executable)).digest('hex') };
}

// Verifies both path presence and bytes so package upgrades require an intentional re-pin.
function binaryPinMatches(pin: BinaryPin): boolean {
  return existsSync(pin.path) && createHash('sha256').update(readFileSync(pin.path)).digest('hex') === pin.sha256;
}

// Injects a machine pin into the existing runner shape without mutating the packaged catalog.
function withBinaryPin(service: ServiceConfig, pin: BinaryPin): ServiceConfig {
  return { ...service, cli: service.cli ? { ...service.cli, trustedExecutable: pin.path, trustedExecutableSha256: pin.sha256 } : undefined };
}

// Produces one actionable alias error without revealing credential metadata.
function accountMissingError(serviceId: string, account: string, accounts: string[]): SignedInError {
  return new SignedInError('AUTH_REQUIRED', `${serviceId}@${account} is not signed in`, {
    accounts,
    remedy: `signed-in login ${serviceId}${account === 'default' ? '' : `@${account}`}`,
    service: serviceId,
  });
}

// Converts private authentication failures into one safe cause and runnable recovery action without exposing provider output.
function providerAuthenticationRequired(
  service: ServiceConfig,
  serviceId: string,
  account?: string,
  cause?: 'credential-rejected',
): SignedInError {
  const target = `${serviceId}${account && account !== 'default' ? `@${account}` : ''}`;
  const message = cause === 'credential-rejected'
    ? `${service.label} rejected the stored credential`
    : `${service.label} sign-in needs attention`;
  return new SignedInError('AUTH_REQUIRED', message, {
    ...(cause ? { cause } : {}),
    remedy: `signed-in login ${target}`,
    service: serviceId,
  });
}

// Copies a vault record only when present and verifies the destination before the source can be removed.
function copyAndVerifyRecord(store: SecretStore, source: string, destination: string): void {
  const value = store.get<unknown>(source);
  if (value === undefined) return;
  store.set(destination, value);
  if (stableStringify(store.get(destination)) !== stableStringify(value)) throw new Error('Vault re-key verification failed');
}

// Identifies only explicit alias bindings because true follows the machine default automatically.
function bindingReferencesAccount(binding: ProjectServiceBinding | undefined, account: string): boolean {
  return typeof binding === 'string' ? binding === account : typeof binding === 'object' && (binding?.alias ?? binding?.account) === account;
}

// Hashes only non-empty static fields to identify shared credentials during migration.
function credentialIdentity(record: CredentialRecord | undefined): string | null {
  const fields = Object.fromEntries(Object.entries(record?.fields ?? {}).filter(([, value]) => value !== ''));
  return Object.keys(fields).length > 0 ? createHash('sha256').update(stableStringify(fields)).digest('hex') : null;
}

// Hashes an opaque record for migration verification without treating session equality as connection identity.
function recordDigest(value: unknown): string | null {
  return value === undefined ? null : createHash('sha256').update(stableStringify(value)).digest('hex');
}

// Allocates deterministic migration names with explicit collision and reserved-name handling.
function allocateMigrationAccount(journal: MigrationJournal, serviceId: string, projectId: string): string {
  const taken = new Set(Object.values(journal.entries).filter((entry) => entry.serviceId === serviceId).map((entry) => entry.account));
  if (taken.size === 0) return 'default';
  const normalized = projectId.length <= 32 ? projectId : `${projectId.slice(0, 28)}-${createHash('sha256').update(projectId).digest('hex').slice(0, 3)}`;
  let candidate = normalized;
  let suffix = 2;
  while (taken.has(candidate) || reservedAccountNames.has(candidate)) {
    const suffixText = `-${suffix}`;
    candidate = `${normalized.slice(0, 32 - suffixText.length)}${suffixText}`;
    suffix += 1;
  }
  return candidate;
}

// Verifies migration targets against the source digests before a journal entry may become committed.
function verifyMigratedRecord(store: SecretStore, entry: MigrationEntry, credentials: CredentialRecord | undefined, session: SessionBundle | undefined): void {
  if (credentials && credentialIdentity(store.get<CredentialRecord>(entry.targetCredentialKey)) !== entry.credId) throw new Error('Credential migration verification failed');
  if (session && recordDigest(store.get<SessionBundle>(entry.targetSessionKey)) !== entry.sessId) throw new Error('Session migration verification failed');
}

// Rebuilds the legacy alias-keyed index from committed journal targets before its v2 re-key.
function buildAccountsFromJournal(journal: MigrationJournal, store: SecretStore): LegacyMachineAccounts {
  const index: LegacyMachineAccounts = { schemaVersion: 1, services: {} };
  for (const entry of Object.values(journal.entries).filter((candidate) => candidate.state === 'DELETED')) {
    const credentials = store.get<CredentialRecord>(entry.targetCredentialKey);
    const session = store.get<SessionBundle>(entry.targetSessionKey);
    if (!credentials && !session) continue;
    const service = index.services[entry.serviceId] ?? { accounts: {} };
    const previous = service.accounts[entry.account];
    service.accounts[entry.account] = {
      configuredFields: Object.keys(credentials?.fields ?? {}),
      createdAt: previous?.createdAt ?? entry.trustedAt,
      hasSession: Boolean(session),
      updatedAt: credentials?.updatedAt ?? session?.updatedAt ?? entry.trustedAt,
    };
    service.default ??= entry.account;
    index.services[entry.serviceId] = service;
  }
  return index;
}

/**
 * Freezes a deterministic migration plan so restarts cannot allocate different IDs or aliases.
 */
function createConnectionMigration(index: LegacyMachineAccounts): ConnectionMigrationJournal {
  const entries: Record<string, ConnectionMigrationEntry> = {};
  for (const [serviceId, service] of Object.entries(index.services)) {
    const taken = new Set<string>();
    const legacyAliases = Object.keys(service.accounts).sort((left, right) => Number(left === 'default') - Number(right === 'default') || left.localeCompare(right));
    for (const legacyAlias of legacyAliases) {
      const metadata = service.accounts[legacyAlias]!;
      const derived = legacyAlias === 'default'
        ? deriveConnectionAlias(metadata.identity, 'primary', taken)
        : { alias: allocateAlias(normalizeAlias(legacyAlias) ?? 'primary', taken), source: 'operator' as const };
      taken.add(derived.alias);
      const connectionId = migratedConnectionId(serviceId, legacyAlias, metadata.createdAt);
      entries[`${serviceId}\u0000${legacyAlias}`] = {
        alias: derived.alias,
        aliasSource: derived.source,
        connectionId,
        default: service.default === legacyAlias || (!service.default && legacyAliases[0] === legacyAlias),
        legacyAlias,
        metadata,
        serviceId,
        sourceCredentialKey: accountCredentialStoreKey(serviceId, legacyAlias),
        sourceSessionKey: accountSessionStoreKey(serviceId, legacyAlias),
        targetCredentialKey: connectionCredentialStoreKey(serviceId, connectionId),
        targetSessionKey: connectionSessionStoreKey(serviceId, connectionId),
      };
    }
  }
  return { entries, version: 1 };
}

/**
 * Builds the authoritative v2 index only after every encrypted record has copied successfully.
 */
function buildConnectionsFromMigration(journal: ConnectionMigrationJournal): MachineConnections {
  const index: MachineConnections = { schemaVersion: 2, services: {} };
  for (const entry of Object.values(journal.entries)) {
    const service = index.services[entry.serviceId] ?? { connections: {} };
    service.connections[entry.connectionId] = { ...entry.metadata, alias: entry.alias, aliasSource: entry.aliasSource };
    const legacyServiceEntries = Object.values(journal.entries).filter((candidate) => candidate.serviceId === entry.serviceId);
    const legacyDefault = legacyServiceEntries.find((candidate) => candidate.default) ?? legacyServiceEntries[0];
    if (legacyDefault) service.default = legacyDefault.connectionId;
    index.services[entry.serviceId] = service;
  }
  return index;
}

/**
 * Removes obsolete alias-keyed ciphertext only after the v2 index and public mirror are durable.
 */
function cleanupConnectionMigration(journal: ConnectionMigrationJournal, store: SecretStore): void {
  for (const entry of Object.values(journal.entries)) {
    store.delete(entry.sourceCredentialKey);
    store.delete(entry.sourceSessionKey);
  }
  store.delete(connectionMigrationStoreKey());
}

/**
 * Gives migrated authority a stable opaque ID even if migration resumes before its journal is read.
 */
function migratedConnectionId(serviceId: string, alias: string, createdAt: string): string {
  return `c_${createHash('sha256').update(`${serviceId}\u0000${alias}\u0000${createdAt}`).digest('hex').slice(0, 24)}`;
}

/**
 * Allocates opaque local identity that never needs to change when its human alias does.
 */
function createConnectionId(): string {
  return `c_${randomBytes(12).toString('hex')}`;
}

// Canonicalizes nested values for migration equality and vault re-key verification.
function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (typeof value === 'object' && value !== null) {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

// Keeps terminal-safe error hints from including resolver output in unexpected failures.
export function safeErrorMessage(error: unknown): string {
  return redactText(error instanceof Error ? error.message : String(error));
}
