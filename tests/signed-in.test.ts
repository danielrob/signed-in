import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { chmodSync, copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import tls from 'node:tls';

import forge from 'node-forge';

import { deriveConnectionAlias } from '../packages/signed-in/src/aliases.js';
import { bootstrapAwsCredentials } from '../packages/signed-in/src/aws-bootstrap.js';
import { builtInServices } from '../packages/signed-in/src/catalog.js';
import { fingerprintProjectConfig, loadMachineState, validateProjectConfig } from '../packages/signed-in/src/config.js';
import { authenticateHeaders } from '../packages/signed-in/src/http-auth.js';
import { performGatewayRequest } from '../packages/signed-in/src/http-gateway.js';
import { findProviderLoginUrl } from '../packages/signed-in/src/external-url.js';
import {
  createMachineIdentity,
  decryptPairingEnvelope,
  encryptPairingPayload,
  publicMachineIdentity,
} from '../packages/signed-in/src/pairing.js';
import { evaluatePolicy } from '../packages/signed-in/src/policy.js';
import { startCredentialProxy, startCredentialSocketProxy } from '../packages/signed-in/src/proxy.js';
import { redactStructured, StreamRedactor } from '../packages/signed-in/src/redact.js';
import { adoptExistingProviderLogin, discoverExistingProviderLogin, runProviderCommand, runProviderLogin } from '../packages/signed-in/src/runner.js';
import { materializeBundle, snapshotBundle, snapshotDeclaredPaths } from '../packages/signed-in/src/session.js';
import {
  accountCredentialStoreKey,
  accountSessionStoreKey,
  binaryPinStoreKey,
  connectionCredentialStoreKey,
  connectionSessionStoreKey,
  credentialStoreKey,
  machineAccountsStoreKey,
  MemorySecretStore,
  trustedProjectStoreKey,
} from '../packages/signed-in/src/secrets.js';
import { SignedInError, SignedInService } from '../packages/signed-in/src/service.js';
import type { SignedInPaths } from '../packages/signed-in/src/paths.js';
import type { MachineConnections, SignedInProjectConfig, PairingPayload } from '../packages/signed-in/src/types.js';

const baseConfig: SignedInProjectConfig = {
  environment: 'production',
  policies: [],
  project: { id: 'test-project', name: 'Test Project' },
  providers: {
    demo: {
      credentialMode: 'shared',
      credentials: [{ env: 'DEMO_TOKEN', helpUrl: 'https://example.com/tokens', id: 'token', label: 'Demo token', portable: true }],
      http: {
        auth: { field: 'token', type: 'bearer' },
        baseUrl: 'https://api.example.com',
      },
      label: 'Demo',
      signIn: 'manual',
    },
  },
  schemaVersion: 2,
  services: { demo: true },
};

test('CLI help and version stay discoverable without starting the daemon', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-cli-help-'));
  const rootHelp = runSignedInCli(['--help'], stateRoot);
  assert.equal(rootHelp.status, 0);
  assert.match(rootHelp.stdout, /signed-in[\s\S]*signed-in aws s3 ls/u);
  assert.match(rootHelp.stdout, /signed-in help agent/u);
  assert.match(rootHelp.stdout, /signed-in connections\s+repair or remove a connection/u);
  assert.match(rootHelp.stdout, /signed-in ping \[service\|--all\]\s+test authenticated access/u);

  const loginHelp = runSignedInCli(['login', '--help'], stateRoot);
  assert.equal(loginHelp.status, 0);
  assert.match(loginHelp.stdout, /signed-in login \[service\[@alias\]…\]/u);

  const pingHelp = runSignedInCli(['ping', '--help'], stateRoot);
  assert.equal(pingHelp.status, 0);
  assert.match(pingHelp.stdout, /Prove that stored service authority[\s\S]*signed-in ping \[service\[@alias\] \| --all\]/u);
  assert.match(pingHelp.stdout, /every saved alias/u);

  const verifyHelp = runSignedInCli(['verify', '--help'], stateRoot);
  assert.equal(verifyHelp.status, 0);
  assert.match(verifyHelp.stdout, /Compatibility alias for signed-in ping[\s\S]*signed-in verify \[service\[@alias\] \| --all\]/u);

  const agentHelp = runSignedInCli(['help', 'agent'], stateRoot);
  assert.equal(agentHelp.status, 0);
  assert.match(agentHelp.stdout, /Agent guide[\s\S]*Never search for, print, or request the underlying credential/u);

  const serviceHelp = runSignedInCli(['help', 'aws'], stateRoot);
  assert.equal(serviceHelp.status, 0);
  assert.match(serviceHelp.stdout, /AWS[\s\S]*signed-in login aws\[@alias\][\s\S]*signed-in aws --help/u);

  const shareHelp = runSignedInCli(['share-auth', '--help'], stateRoot);
  assert.equal(shareHelp.status, 0);
  assert.match(shareHelp.stdout, /recipient-bound ciphertext/u);

  const connectionsHelp = runSignedInCli(['connections', '--help'], stateRoot);
  assert.equal(connectionsHelp.status, 0);
  assert.match(connectionsHelp.stdout, /signed-in connections \[service\[@alias\]\]/u);

  const version = runSignedInCli(['--version'], stateRoot);
  assert.equal(version.status, 0);
  assert.equal(version.stdout, '0.1.0\n');
  assert.equal(existsSync(path.join(stateRoot, 'runtime')), false);
});

test('CLI completions include pair identity and built-ins reject unknown flags', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-cli-completion-'));
  const completion = runSignedInCli(['completion', 'zsh'], stateRoot);
  assert.equal(completion.status, 0);
  assert.match(completion.stdout, /public-key identity export import/u);

  const invalid = runSignedInCli(['completion', '--nope'], stateRoot);
  assert.equal(invalid.status, 1);
  assert.equal(invalid.stdout, '');
  assert.match(invalid.stderr, /Unknown option '--nope'/u);

  const conflictingPing = runSignedInCli(['ping', 'github', '--all'], stateRoot);
  assert.equal(conflictingPing.status, 1);
  assert.match(conflictingPing.stderr, /Choose one connection or --all/u);

  const providerJson = runSignedInCli(['not-a-service', '--json'], stateRoot);
  assert.equal(providerJson.status, 1);
  assert.equal(providerJson.stdout, '');
  assert.doesNotMatch(providerJson.stderr, /^\s*\{/u);
  runSignedInCli(['daemon', 'stop'], stateRoot);
});

test('opening setup instructions settles before a top-level CLI process exits', { skip: process.platform === 'win32' }, () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-open-url-'));
  const bin = path.join(root, 'bin');
  mkdirSync(bin);
  for (const command of ['open', 'xdg-open']) {
    const executable = path.join(bin, command);
    writeFileSync(executable, '#!/bin/sh\nsleep 0.1\n');
    chmodSync(executable, 0o755);
  }
  const probe = path.join(root, 'probe.mts');
  const moduleUrl = new URL('../packages/signed-in/src/external-url.ts', import.meta.url).href;
  writeFileSync(probe, `import { openExternalUrl } from ${JSON.stringify(moduleUrl)};\nawait openExternalUrl('https://example.com/docs');\nprocess.stdout.write('settled\\n');\n`);

  const result = spawnSync(process.execPath, ['--import', 'tsx', probe], {
    encoding: 'utf8',
    env: { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}` },
    timeout: 5_000,
  });

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'settled\n');
});

test('daemon status keeps warnings off stdout', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-cli-warning-'));
  const status = runSignedInCli(['daemon', 'status'], stateRoot);
  assert.equal(status.status, 0);
  assert.equal(status.stdout, '');
  assert.match(status.stderr, /signed-in-daemon is not running/u);
});

test('bare status is useful on a pristine machine without a project', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-cli-pristine-'));
  const status = runSignedInCli([], stateRoot);
  assert.equal(status.status, 0);
  assert.match(status.stdout, /No services are signed in/u);
  assert.match(status.stdout, /signed-in login/u);
  assert.match(status.stdout, /signed-in help agent/u);
  assert.doesNotMatch(status.stderr, /trusted signed-in project|setup --config/u);
  assert.equal(existsSync(path.join(stateRoot, 'runtime')), false);

  const catalog = runSignedInCli(['status', '--all'], stateRoot);
  assert.equal(catalog.status, 0);
  assert.match(catalog.stdout, /Cloud infrastructure, release storage/u);
  assert.doesNotMatch(catalog.stdout, /browser ·|API key ·/u);
  assert.equal(existsSync(path.join(stateRoot, 'runtime')), false);
  runSignedInCli(['daemon', 'stop'], stateRoot);
});

test('non-interactive login fails with the human-required contract and a runnable remedy', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-cli-human-'));
  const login = runSignedInCli(['--json', 'login', 'resend'], stateRoot);
  assert.equal(login.status, 75);
  assert.equal(login.stdout, '');
  const failure = JSON.parse(login.stderr) as { error: { code: string; remedy: string } };
  assert.equal(failure.error.code, 'HUMAN_REQUIRED');
  assert.equal(failure.error.remedy, 'signed-in login resend');

  const reset = runSignedInCli(['--json', 'reset'], stateRoot);
  assert.equal(reset.status, 75);
  assert.equal(reset.stdout, '');
  const resetFailure = JSON.parse(reset.stderr) as { error: { code: string; remedy: string } };
  assert.equal(resetFailure.error.code, 'HUMAN_REQUIRED');
  assert.equal(resetFailure.error.remedy, 'signed-in reset');

  const trust = runSignedInCli(['--json', 'trust', 'aws'], stateRoot);
  assert.equal(trust.status, 75);
  assert.equal(trust.stdout, '');
  const trustFailure = JSON.parse(trust.stderr) as { error: { code: string; remedy: string } };
  assert.equal(trustFailure.error.code, 'HUMAN_REQUIRED');
  assert.equal(trustFailure.error.remedy, 'signed-in trust aws');

  const connections = runSignedInCli(['--json', 'connections'], stateRoot);
  assert.equal(connections.status, 75);
  const connectionsFailure = JSON.parse(connections.stderr) as { error: { code: string; remedy: string } };
  assert.equal(connectionsFailure.error.code, 'HUMAN_REQUIRED');
  assert.equal(connectionsFailure.error.remedy, 'signed-in status --json');
  runSignedInCli(['daemon', 'stop'], stateRoot);
});

test('authentication failures stay prompt-free for automation while retaining the exact login remedy', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-cli-auth-recovery-'));
  const ping = runSignedInCli(['ping', 'github'], stateRoot);
  assert.equal(ping.status, 75);
  assert.match(ping.stderr, /github is not signed in[\s\S]*signed-in login github/u);
  assert.doesNotMatch(ping.stderr, /Sign in to GitHub now/u);
  const compatibility = runSignedInCli(['verify', 'github'], stateRoot);
  assert.equal(compatibility.status, 75);
  assert.match(compatibility.stderr, /github is not signed in[\s\S]*signed-in login github/u);
  assert.doesNotMatch(compatibility.stderr, /trusted project context/u);
  runSignedInCli(['daemon', 'stop'], stateRoot);
});

test('service removes the obsolete control verifier during startup', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-approval-migration-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const store = new MemorySecretStore();
  store.set('machine/operator/verifier', { digest: 'obsolete', salt: 'obsolete', version: 1 });

  new SignedInService(store, paths);

  assert.equal(store.has('machine/operator/verifier'), false);
});

test('doctor distinguishes an unused CLI from a configured service whose CLI is missing', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-doctor-binaries-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const store = new MemorySecretStore();
  const timestamp = '2026-08-08T00:00:00.000Z';
  store.set(machineAccountsStoreKey(), {
    schemaVersion: 2,
    services: {
      gcp: {
        connections: {
          c_doctor: {
            alias: 'work',
            aliasSource: 'operator',
            configuredFields: ['accessToken'],
            createdAt: timestamp,
            hasSession: false,
            updatedAt: timestamp,
          },
        },
        default: 'c_doctor',
      },
    },
  });
  const previousPath = process.env.PATH;
  process.env.PATH = '';
  try {
    const service = new SignedInService(store, paths);
    const services = service.doctor().services;
    assert.deepEqual(
      services.find((service) => service.id === 'gcp'),
      {
        configured: true,
        id: 'gcp',
        label: 'Google Cloud',
        remedy: 'https://cloud.google.com/sdk/docs/install',
        state: 'not-installed',
        trusted: false,
      },
    );
    assert.equal(services.find((service) => service.id === 'aws')?.state, 'not-used');
    const gcp = service.serviceStatuses().find((candidate) => candidate.id === 'gcp');
    assert.equal(gcp?.state, 'needs-you');
    assert.equal(gcp?.remedy, 'signed-in login gcp@work');
    assert.equal(gcp?.accounts[0]?.state, 'needs-sign-in');
    assert.equal(gcp?.accounts[0]?.remedy, 'signed-in login gcp@work');
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
  }
});

test('daemon executable discovery ignores project-local shims and accepts a global command', { skip: process.platform === 'win32' }, () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-global-cli-'));
  const localBin = path.join(root, 'repo', 'node_modules', '.bin');
  const globalBin = path.join(root, 'global-bin');
  const command = `signed-in-provider-${process.pid}-${Date.now()}`;
  mkdirSync(localBin, { recursive: true });
  mkdirSync(globalBin, { recursive: true });
  const localExecutable = path.join(localBin, command);
  const globalExecutable = path.join(globalBin, command);
  writeFileSync(localExecutable, '#!/bin/sh\nexit 0\n');
  writeFileSync(globalExecutable, '#!/bin/sh\nexit 0\n');
  chmodSync(localExecutable, 0o755);
  chmodSync(globalExecutable, 0o755);
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const service = new SignedInService(new MemorySecretStore(), paths);
  const config: SignedInProjectConfig = {
    ...baseConfig,
    providers: {
      demo: {
        ...baseConfig.providers.demo!,
        cli: { command, delivery: 'environment' },
      },
    },
  };
  const previousPath = process.env.PATH;
  try {
    process.env.PATH = localBin;
    service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
    assert.deepEqual(service.cliAvailability({ projectId: 'test-project', providerId: 'demo' }), {
      available: false,
      command,
    });

    process.env.PATH = `${localBin}${path.delimiter}${globalBin}`;
    assert.deepEqual(service.cliAvailability({ projectId: 'test-project', providerId: 'demo' }), {
      available: true,
      command,
      executable: realpathSync(globalExecutable),
    });
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
  }
});

test('account grammar fails before authentication and names its reserved words', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-cli-account-name-'));
  for (const target of ['aws@All', 'aws@']) {
    const login = runSignedInCli(['login', target], stateRoot);
    assert.equal(login.status, 1);
    assert.match(login.stderr, /lowercase letters, digits, and hyphens/u);
    assert.match(login.stderr, /reserved: all, default, list, new, none/u);
  }
  runSignedInCli(['daemon', 'stop'], stateRoot);
});

test('built-in catalog separates interactive sign-in from manual runtime CLIs', () => {
  assert.equal(Object.keys(builtInServices).length, 20);
  assert.equal(builtInServices.github?.signIn, 'interactive');
  assert.equal(builtInServices.stripe?.signIn, 'manual');
  assert.equal(builtInServices.openai?.signIn, 'manual');
  assert.ok(builtInServices.stripe?.cli);
  assert.deepEqual(builtInServices.convex?.session?.loginArgs, ['login', '--device-name', 'signed-in', '--login-flow', 'poll', '--no-open']);
  assert.deepEqual(builtInServices.convex?.session?.remoteLoginArgs, ['login', '--device-name', 'signed-in', '--login-flow', 'poll', '--no-open']);
  assert.deepEqual(builtInServices.aws?.ping, { args: ['sts', 'get-caller-identity'], interface: 'native' });
  assert.deepEqual(builtInServices.clerk?.credentials?.[0]?.prefixes, ['sk_test_', 'sk_live_']);
  assert.deepEqual(builtInServices.shopify?.cli, {
    clearEnv: ['SHOPIFY_FLAG_*'],
    command: 'shopify',
    delivery: 'session',
  });
  assert.equal(builtInServices.shopify?.existingLogin, undefined);
  assert.deepEqual(builtInServices.shopify?.session?.env, {
    CI: '1',
    SHOPIFY_CLI_NO_ANALYTICS: '1',
  });
  assert.deepEqual(builtInServices.shopify?.session?.loginArgs, ['auth', 'login', '--alias', 'signed-in']);
  assert.deepEqual(builtInServices.shopify?.session?.remoteLoginArgs, ['auth', 'login', '--alias', 'signed-in']);
  assert.deepEqual(builtInServices.shopify?.ping, { args: ['organization', 'list', '--json'], interface: 'native' });
  assert.deepEqual(builtInServices.shopify?.target, {
    env: 'SHOPIFY_FLAG_STORE',
    label: 'store',
    pattern: '^[a-z0-9][a-z0-9-]*\\.myshopify\\.com$',
  });
  assert.equal(builtInServices.shopify?.http, undefined);
  assert.deepEqual(builtInServices.github?.session?.loginArgs.slice(-4), ['--scopes', 'workflow', '--insecure-storage', '--skip-ssh-key']);
  assert.deepEqual(builtInServices.datocms?.credentials, [{
    env: 'DATOCMS_API_TOKEN',
    helpUrl: 'https://www.datocms.com/docs/content-management-api/authentication',
    id: 'apiToken',
    label: 'DatoCMS API token',
    portable: true,
    secret: true,
  }]);
  assert.deepEqual(builtInServices.datocms?.http, {
    auth: { field: 'apiToken', type: 'bearer' },
    baseUrl: 'https://site-api.datocms.com',
    defaultHeaders: {
      accept: 'application/json',
      'content-type': 'application/vnd.api+json',
      'x-api-version': '3',
    },
  });
  assert.deepEqual(builtInServices.datocms?.ping, { interface: 'http', method: 'GET', path: '/site' });
  const datocmsConfig: SignedInProjectConfig = {
    ...baseConfig,
    providers: { datocms: builtInServices.datocms! },
    services: { datocms: true },
  };
  assert.deepEqual(evaluatePolicy(datocmsConfig, {
    interface: 'http', method: 'GET', path: '/site', providerId: 'datocms',
  }), {
    classification: 'read',
    effect: 'allow',
    matchedRules: ['signed-in:default-allow'],
    reason: 'Read operations are allowed.',
  });
  assert.deepEqual(evaluatePolicy(datocmsConfig, {
    interface: 'http', method: 'GET', path: '/access_tokens', providerId: 'datocms',
  }), {
    classification: 'credential-control',
    effect: 'deny',
    matchedRules: ['signed-in:credential-boundary'],
    reason: 'Credential creation, extraction, and replacement are outside the agent capability boundary.',
  });
  for (const service of Object.values(builtInServices)) {
    assert.ok(service.ping, `${service.label} needs an authentication probe`);
    if (service.cli) assert.ok(service.installHint, `${service.label} needs an installation remedy`);
  }
});

test('Cloudflare ping uses an OAuth-compatible authenticated user read', () => {
  assert.deepEqual(builtInServices.cloudflare?.ping, {
    interface: 'http',
    method: 'GET',
    path: '/client/v4/user',
  });
});

test('browser login extraction opens only trusted provider device flows', () => {
  assert.equal(
    findProviderLoginUrl('convex', 'Visit https://auth.convex.dev/device?user_code=SMWB-CDPD to finish logging in.'),
    'https://auth.convex.dev/device?user_code=SMWB-CDPD',
  );
  assert.equal(
    findProviderLoginUrl('github', 'Open this URL to continue in your web browser: https://github.com/login/device'),
    'https://github.com/login/device',
  );
  assert.equal(findProviderLoginUrl('convex', 'Visit https://evil.example/device?user_code=SMWB-CDPD'), undefined);
  assert.equal(findProviderLoginUrl('github', 'Open https://evil.example/login/device'), undefined);
  assert.equal(findProviderLoginUrl('clerk', 'Visit https://auth.convex.dev/device?user_code=SMWB-CDPD'), undefined);
});

test('credential prefix validation rejects a cross-service key before it reaches encrypted storage', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-credential-prefix-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const store = new MemorySecretStore();
  const service = new SignedInService(store, paths);
  assert.throws(
    () => service.putCredentials({ fields: { secretKey: 'prod:convex-key' }, providerId: 'clerk' }),
    (error: unknown) => error instanceof SignedInError
      && error.code === 'INVALID_FIELD'
      && error.message === 'Clerk secret key should start with sk_test_… or sk_live_…',
  );
  assert.equal(service.serviceStatuses().find((candidate) => candidate.id === 'clerk')?.accounts.length, 0);
  const timestamp = '2026-08-08T00:00:00.000Z';
  store.set(machineAccountsStoreKey(), {
    schemaVersion: 2,
    services: {
      clerk: {
        connections: {
          c_wrong_vendor: {
            alias: 'acme',
            aliasSource: 'operator',
            configuredFields: ['secretKey'],
            createdAt: timestamp,
            hasSession: false,
            updatedAt: timestamp,
          },
        },
        default: 'c_wrong_vendor',
      },
    },
  });
  store.set(connectionCredentialStoreKey('clerk', 'c_wrong_vendor'), {
    fields: { secretKey: 'prod:convex-key' },
    updatedAt: timestamp,
  });
  const legacyStatus = service.serviceStatuses().find((candidate) => candidate.id === 'clerk')?.accounts[0];
  assert.equal(legacyStatus?.state, 'needs-fields');
  assert.deepEqual(legacyStatus?.invalidFields, ['secretKey']);
});

test('provider output preserves split UTF-8 and signal exit status through redaction', { skip: process.platform === 'win32' }, async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-provider-stream-'));
  const executable = path.join(root, 'demo-provider');
  writeFileSync(executable, '#!/bin/sh\nprintf "\\360\\237"\nsleep 0.05\nprintf "\\230\\200"\nkill -TERM $$\n');
  chmodSync(executable, 0o755);
  const provider = {
    ...baseConfig.providers.demo!,
    cli: { command: executable, delivery: 'environment' as const, trustedExecutable: executable },
  };
  const stdout: Buffer[] = [];
  const result = await runProviderCommand({
    args: [],
    callbacks: { onStderr: () => undefined, onStdout: (chunk) => stdout.push(chunk) },
    config: { ...baseConfig, providers: { demo: provider } },
    credentials: { fields: { token: 'stored-secret' }, updatedAt: new Date().toISOString() },
    cwd: root,
    provider,
    providerId: 'demo',
  });
  assert.equal(Buffer.concat(stdout).toString('utf8'), '😀');
  assert.equal(result.exitCode, 143);
});

test('proxy-delivered CLIs cannot inherit adapter-cleared local profiles', { skip: process.platform === 'win32' }, async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-provider-profile-'));
  const executable = path.join(root, 'demo-provider');
  writeFileSync(executable, '#!/bin/sh\ntest -z "$SIGNED_IN_TEST_PROFILE"\n');
  chmodSync(executable, 0o755);
  const provider = {
    ...baseConfig.providers.demo!,
    cli: {
      clearEnv: ['SIGNED_IN_TEST_PROFILE'],
      command: executable,
      delivery: 'proxy' as const,
      trustedExecutable: executable,
    },
  };
  const previousProfile = process.env.SIGNED_IN_TEST_PROFILE;
  process.env.SIGNED_IN_TEST_PROFILE = 'local-profile';
  try {
    const result = await runProviderCommand({
      args: [],
      callbacks: { onStderr: () => undefined, onStdout: () => undefined },
      config: { ...baseConfig, providers: { demo: provider } },
      credentials: { fields: { token: 'stored-secret' }, updatedAt: new Date().toISOString() },
      cwd: root,
      provider,
      providerId: 'demo',
    });
    assert.equal(result.exitCode, 0);
  } finally {
    if (previousProfile === undefined) delete process.env.SIGNED_IN_TEST_PROFILE;
    else process.env.SIGNED_IN_TEST_PROFILE = previousProfile;
  }
});

test('session-delivered CLIs cannot inherit adapter-cleared authority flags', { skip: process.platform === 'win32' }, async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-session-profile-'));
  const executable = path.join(root, 'demo-provider');
  writeFileSync(executable, '#!/bin/sh\ntest -z "$SIGNED_IN_TEST_PROFILE"\n');
  chmodSync(executable, 0o755);
  const provider = {
    ...baseConfig.providers.demo!,
    cli: {
      clearEnv: ['SIGNED_IN_TEST_*'],
      command: executable,
      delivery: 'session' as const,
      trustedExecutable: executable,
    },
    session: { loginArgs: ['login'], retain: true },
  };
  const previousProfile = process.env.SIGNED_IN_TEST_PROFILE;
  process.env.SIGNED_IN_TEST_PROFILE = 'ambient-authority';
  try {
    const result = await runProviderCommand({
      args: [],
      callbacks: { onStderr: () => undefined, onStdout: () => undefined },
      config: { ...baseConfig, providers: { demo: provider } },
      credentials: { fields: { token: 'stored-secret' }, updatedAt: new Date().toISOString() },
      cwd: root,
      provider,
      providerId: 'demo',
      session: { files: [], updatedAt: new Date().toISOString() },
    });
    assert.equal(result.exitCode, 0);
  } finally {
    if (previousProfile === undefined) delete process.env.SIGNED_IN_TEST_PROFILE;
    else process.env.SIGNED_IN_TEST_PROFILE = previousProfile;
  }
});

test('connection aliases derive personal and organisation names from provider identities', () => {
  assert.deepEqual(deriveConnectionAlias('alex@gmail.com', 'primary', []), { alias: 'personal', source: 'domain' });
  assert.deepEqual(deriveConnectionAlias('alex@acme.example', 'primary', []), { alias: 'acme', source: 'domain' });
  assert.deepEqual(deriveConnectionAlias('all', 'primary', []), { alias: 'all-2', source: 'identity' });
  assert.deepEqual(deriveConnectionAlias('default', 'primary', []), { alias: 'default-2', source: 'identity' });
  assert.deepEqual(deriveConnectionAlias('alex@studio.co.nz', 'primary', []), { alias: 'studio', source: 'domain' });
  assert.deepEqual(deriveConnectionAlias('https://console.example.com/account', 'primary', []), { alias: 'example', source: 'domain' });
  assert.deepEqual(deriveConnectionAlias('octocat', 'primary', []), { alias: 'octocat', source: 'identity' });
  assert.deepEqual(deriveConnectionAlias('123456789012', 'primary', []), { alias: 'account-789012', source: 'identity' });
  assert.deepEqual(deriveConnectionAlias('alex@acme.example', 'primary', ['acme']), { alias: 'acme-2', source: 'domain' });
});

test('AWS browser login provisions a generic shareable IAM user into the encrypted connection', async () => {
  const browserCredentials = {
    fields: { accessKeyId: 'temporary-id', secretAccessKey: 'temporary-secret', sessionToken: 'temporary-session' },
    updatedAt: new Date().toISOString(),
  };
  const calls: string[][] = [];
  const result = await bootstrapAwsCredentials({
    browserCredentials,
    run: async (args, credentials) => {
      calls.push(args);
      const command = args.slice(0, 2).join(' ');
      if (command === 'sts get-caller-identity') {
        return credentials.fields.accessKeyId === 'durable-id'
          ? { Account: '123456789012', Arn: 'arn:aws:iam::123456789012:user/signed-in' }
          : { Account: '123456789012', Arn: 'arn:aws:iam::123456789012:root' };
      }
      if (command === 'iam list-account-aliases') return { AccountAliases: ['example-production'] };
      if (command === 'iam get-user') throw new Error('missing');
      if (command === 'iam list-access-keys') {
        return {
          AccessKeyMetadata: [
            { AccessKeyId: 'active-existing', CreateDate: '2026-01-01T00:00:00Z', Status: 'Active' },
            { AccessKeyId: 'inactive-existing', CreateDate: '2026-02-01T00:00:00Z', Status: 'Inactive' },
          ],
        };
      }
      if (command === 'iam create-access-key') {
        return { AccessKey: { AccessKeyId: 'durable-id', SecretAccessKey: 'durable-secret', UserName: 'signed-in' } };
      }
      return {};
    },
    wait: async () => undefined,
  });

  assert.equal(result.alias, 'example-production');
  assert.equal(result.userName, 'signed-in');
  assert.deepEqual(result.credentials.fields, { accessKeyId: 'durable-id', secretAccessKey: 'durable-secret' });
  assert.equal(calls.some((args) => args.slice(0, 2).join(' ') === 'iam create-user'), true);
  assert.equal(calls.some((args) => args.includes('attach-user-policy') && args.some((value) => value.endsWith('/AdministratorAccess'))), true);
  assert.equal(calls.some((args) => args.includes('delete-access-key') && args.includes('inactive-existing')), true);
  assert.equal(JSON.stringify(calls).includes('durable-secret'), false);
});

test('AWS accounts without provider aliases receive safe fallback connection names', async () => {
  const result = await bootstrapAwsCredentials({
    browserCredentials: {
      fields: { accessKeyId: 'temporary-id', secretAccessKey: 'temporary-secret', sessionToken: 'temporary-session' },
      updatedAt: new Date().toISOString(),
    },
    run: async (args, credentials) => {
      const command = args.slice(0, 2).join(' ');
      if (command === 'sts get-caller-identity') {
        return credentials.fields.accessKeyId === 'generated-id'
          ? { Account: '210987654321', Arn: 'arn:aws:iam::210987654321:user/signed-in' }
          : { Account: '210987654321', Arn: 'arn:aws:iam::210987654321:root' };
      }
      if (command === 'iam list-account-aliases') return { AccountAliases: [] };
      if (command === 'iam get-user') return { User: { UserName: 'signed-in' } };
      if (command === 'iam list-access-keys') return { AccessKeyMetadata: [] };
      if (command === 'iam create-access-key') {
        return { AccessKey: { AccessKeyId: 'generated-id', SecretAccessKey: 'generated-secret', UserName: 'signed-in' } };
      }
      return {};
    },
    wait: async () => undefined,
  });

  assert.equal(result.alias, 'account-654321');
  assert.equal(result.userName, 'signed-in');
  assert.equal(result.identity.includes('210987654321'), true);
});

test('AWS bootstrap reuses only a sealed key that proves the shared connection principal', async () => {
  const previousCredentials = {
    fields: { accessKeyId: 'sealed-id', secretAccessKey: 'sealed-secret' },
    updatedAt: new Date().toISOString(),
  };
  const calls: string[][] = [];
  const result = await bootstrapAwsCredentials({
    browserCredentials: {
      fields: { accessKeyId: 'temporary-id', secretAccessKey: 'temporary-secret', sessionToken: 'temporary-session' },
      updatedAt: new Date().toISOString(),
    },
    previousCredentials,
    run: async (args, credentials) => {
      calls.push(args);
      const command = args.slice(0, 2).join(' ');
      if (command === 'iam list-account-aliases') return { AccountAliases: ['team-account'] };
      if (command === 'sts get-caller-identity') {
        return credentials.fields.accessKeyId === 'sealed-id'
          ? { Account: '123456789012', Arn: 'arn:aws:iam::123456789012:user/signed-in' }
          : { Account: '123456789012', Arn: 'arn:aws:iam::123456789012:root' };
      }
      throw new Error(`Unexpected AWS bootstrap command: ${args.join(' ')}`);
    },
  });

  assert.equal(result.alias, 'team-account');
  assert.deepEqual(result.credentials, previousCredentials);
  assert.equal(calls.some((args) => args.includes('create-access-key')), false);
});

test('AWS bootstrap never rotates active shared keys that may be in use on another machine', async () => {
  const calls: string[][] = [];
  await assert.rejects(() => bootstrapAwsCredentials({
    browserCredentials: {
      fields: { accessKeyId: 'temporary-id', secretAccessKey: 'temporary-secret', sessionToken: 'temporary-session' },
      updatedAt: new Date().toISOString(),
    },
    run: async (args) => {
      calls.push(args);
      const command = args.slice(0, 2).join(' ');
      if (command === 'sts get-caller-identity') return { Account: '123456789012', Arn: 'arn:aws:iam::123456789012:root' };
      if (command === 'iam list-account-aliases') return { AccountAliases: ['team-account'] };
      if (command === 'iam get-user') return { User: { UserName: 'signed-in' } };
      if (command === 'iam list-access-keys') {
        return { AccessKeyMetadata: [
          { AccessKeyId: 'shared-one', Status: 'Active' },
          { AccessKeyId: 'shared-two', Status: 'Active' },
        ] };
      }
      return {};
    },
  }), /share an existing signed-in connection/iu);

  assert.equal(calls.some((args) => args.includes('delete-access-key')), false);
  assert.equal(calls.some((args) => args.includes('create-access-key')), false);
});

test('trusted config fingerprints are stable across object key order', () => {
  const reordered = {
    ...baseConfig,
    project: { name: 'Test Project', id: 'test-project' },
  };
  assert.equal(
    fingerprintProjectConfig(validateProjectConfig(baseConfig)),
    fingerprintProjectConfig(validateProjectConfig(reordered)),
  );
});

test('config rejects arbitrary interpreter commands', () => {
  assert.throws(() => validateProjectConfig({
    ...baseConfig,
    providers: { demo: { cli: { command: 'sh' }, label: 'Demo' } },
  }), /general-purpose interpreter/u);
  assert.throws(() => validateProjectConfig({
    ...baseConfig,
    providers: { demo: { cli: { command: 'pnpm' }, label: 'Demo' } },
  }), /package runner/u);
  assert.throws(() => validateProjectConfig({
    ...baseConfig,
    providers: {
      demo: {
        ...baseConfig.providers.demo!,
        cli: {
          command: 'demo',
          delivery: 'proxy',
          proxySocket: { configPath: '../outside', configTemplate: 'socket={socket}' },
        },
      },
    },
  }), /stay inside the command sandbox/u);
});

test('project contracts reject unsafe checks and targets unsupported by an adapter', () => {
  assert.throws(() => validateProjectConfig({
    ...baseConfig,
    services: { demo: { checks: [{ id: 'write', method: 'POST', path: '/records' }] } },
  }), /method must be GET or HEAD/u);
  assert.throws(() => validateProjectConfig({
    ...baseConfig,
    services: { demo: { checks: [{ id: 'escape', path: 'https:\/\/other.example.com\/me' }] } },
  }), /relative HTTP path/u);

  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-project-target-validation-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const service = new SignedInService(new MemorySecretStore(), paths);
  assert.throws(() => service.trustProject({
    approved: true,
    config: { ...baseConfig, services: { demo: { target: 'prod:example-123' } } },
    configPath: path.join(root, 'signed-in.config.json'),
    roots: [root],
  }), /does not define a project target/u);
});

test('project trust guides a missing named custom connection and seals it after sign-in', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-project-pending-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const service = new SignedInService(new MemorySecretStore(), paths);
  const config: SignedInProjectConfig = {
    ...baseConfig,
    services: { demo: { alias: 'acme-production', required: true } },
  };
  const pending = service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
  assert.deepEqual(pending.missing, [{ alias: 'acme-production', service: 'demo' }]);
  assert.deepEqual(service.describeProject('test-project').pendingConnections, ['demo']);

  service.putCredentials({ account: 'acme-production', fields: { token: 'pending-secret' }, projectId: 'test-project', providerId: 'demo' });
  const sealed = service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
  assert.deepEqual(sealed.missing, []);
  assert.ok(service.describeProject('test-project').connections?.demo);
  assert.equal(service.describeProject('test-project').pendingConnections, undefined);
});

test('policy denies credential minting and confirms destructive operations', () => {
  const mint = evaluatePolicy(baseConfig, {
    args: ['iam', 'create-access-key'],
    interface: 'native',
    projectId: 'test-project',
    providerId: 'demo',
  });
  assert.equal(mint.effect, 'deny');
  assert.equal(mint.classification, 'credential-control');

  const deletion = evaluatePolicy(baseConfig, {
    args: ['sites', 'delete', 'example'],
    interface: 'native',
    projectId: 'test-project',
    providerId: 'demo',
  });
  assert.equal(deletion.effect, 'confirm');
  assert.equal(deletion.classification, 'destructive');
  const hyphenatedDeletion = evaluatePolicy(baseConfig, {
    args: ['iam', 'delete-user', '--user-name', 'example'],
    interface: 'native',
    projectId: 'test-project',
    providerId: 'demo',
  });
  assert.equal(hyphenatedDeletion.effect, 'confirm');
});

test('Shopify scope grants require a terminal confirmation that project policy cannot weaken', () => {
  const shopifyConfig: SignedInProjectConfig = {
    ...baseConfig,
    policies: [{ effect: 'allow', id: 'project:allow-shopify', providers: ['shopify'], reason: 'Project allows Shopify commands.' }],
    providers: { shopify: builtInServices.shopify! },
    services: { shopify: true },
  };
  const grant = evaluatePolicy(shopifyConfig, {
    args: ['store', 'auth', '--store', 'example.myshopify.com', '--scopes=read_products,write_products'],
    interface: 'native',
    providerId: 'shopify',
  });
  assert.equal(grant.classification, 'mutation');
  assert.equal(grant.effect, 'confirm');
  assert.deepEqual(grant.matchedRules, ['signed-in:provider-confirmation']);

  const deniedGrant = evaluatePolicy({
    ...shopifyConfig,
    policies: [{ effect: 'deny', id: 'project:deny-shopify', providers: ['shopify'], reason: 'Project denies Shopify commands.' }],
  }, {
    args: ['store', 'auth', '--store', 'example.myshopify.com', '--scopes', 'read_products'],
    interface: 'native',
    providerId: 'shopify',
  });
  assert.equal(deniedGrant.effect, 'deny');
  assert.deepEqual(deniedGrant.matchedRules, ['project:deny-shopify']);

  const authList = evaluatePolicy(shopifyConfig, {
    args: ['store', 'auth', 'list', '--json'],
    interface: 'native',
    providerId: 'shopify',
  });
  assert.equal(authList.classification, 'read');
  assert.equal(authList.effect, 'allow');

  const mutation = evaluatePolicy(shopifyConfig, {
    args: ['store', 'execute', '--allow-mutations', '--query', 'mutation { example }'],
    interface: 'native',
    providerId: 'shopify',
  });
  assert.equal(mutation.classification, 'mutation');
});

test('policy denies credential endpoints even for GET requests', () => {
  const decision = evaluatePolicy(baseConfig, {
    interface: 'http',
    method: 'GET',
    path: '/v1/organization_access_tokens',
    projectId: 'test-project',
    providerId: 'demo',
  });
  assert.equal(decision.effect, 'deny');
  assert.equal(decision.classification, 'credential-control');
  const encoded = evaluatePolicy(baseConfig, {
    interface: 'http',
    method: 'POST',
    path: '/v1/api%2Dkeys',
    projectId: 'test-project',
    providerId: 'demo',
  });
  assert.equal(encoded.effect, 'deny');
});

test('stream redaction catches exact secrets split across chunks', () => {
  const secret = 'top-secret-value-123456789';
  const redactor = new StreamRedactor([secret]);
  const output = [
    redactor.push('before top-secret-'),
    redactor.push('value-123456789 after'),
    redactor.finish(),
  ].join('');
  assert.doesNotMatch(output, /top-secret|123456789/u);
  assert.match(output, /before/u);
  assert.match(output, /after/u);
});

test('stream redaction releases interactive prompts without waiting for process exit', () => {
  const redactor = new StreamRedactor(['known-secret-value']);
  assert.equal(redactor.push('Open browser now? '), '');
  assert.equal(redactor.flushPrompt(), 'Open browser now? ');
  assert.equal(redactor.finish(), '');
});

test('stream redaction releases GitHub device codes and browser instructions immediately', () => {
  const prompt = '! First copy your one-time code: ABCD-EFGH\nOpen this URL to continue in your web browser: https://github.com/login/device\n';
  const redactor = new StreamRedactor(['known-secret-value']);
  const output = `${redactor.push(prompt)}${redactor.flushPrompt()}`;
  assert.equal(output, prompt);
  assert.equal(redactor.finish(), '');
});

test('structured redaction removes newly returned token fields', () => {
  assert.deepEqual(redactStructured({
    id: 'safe-id',
    nested: { refresh_token: 'newly-minted-value' },
  }), {
    id: 'safe-id',
    nested: { refresh_token: '[REDACTED]' },
  });
});

test('pairing envelopes are destination-bound, signed, and tamper-evident', () => {
  const sender = createMachineIdentity('sender');
  const recipient = createMachineIdentity('recipient');
  const payload: PairingPayload = {
    credentials: [{ account: 'default', fields: { token: 'portable-secret' }, providerId: 'demo', updatedAt: new Date().toISOString() }],
    skipped: [],
  };
  const envelope = encryptPairingPayload(sender, publicMachineIdentity(recipient), payload);
  assert.deepEqual(decryptPairingEnvelope(recipient, envelope), payload);
  assert.throws(() => decryptPairingEnvelope(createMachineIdentity('wrong'), envelope), /different machine/u);
  assert.throws(() => decryptPairingEnvelope(recipient, {
    ...envelope,
    ciphertext: `${envelope.ciphertext.slice(0, -2)}AA`,
  }), /signature is invalid/u);
});

test('session bundles restore files under a private root', () => {
  const source = mkdtempSync(path.join(tmpdir(), 'signed-in-session-source-'));
  const destination = mkdtempSync(path.join(tmpdir(), 'signed-in-session-destination-'));
  mkdirSync(path.join(source, '.provider'), { recursive: true });
  mkdirSync(path.join(source, '.aws', 'login', 'cache'), { recursive: true });
  mkdirSync(path.join(source, '.cache'), { recursive: true });
  mkdirSync(path.join(source, '.npm', '_cacache'), { recursive: true });
  writeFileSync(path.join(source, '.provider', 'tokens.json'), '{"token":"session-secret"}', { mode: 0o600 });
  writeFileSync(path.join(source, '.aws', 'login', 'cache', 'session.json'), '{"token":"aws-login-secret"}', { mode: 0o600 });
  writeFileSync(path.join(source, '.cache', 'noise.json'), '{}', { mode: 0o600 });
  writeFileSync(path.join(source, '.npm', '_cacache', 'package.tgz'), 'disposable-package-cache', { mode: 0o600 });
  const bundle = snapshotBundle(source);
  materializeBundle(destination, bundle);
  assert.equal(readFileSync(path.join(destination, '.provider', 'tokens.json'), 'utf8'), '{"token":"session-secret"}');
  assert.equal(readFileSync(path.join(destination, '.aws', 'login', 'cache', 'session.json'), 'utf8'), '{"token":"aws-login-secret"}');
  assert.equal(bundle.files.some((file) => file.path === '.cache/noise.json'), false);
  assert.equal(bundle.files.some((file) => file.path.startsWith('.npm/')), false);
});

test('existing login capture copies only declared paths and rejects symlinks', { skip: process.platform === 'win32' }, () => {
  const home = mkdtempSync(path.join(tmpdir(), 'signed-in-existing-capture-'));
  mkdirSync(path.join(home, '.provider'), { recursive: true });
  mkdirSync(path.join(home, '.ssh'), { recursive: true });
  writeFileSync(path.join(home, '.provider', 'session.json'), '{"refresh":"private-session"}', { mode: 0o600 });
  writeFileSync(path.join(home, '.ssh', 'id_ed25519'), 'unrelated-private-key', { mode: 0o600 });

  const bundle = snapshotDeclaredPaths(home, [{ source: '.provider', target: '.isolated/provider' }]);

  assert.deepEqual(bundle.files.map((file) => file.path), ['.isolated/provider/session.json']);
  assert.doesNotMatch(JSON.stringify(bundle), /unrelated-private-key/u);
  symlinkSync(path.join(home, '.ssh', 'id_ed25519'), path.join(home, '.provider', 'linked-secret'));
  assert.throws(
    () => snapshotDeclaredPaths(home, [{ source: '.provider', target: '.provider' }]),
    /unsupported symlink/u,
  );
});

test('existing CLI discovery and adoption keep resolver secrets out of discovery results', { skip: process.platform === 'win32' }, async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-existing-runner-'));
  const home = path.join(root, 'home');
  const executable = path.join(root, 'demo-provider');
  mkdirSync(path.join(home, '.demo'), { recursive: true });
  writeFileSync(path.join(home, '.demo', 'token'), 'private-adopted-token');
  writeFileSync(executable, `#!/bin/sh
case "$1" in
  status) test -f "$HOME/.demo/token" ;;
  identity) printf 'alex@acme.example\\n' ;;
  token) cat "$HOME/.demo/token" ;;
  *) exit 1 ;;
esac
`);
  chmodSync(executable, 0o755);
  const provider = {
    cli: { command: executable, delivery: 'environment' as const, trustedExecutable: executable },
    credentials: [{ id: 'token', label: 'Token', secret: true }],
    existingLogin: { detectArgs: ['status'], identityArgs: ['identity'], source: 'demo' },
    label: 'Demo',
    session: {
      loginArgs: ['login'],
      resolvers: [{ args: ['token'], format: 'text' as const, persist: true, targetField: 'token' }],
      retain: false,
    },
  };
  const previousHome = process.env.HOME;
  process.env.HOME = home;
  try {
    const discovery = await discoverExistingProviderLogin({ cwd: root, provider });
    assert.deepEqual(discovery, { available: true, identity: 'alex@acme.example', source: 'demo' });
    assert.doesNotMatch(JSON.stringify(discovery), /private-adopted-token/u);
    const adopted = await adoptExistingProviderLogin({ cwd: root, provider });
    assert.equal(adopted.credentials.fields.token, 'private-adopted-token');
    assert.equal(adopted.clearSession, true);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
});

test('existing CLI discovery rejects a successful status command without copyable login state', { skip: process.platform === 'win32' }, async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-existing-empty-'));
  const home = path.join(root, 'home');
  const executable = path.join(root, 'demo-provider');
  mkdirSync(home, { recursive: true });
  writeFileSync(executable, '#!/bin/sh\nexit 0\n');
  chmodSync(executable, 0o755);
  const provider = {
    cli: { command: executable, delivery: 'session' as const, trustedExecutable: executable },
    existingLogin: {
      detectArgs: ['status'],
      paths: [{ source: '.demo', target: '.demo' }],
      source: 'demo',
    },
    label: 'Demo',
    session: { loginArgs: ['login'], retain: true },
  };
  const previousHome = process.env.HOME;
  process.env.HOME = home;
  try {
    assert.deepEqual(await discoverExistingProviderLogin({ cwd: root, provider }), {
      available: false,
      source: 'demo',
    });
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
});

test('existing CLI discovery rejects an empty required identity', { skip: process.platform === 'win32' }, async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-existing-no-identity-'));
  const executable = path.join(root, 'demo-provider');
  writeFileSync(executable, '#!/bin/sh\nexit 0\n');
  chmodSync(executable, 0o755);
  const provider = {
    cli: { command: executable, delivery: 'environment' as const, trustedExecutable: executable },
    existingLogin: { detectArgs: ['status'], identityArgs: ['identity'], source: 'demo' },
    label: 'Demo',
    session: { loginArgs: ['login'], retain: false },
  };

  assert.deepEqual(await discoverExistingProviderLogin({ cwd: root, provider }), {
    available: false,
    source: 'demo',
  });
});

test('service adoption assigns a domain alias, records provenance, and verifies the isolated copy', { skip: process.platform === 'win32' }, async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-existing-service-'));
  const home = path.join(root, 'operator-home');
  const executable = path.join(root, 'demo-provider');
  const paths = testPaths(root);
  mkdirSync(path.join(home, '.demo'), { recursive: true });
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  writeFileSync(path.join(home, '.demo', 'session.json'), '{"refresh":"private-session"}', { mode: 0o600 });
  writeFileSync(executable, `#!/bin/sh
case "$1" in
  status|ping) test -f "$HOME/.demo/session.json" ;;
  identity) printf 'alex@acme.example\\n' ;;
  *) exit 1 ;;
esac
`);
  chmodSync(executable, 0o755);
  const config: SignedInProjectConfig = {
    ...baseConfig,
    providers: {
      demo: {
        cli: { command: executable, delivery: 'session' },
        existingLogin: {
          detectArgs: ['status'],
          identityArgs: ['identity'],
          paths: [{ source: '.demo', target: '.demo' }],
          source: 'demo',
        },
        identityArgs: ['identity'],
        label: 'Demo',
        ping: { args: ['ping'], interface: 'native' },
        session: { loginArgs: ['login'], retain: true },
        signIn: 'interactive',
      },
    },
  };
  const store = new MemorySecretStore();
  const service = new SignedInService(store, paths);
  service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
  const previousHome = process.env.HOME;
  process.env.HOME = home;
  try {
    assert.deepEqual(await service.discoverExistingLogin({ cwd: root, projectId: 'test-project', providerId: 'demo' }), {
      available: true,
      identity: 'alex@acme.example',
      source: 'demo',
    });
    const adopted = await service.adoptExistingLogin({
      alias: 'primary',
      approved: true,
      callbacks: { onStderr: () => undefined, onStdout: () => undefined },
      cwd: root,
      projectId: 'test-project',
      providerId: 'demo',
    });
    assert.equal(adopted.status.account, 'acme');
    assert.equal(adopted.status.ready, true);
    assert.equal(adopted.status.identity, 'alex@acme.example');
    assert.equal(adopted.status.origin?.kind, 'adopted');
    assert.equal(adopted.status.origin?.source, 'demo');
    const session = store.get<{ files: Array<{ path: string }> }>(connectionSessionStoreKey('demo', adopted.status.connectionId));
    assert.deepEqual(session?.files.map((file) => file.path), ['.demo/session.json']);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
});

test('HTTP gateway treats JSON:API responses as text and redacts credential-shaped fields', async () => {
  const server = http.createServer((request, response) => {
    response.setHeader('content-type', 'application/vnd.api+json');
    response.end(JSON.stringify({ authorization: request.headers.authorization, id: 'safe', token: 'response-token-value' }));
  });
  await listen(server);
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  try {
    const response = await performGatewayRequest({
      body: Buffer.alloc(0),
      credentials: { token: 'gateway-secret-value' },
      gateway: {
        auth: { field: 'token', type: 'bearer' },
        baseUrl: `http://127.0.0.1:${address.port}`,
      },
      headers: {},
      method: 'GET',
      path: '/echo',
      secrets: ['gateway-secret-value'],
    });
    assert.equal(response.status, 200);
    assert.equal(response.bodyEncoding, 'utf8');
    assert.doesNotMatch(response.body, /gateway-secret-value|response-token-value/u);
    assert.deepEqual(JSON.parse(response.body), { authorization: '[REDACTED]', id: 'safe', token: '[REDACTED]' });
  } finally {
    await close(server);
  }
});

// Proves curl-style header casing cannot hide a JSON body behind a duplicated adapter default.
test('HTTP gateway forwards POST bodies with case-insensitive header overrides', async () => {
  let receivedBody = '';
  let receivedContentType: string | undefined;
  const server = http.createServer(async (request, response) => {
    receivedBody = (await readIncomingBody(request)).toString('utf8');
    receivedContentType = request.headers['content-type'];
    response.setHeader('content-type', 'application/json');
    response.end('{"success":true}');
  });
  await listen(server);
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  try {
    const body = Buffer.from('{"name":"publication-candidate"}', 'utf8');
    const response = await performGatewayRequest({
      body,
      credentials: { token: 'gateway-secret-value' },
      gateway: {
        auth: { field: 'token', type: 'bearer' },
        baseUrl: `http://127.0.0.1:${address.port}`,
        defaultHeaders: { 'content-type': 'application/problem+json' },
      },
      headers: { 'Content-Type': 'application/json' },
      method: 'POST',
      path: '/database',
      secrets: ['gateway-secret-value'],
    });
    assert.equal(response.status, 200);
    assert.equal(receivedBody, body.toString('utf8'));
    assert.equal(receivedContentType, 'application/json');
  } finally {
    await close(server);
  }
});

test('HTTP gateway follows only same-origin canonical redirects', async () => {
  const server = http.createServer((request, response) => {
    if (request.url === '/products') {
      response.writeHead(307, { location: '/products/' });
      response.end();
      return;
    }
    if (request.url === '/escape') {
      response.writeHead(307, { location: '/different' });
      response.end();
      return;
    }
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ authorization: request.headers.authorization, path: request.url }));
  });
  await listen(server);
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const options = {
    body: Buffer.alloc(0),
    credentials: { token: 'redirect-secret' },
    gateway: {
      auth: { field: 'token' as const, type: 'bearer' as const },
      baseUrl: `http://127.0.0.1:${address.port}`,
    },
    headers: {},
    method: 'GET',
    secrets: ['redirect-secret'],
  };
  try {
    const response = await performGatewayRequest({ ...options, path: '/products' });
    assert.equal(response.status, 200);
    assert.deepEqual(JSON.parse(response.body), { authorization: '[REDACTED]', path: '/products/' });
    await assert.rejects(
      performGatewayRequest({ ...options, path: '/escape' }),
      /outside the approved canonical endpoint/iu,
    );
  } finally {
    await close(server);
  }
});

test('service HTTP ping proves authority without returning the provider response', async () => {
  let rejectAuthentication = false;
  const server = http.createServer((request, response) => {
    if (request.url === '/unauthorized' || rejectAuthentication) response.statusCode = 401;
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ authorization: request.headers.authorization, private: 'provider-body' }));
  });
  await listen(server);
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-http-ping-'));
  const executable = path.join(root, process.platform === 'win32' ? 'demo-provider.exe' : 'demo-provider');
  if (process.platform === 'win32') copyFileSync(process.execPath, executable);
  else {
    writeFileSync(executable, '#!/bin/sh\nexit 0\n');
    chmodSync(executable, 0o755);
  }
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const service = new SignedInService(new MemorySecretStore(), paths);
  const config: SignedInProjectConfig = {
    ...baseConfig,
    providers: {
      demo: {
        ...baseConfig.providers.demo!,
        cli: { command: executable, delivery: 'environment' },
        http: { ...baseConfig.providers.demo!.http!, baseUrl: `http://127.0.0.1:${address.port}` },
        ping: { interface: 'http', method: 'GET', path: '/me' },
        target: { env: 'DEMO_DEPLOYMENT', label: 'deployment' },
      },
    },
  };
  try {
    service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
    service.putCredentials({ fields: { token: 'ping-secret' }, projectId: 'test-project', providerId: 'demo' });
    const result = await service.pingService({ cwd: root, projectId: 'test-project', providerId: 'demo' });
    assert.equal(result.account, 'primary');
    assert.equal(result.interface, 'http');
    assert.equal(result.ok, true);
    assert.equal(result.status, 200);
    assert.deepEqual(result.target, { label: 'deployment', value: null });
    assert.doesNotMatch(JSON.stringify(result), /ping-secret|provider-body/u);
    const denied = await service.request({ method: 'GET', path: '/unauthorized', projectId: 'test-project', providerId: 'demo' });
    assert.equal(denied.response.status, 401);
    assert.equal(service.serviceStatuses('test-project').find((status) => status.id === 'demo')?.state, 'connected');
    rejectAuthentication = true;
    await assert.rejects(
      service.request({ method: 'GET', path: '/expired', projectId: 'test-project', providerId: 'demo' }),
      (error: unknown) => error instanceof SignedInError
        && error.code === 'AUTH_REQUIRED'
        && error.message === 'Demo rejected the stored credential'
        && (error.details as { cause?: unknown })?.cause === 'credential-rejected'
        && (error.details as { remedy?: unknown })?.remedy === 'signed-in login demo@primary',
    );
    const rejectionReceipt = service.readAudit().at(-1) as { errorCode?: string };
    assert.equal(rejectionReceipt.errorCode, 'AUTH_REQUIRED');
  } finally {
    await close(server);
  }
});

test('service native ping suppresses provider output while preserving its exit proof', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-native-ping-'));
  const executable = path.join(root, process.platform === 'win32' ? 'demo-provider.exe' : 'demo-provider');
  const providerScript = path.join(root, 'demo-provider.cjs');
  if (process.platform === 'win32') {
    copyFileSync(process.execPath, executable);
    writeFileSync(providerScript, 'process.stdout.write("provider-private-output");\nprocess.exit(process.argv[2] === "whoami" && process.env.DEMO_TOKEN === "ping-secret" ? 0 : 1);\n');
  } else {
    writeFileSync(executable, '#!/bin/sh\nprintf "provider-private-output"\ntest "$1" = "whoami" && test "$DEMO_TOKEN" = "ping-secret"\n');
    chmodSync(executable, 0o755);
  }
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const service = new SignedInService(new MemorySecretStore(), paths);
  const config: SignedInProjectConfig = {
    ...baseConfig,
    providers: {
      demo: {
        ...baseConfig.providers.demo!,
        cli: {
          command: executable,
          delivery: 'environment',
          ...(process.platform === 'win32' ? { prefixArgs: [providerScript] } : {}),
        },
        ping: { args: ['whoami'], interface: 'native' },
      },
    },
  };
  service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
  service.putCredentials({ fields: { token: 'ping-secret' }, projectId: 'test-project', providerId: 'demo' });
  const result = await service.pingService({ cwd: root, projectId: 'test-project', providerId: 'demo' });
  assert.equal(result.interface, 'native');
  assert.equal(result.exitCode, 0);
  assert.equal(result.ok, true);
  assert.doesNotMatch(JSON.stringify(result), /ping-secret|provider-private-output/u);
  service.putCredentials({
    account: 'primary', approved: true, fields: { token: 'expired-secret' }, projectId: 'test-project', providerId: 'demo', replace: true,
  });
  await assert.rejects(
    service.pingService({ cwd: root, projectId: 'test-project', providerId: 'demo' }),
    (error: unknown) => error instanceof SignedInError
      && error.code === 'AUTH_REQUIRED'
      && (error.details as { remedy?: unknown })?.remedy === 'signed-in login demo@primary',
  );
});

test('project targets reach the provider CLI through its catalog-declared environment only', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-project-target-'));
  const executable = path.join(root, process.platform === 'win32' ? 'target-provider.exe' : 'target-provider');
  const providerScript = path.join(root, 'target-provider.cjs');
  if (process.platform === 'win32') {
    copyFileSync(process.execPath, executable);
    writeFileSync(providerScript, 'process.exit(process.env.DEMO_DEPLOYMENT === "prod:example-deployment-123" ? 0 : 1);\n');
  } else {
    writeFileSync(executable, '#!/bin/sh\ntest "$DEMO_DEPLOYMENT" = "prod:example-deployment-123"\n');
    chmodSync(executable, 0o755);
  }
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const service = new SignedInService(new MemorySecretStore(), paths);
  const config: SignedInProjectConfig = {
    ...baseConfig,
    providers: {
      demo: {
        ...baseConfig.providers.demo!,
        cli: {
          command: executable,
          delivery: 'environment',
          ...(process.platform === 'win32' ? { prefixArgs: [providerScript] } : {}),
        },
        ping: { args: ['whoami'], interface: 'native' },
        target: { env: 'DEMO_DEPLOYMENT', label: 'deployment', pattern: '^prod:[a-z0-9-]+$' },
      },
    },
    services: { demo: { target: 'prod:example-deployment-123' } },
  };
  service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
  service.putCredentials({ fields: { token: 'target-secret' }, projectId: 'test-project', providerId: 'demo' });
  const result = await service.pingService({ cwd: root, projectId: 'test-project', providerId: 'demo' });
  assert.equal(result.ok, true);
  assert.deepEqual(result.target, { label: 'deployment', value: 'prod:example-deployment-123' });
  const verification = await service.verifyProject({ cwd: root, projectId: 'test-project', providerId: 'demo' });
  assert.deepEqual(verification.services[0]?.target, { label: 'deployment', value: 'prod:example-deployment-123' });
});

test('project verification enforces identity and reports insufficient capability without returning bodies', async () => {
  const server = http.createServer((request, response) => {
    response.setHeader('content-type', 'application/json');
    response.statusCode = request.url === '/forbidden' ? 403 : 200;
    response.end(JSON.stringify({ private: 'verification-body' }));
  });
  await listen(server);
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-project-verify-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const store = new MemorySecretStore();
  const service = new SignedInService(store, paths);
  const config: SignedInProjectConfig = {
    ...baseConfig,
    providers: {
      demo: {
        ...baseConfig.providers.demo!,
        http: { ...baseConfig.providers.demo!.http!, baseUrl: `http://127.0.0.1:${address.port}` },
        ping: { interface: 'http', path: '/me' },
      },
    },
    services: {
      demo: {
        alias: 'acme-production',
        checks: [
          { id: 'read-data', label: 'Read data', path: '/data' },
          { id: 'read-issues', label: 'Read issues', path: '/forbidden' },
        ],
        expectedIdentity: 'acme-production-tenant',
      },
    },
  };
  try {
    const pending = service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
    assert.equal(pending.missing.length, 1);
    service.putCredentials({ account: 'acme-production', fields: { token: 'verify-secret' }, projectId: 'test-project', providerId: 'demo' });
    assert.throws(
      () => service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] }),
      (error: unknown) => error instanceof SignedInError && error.code === 'AUTH_REQUIRED' && /no verified identity/u.test(error.message),
    );
    const accounts = store.get<MachineConnections>(machineAccountsStoreKey())!;
    const connection = Object.values(accounts.services.demo!.connections)[0]!;
    connection.identity = 'acme-production · acme-production-tenant · provider-principal';
    store.set(machineAccountsStoreKey(), accounts);
    service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
    const result = await service.verifyProject({ cwd: root, projectId: 'test-project' });
    assert.equal(result.ok, false);
    assert.equal(result.services[0]?.identity, 'acme-production · acme-production-tenant · provider-principal');
    assert.deepEqual(result.services[0]?.checks.map((check) => [check.id, check.status, check.ok]), [
      ['read-data', 200, true],
      ['read-issues', 403, false],
    ]);
    assert.doesNotMatch(JSON.stringify(result), /verify-secret|verification-body/u);
  } finally {
    await close(server);
  }
});

test('HTTP gateway aborts an in-flight authenticated request when its client disconnects', async () => {
  const server = http.createServer(() => undefined);
  await listen(server);
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const controller = new AbortController();
  try {
    const request = performGatewayRequest({
      body: Buffer.alloc(0),
      credentials: { token: 'gateway-secret-value' },
      gateway: {
        auth: { field: 'token', type: 'bearer' },
        baseUrl: `http://127.0.0.1:${address.port}`,
      },
      headers: {},
      method: 'GET',
      path: '/wait',
      secrets: ['gateway-secret-value'],
      signal: controller.signal,
    });
    controller.abort();
    await assert.rejects(request, /abort/iu);
  } finally {
    await close(server);
  }
});

test('AWS authentication replaces dummy signatures and can sign direct gateway requests', () => {
  const auth = {
    accessKeyField: 'accessKeyId',
    defaultRegion: 'us-east-1',
    defaultService: 'sts',
    secretKeyField: 'secretAccessKey',
    sessionTokenField: 'sessionToken',
    type: 'aws-sigv4' as const,
  };
  const credentials = {
    accessKeyId: 'REALACCESSKEY',
    secretAccessKey: 'real-secret-key',
    sessionToken: 'real-session-token',
  };
  const direct = authenticateHeaders(auth, credentials, 'POST', new URL('https://sts.amazonaws.com/'), {}, Buffer.alloc(0));
  assert.match(direct.authorization ?? '', /Credential=REALACCESSKEY\/\d{8}\/us-east-1\/sts\/aws4_request/u);
  const proxied = authenticateHeaders(auth, credentials, 'GET', new URL('https://s3.us-west-2.amazonaws.com/'), {
    authorization: 'AWS4-HMAC-SHA256 Credential=DUMMY/20260804/us-west-2/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=dummy',
    'x-amz-date': '20260804T000000Z',
  }, Buffer.alloc(0));
  assert.match(proxied.authorization ?? '', /Credential=REALACCESSKEY\/20260804\/us-west-2\/s3\/aws4_request/u);
  assert.doesNotMatch(proxied.authorization ?? '', /DUMMY|real-secret-key/u);
});

test('HTTP authentication supports empty-password Basic auth and just-in-time App Store JWTs', () => {
  const basic = authenticateHeaders({
    password: 'empty',
    type: 'basic',
    usernameField: 'secretKey',
  }, { secretKey: 'stripe-key' }, 'GET', new URL('https://api.stripe.com/v1/customers'), {}, Buffer.alloc(0));
  assert.equal(basic.authorization, `Basic ${Buffer.from('stripe-key:', 'utf8').toString('base64')}`);

  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privateKey = pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  const apple = authenticateHeaders({
    issuerField: 'issuerId',
    keyIdField: 'keyId',
    privateKeyField: 'privateKey',
    type: 'apple-connect-jwt',
  }, {
    issuerId: 'issuer-id',
    keyId: 'key-id',
    privateKey,
  }, 'GET', new URL('https://api.appstoreconnect.apple.com/v1/apps'), {}, Buffer.alloc(0));
  assert.equal(apple.authorization?.startsWith('Bearer '), true);
  assert.equal(apple.authorization?.slice('Bearer '.length).split('.').length, 3);
  assert.doesNotMatch(apple.authorization ?? '', /PRIVATE KEY/u);
});

test('native credential proxy replaces dummy auth after TLS and redacts the upstream response', async () => {
  const certificate = createSelfSignedCertificate('localhost');
  const upstream = https.createServer(certificate, (request, response) => {
    response.setHeader('content-type', 'application/json');
    response.setHeader('transfer-encoding', 'chunked');
    response.write(`{"authorization":${JSON.stringify(request.headers.authorization)},"ok":`);
    response.end('true}');
  });
  await listen(upstream);
  const address = upstream.address();
  assert.ok(address && typeof address !== 'string');
  const proxy = await startCredentialProxy({
    credentials: { token: 'real-proxy-secret' },
    gateway: {
      auth: { field: 'token', type: 'bearer' },
      baseUrl: `https://localhost:${address.port}`,
    },
    secrets: ['real-proxy-secret'],
    upstreamCa: certificate.cert,
  });
  try {
    const serial = new X509Certificate(proxy.caCertificate).serialNumber.replaceAll(':', '');
    assert.ok(Number.parseInt(serial[0] ?? 'f', 16) < 8, `ephemeral CA serial must be positive: ${serial}`);
    const response = await requestThroughConnectProxy(proxy.url, proxy.caCertificate, `localhost:${address.port}`);
    assert.match(response, /200 OK/u);
    assert.doesNotMatch(response, /transfer-encoding:/iu);
    assert.match(response, /content-length:/iu);
    assert.match(response, /\[REDACTED\]/u);
    assert.doesNotMatch(response, /real-proxy-secret|dummy-value/u);
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

test('native credential socket replaces dummy auth without exposing a custom CA', { skip: process.platform === 'win32' }, async () => {
  const certificate = createSelfSignedCertificate('localhost');
  const upstream = https.createServer(certificate, (request, response) => {
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ authorization: request.headers.authorization, ok: true }));
  });
  await listen(upstream);
  const address = upstream.address();
  assert.ok(address && typeof address !== 'string');
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-native-socket-'));
  const socketPath = path.join(root, 'provider.sock');
  const proxy = await startCredentialSocketProxy({
    credentials: { token: 'real-socket-secret' },
    gateway: {
      auth: { field: 'token', type: 'bearer' },
      baseUrl: `https://localhost:${address.port}`,
    },
    secrets: ['real-socket-secret'],
    upstreamCa: certificate.cert,
  }, socketPath);
  try {
    const response = await requestThroughUnixSocket(socketPath, `localhost:${address.port}`);
    assert.equal(response.statusCode, 200);
    assert.match(response.body, /\[REDACTED\]/u);
    assert.doesNotMatch(response.body, /real-socket-secret|dummy-value/u);
  } finally {
    await proxy.close();
    await close(upstream);
  }
});

test('service never exposes stored values and pairs only portable shared credentials', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-service-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const store = new MemorySecretStore();
  const service = new SignedInService(store, paths);
  assert.throws(() => service.trustProject({
    config: baseConfig,
    configPath: path.join(root, 'signed-in.config.json'),
    roots: [root],
  }), /trust reviewed bindings/iu);
  service.trustProject({
    approved: true,
    config: baseConfig,
    configPath: path.join(root, 'signed-in.config.json'),
    roots: [root],
  });
  assert.equal(service.doctor('test-project').project?.configDrift, true);
  const status = service.putCredentials({
    account: 'default',
    fields: { token: 'stored-secret' },
    projectId: 'test-project',
    providerId: 'demo',
  });
  assert.deepEqual(status.configuredFields, ['token']);
  assert.equal(JSON.stringify(status).includes('stored-secret'), false);
  const awsStatus = service.putCredentials({
    account: 'team-account',
    fields: { accessKeyId: 'shared-aws-id', secretAccessKey: 'shared-aws-secret' },
    providerId: 'aws',
  });
  assert.equal(awsStatus.httpReady, true);
  const datocmsStatus = service.putCredentials({
    account: 'website',
    fields: { apiToken: 'datocms-test-token' },
    providerId: 'datocms',
  });
  assert.equal(datocmsStatus.httpReady, true);
  assert.deepEqual(datocmsStatus.configuredFields, ['apiToken']);

  const destination = createMachineIdentity('destination');
  assert.throws(() => service.exportPairing({
    recipient: encodeIdentity(publicMachineIdentity(destination)),
  }), /share portable connections/iu);
  const exported = service.exportPairing({
    approved: true,
    recipient: encodeIdentity(publicMachineIdentity(destination)),
  });
  assert.equal(JSON.stringify(exported).includes('stored-secret'), false);
  const decrypted = decryptPairingEnvelope(destination, exported.envelope);
  assert.equal(decrypted.credentials[0]?.fields.token, 'stored-secret');
  assert.deepEqual(decrypted.credentials.find((entry) => entry.providerId === 'aws')?.fields, {
    accessKeyId: 'shared-aws-id',
    secretAccessKey: 'shared-aws-secret',
  });
  assert.deepEqual(decrypted.credentials.find((entry) => entry.providerId === 'datocms')?.fields, {
    apiToken: 'datocms-test-token',
  });

  const durableExecutable = path.join(root, process.platform === 'win32' ? 'demo-provider.cmd' : 'demo-provider');
  writeFileSync(durableExecutable, process.platform === 'win32' ? '@exit /b 0\r\n' : '#!/bin/sh\nexit 0\n');
  chmodSync(durableExecutable, 0o755);
  const durableConfig: SignedInProjectConfig = {
    ...baseConfig,
    project: { id: 'durable-project', name: 'Durable Project' },
    providers: {
      demo: {
        ...baseConfig.providers.demo!,
        cli: { command: durableExecutable, delivery: 'proxy' },
        signIn: 'manual',
        session: {
          loginArgs: ['login'],
          resolvers: [{ args: [], format: 'text', persist: true, targetField: 'token' }],
          retain: false,
        },
      },
    },
  };
  service.trustProject({
    approved: true,
    config: durableConfig,
    configPath: path.join(root, 'durable.config.json'),
    roots: [root],
  });
  assert.equal(store.has(binaryPinStoreKey('demo')), true);
  const durableStatus = service.putCredentials({
    account: 'default',
    approved: true,
    fields: { token: 'durable-secret' },
    projectId: 'durable-project',
    providerId: 'demo',
  });
  assert.equal(durableStatus.sessionReady, false);
  assert.equal(durableStatus.httpReady, true);
});

test('project trust rejects unknown service bindings before sealing them', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-project-unknown-service-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const service = new SignedInService(new MemorySecretStore(), paths);
  assert.throws(() => service.trustProject({
    approved: true,
    config: { ...baseConfig, providers: {}, services: { clrek: true } },
    configPath: path.join(root, 'signed-in.config.json'),
    roots: [root],
  }), /unknown service 'clrek'/iu);
});

test('a project cannot implicitly approve a provider CLI installed after trust', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-project-late-cli-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const service = new SignedInService(new MemorySecretStore(), paths);
  const config: SignedInProjectConfig = {
    ...baseConfig,
    providers: {
      demo: {
        ...baseConfig.providers.demo!,
        cli: { command: path.join(root, 'not-installed-yet'), delivery: 'environment' },
      },
    },
  };
  service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
  service.putCredentials({ account: 'default', fields: { token: 'stored-secret' }, projectId: 'test-project', providerId: 'demo' });
  await assert.rejects(
    service.runNative({ args: [], cwd: root, projectId: 'test-project', providerId: 'demo' }, { onStderr: () => undefined, onStdout: () => undefined }),
    (error: unknown) => error instanceof SignedInError
      && error.code === 'BINARY_NOT_APPROVED'
      && (error.details as { remedy?: string }).remedy === 'signed-in trust demo',
  );
});

test('manual reconnect replaces stale optional credential fields and keeps usable HTTP access ready', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-credential-replace-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const store = new MemorySecretStore();
  const service = new SignedInService(store, paths);
  const initial = service.putCredentials({
    account: 'work',
    fields: { accessKeyId: 'temporary-id', secretAccessKey: 'temporary-secret', sessionToken: 'stale-session' },
    providerId: 'aws',
  });
  const previousPath = process.env.PATH;
  process.env.PATH = '';
  try {
    const replaced = service.putCredentials({
      account: 'work',
      approved: true,
      fields: { accessKeyId: 'durable-id', secretAccessKey: 'durable-secret' },
      providerId: 'aws',
      replace: true,
    });
    assert.deepEqual(store.get<{ fields: Record<string, string> }>(connectionCredentialStoreKey('aws', initial.connectionId))?.fields, {
      accessKeyId: 'durable-id',
      secretAccessKey: 'durable-secret',
    });
    assert.equal(replaced.httpReady, true);
    assert.equal(replaced.nativeReady, false);
    assert.equal(replaced.nativeRemedy, builtInServices.aws!.installHint);
    assert.equal(replaced.ready, true);
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
  }
});

test('first accounts are login-first while changing the machine default is confirmation-gated', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-accounts-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const service = new SignedInService(new MemorySecretStore(), paths);
  service.putCredentials({ account: 'default', fields: { apiKey: 'first-secret' }, providerId: 'resend' });
  service.putCredentials({ account: 'work', fields: { apiKey: 'second-secret' }, providerId: 'resend' });
  assert.throws(() => service.useAccount({ account: 'work', providerId: 'resend' }), /use resend@work/iu);
  assert.deepEqual(service.useAccount({ account: 'work', approved: true, providerId: 'resend' }), {
    changed: true,
    previous: 'primary',
  });
  const statuses = service.serviceStatuses().find((candidate) => candidate.id === 'resend');
  assert.equal(statuses?.accounts.find((candidate) => candidate.account === 'work')?.default, true);
});

test('renaming an alias preserves stored authority and sealed project connection identity', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-alias-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const store = new MemorySecretStore();
  const service = new SignedInService(store, paths);
  service.putCredentials({ account: 'work', fields: { apiKey: 'work-secret' }, providerId: 'resend' });
  const config: SignedInProjectConfig = { ...baseConfig, providers: {}, services: { resend: { alias: 'work', required: true } } };
  service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
  const before = service.serviceStatuses('test-project').find((candidate) => candidate.id === 'resend')?.accounts[0];
  assert.ok(before);
  assert.equal(service.renameAccount({ account: 'work', approved: true, newName: 'acme', providerId: 'resend' }).projects[0]?.name, 'Test Project');
  const after = service.serviceStatuses('test-project').find((candidate) => candidate.id === 'resend')?.accounts[0];
  assert.ok(after);
  assert.equal(after.account, 'acme');
  assert.equal(after.connectionId, before.connectionId);
  assert.equal(service.describeProject('test-project').connections?.resend, before.connectionId);
  assert.deepEqual(service.describeProject('test-project').config.services.resend, { alias: 'work', required: true });
  assert.equal(store.has(connectionCredentialStoreKey('resend', before.connectionId)), true);
});

test('a removed sealed connection cannot redirect a project through a reused alias', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-removed-connection-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const service = new SignedInService(new MemorySecretStore(), paths);
  service.putCredentials({ account: 'work', fields: { apiKey: 'first-secret' }, providerId: 'resend' });
  const config: SignedInProjectConfig = { ...baseConfig, providers: {}, services: { resend: 'work' } };
  service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
  service.logoutProvider({ account: 'work', approved: true, providerId: 'resend' });
  service.putCredentials({ account: 'work', fields: { apiKey: 'replacement-secret' }, providerId: 'resend' });

  const status = service.serviceStatuses('test-project').find((candidate) => candidate.id === 'resend');
  assert.equal(status?.projectConnectionMissing, true);
  await assert.rejects(
    service.request({ method: 'GET', path: '/domains', projectId: 'test-project', providerId: 'resend' }),
    (error: unknown) => error instanceof SignedInError && error.code === 'PROJECT_CONNECTION_MISSING',
  );
});

// Reproduces Shopify's device-auth CI gate through piped subprocesses and checks that ordinary commands stay unattended.
test('Shopify browser login permits device authorization without enabling runtime prompts or upgrades', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-shopify-login-'));
  const executable = path.join(root, 'shopify-fixture.cjs');
  writeFileSync(executable, `
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
const settings = path.join(process.env.HOME, 'upgrade-disabled');
const session = path.join(process.env.HOME, 'fixture-session');
assert.equal(process.stdin.isTTY, undefined);
assert.equal(process.env.SHOPIFY_CLI_NO_ANALYTICS, '1');
if (args[0] === 'config') {
  assert.deepEqual(args, ['config', 'autoupgrade', 'off']);
  assert.equal(process.env.CI, '1');
  fs.writeFileSync(settings, 'disabled');
} else if (args[0] === 'auth') {
  assert.deepEqual(args, ['auth', 'login', '--alias', 'signed-in']);
  if (['1', 'true'].includes(process.env.CI)) {
    process.stderr.write('Authorization is required to continue, but the current environment does not support interactive prompts.');
    process.exit(1);
  }
  assert.equal(fs.readFileSync(settings, 'utf8'), 'disabled');
  assert.equal(process.env.SHOPIFY_CLI_FORCE_AUTO_UPGRADE, '0');
  fs.writeFileSync(session, 'fixture');
  process.stdout.write('Device authorization available\\n');
} else {
  assert.deepEqual(args, ['organization', 'list', '--json']);
  assert.equal(process.env.CI, '1');
  assert.equal(fs.readFileSync(session, 'utf8'), 'fixture');
  process.stdout.write('[]\\n');
}
`);
  const provider = {
    ...builtInServices.shopify!,
    cli: { ...builtInServices.shopify!.cli!, prefixArgs: [executable], trustedExecutable: process.execPath },
  };
  const originalCi = process.env.CI;
  try {
    for (const remote of [false, true]) {
      const output: Buffer[] = [];
      const errors: Buffer[] = [];
      const callbacks = { onStderr: (chunk: Buffer) => errors.push(chunk), onStdout: (chunk: Buffer) => output.push(chunk) };
      const login = await runProviderLogin({
        callbacks,
        credentials: { fields: {}, updatedAt: new Date().toISOString() },
        cwd: root,
        provider,
        remote,
      });
      assert.equal(login.exitCode, 0, Buffer.concat(errors).toString());
      assert.match(Buffer.concat(output).toString(), /Device authorization available/u);
      const command = await runProviderCommand({
        args: ['organization', 'list', '--json'],
        callbacks,
        config: baseConfig,
        credentials: login.credentials,
        cwd: root,
        provider,
        providerId: 'shopify',
        session: login.session,
      });
      assert.equal(command.exitCode, 0, Buffer.concat(errors).toString());
      assert.equal(process.env.CI, originalCi);
    }
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

// Holds the provider open until its code reaches the caller, so a post-exit flush cannot pass as timely login output.
test('Shopify verification codes reach the caller before browser approval completes', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-shopify-code-'));
  const executable = path.join(root, 'shopify-code-fixture.cjs');
  writeFileSync(executable, `
const assert = require('node:assert/strict');
if (process.argv[2] === 'config') process.exit(0);
const output = process.env.FIXTURE_LOGIN_STREAM === 'stderr' ? process.stderr : process.stdout;
// Makes delayed output fail while keeping a broken test from leaving a provider process running.
const timeout = setTimeout(() => process.exit(1), 5000);
// Finishes the simulated browser approval only after the caller has received the complete verification code.
process.stdin.once('data', (chunk) => {
  assert.equal(chunk.toString(), 'verified\\n');
  clearTimeout(timeout);
  process.stdout.write('Login completed\\n');
  process.stdin.pause();
});
output.write('User verification code: ABCD-');
// Splits the code across output chunks to exercise the same stream boundary as a real provider CLI.
setTimeout(() => output.write('EFGH\\n'), 20);
`);
  try {
    for (const stream of ['stdout', 'stderr']) {
      let child: import('node:child_process').ChildProcessWithoutNullStreams | undefined;
      let output = '';
      let codeReceived = false;
      // Acknowledges only the complete displayed code, rather than releasing the provider on a timer.
      const observe = (chunk: Buffer): void => {
        output += chunk.toString();
        if (!codeReceived && output.includes('User verification code: ABCD-EFGH\n')) {
          codeReceived = true;
          if (child && !child.stdin.destroyed) child.stdin.end('verified\n');
        }
      };
      const result = await runProviderLogin({
        callbacks: {
          // Tracks the login subprocess after the short setup command has exited.
          onChild: (current) => { child = current; },
          onStderr: observe,
          onStdout: observe,
        },
        credentials: { fields: { token: 'synthetic-session-secret'.repeat(100) }, updatedAt: new Date().toISOString() },
        cwd: root,
        provider: {
          ...builtInServices.shopify!,
          cli: { ...builtInServices.shopify!.cli!, prefixArgs: [executable], trustedExecutable: process.execPath },
          session: {
            ...builtInServices.shopify!.session!,
            env: { ...builtInServices.shopify!.session!.env, FIXTURE_LOGIN_STREAM: stream },
          },
        },
        remote: stream === 'stderr',
      });
      assert.equal(result.exitCode, 0, `${stream} held the verification code until the provider timed out`);
      assert.equal(codeReceived, true);
      assert.match(output, /Login completed/u);
    }
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test('a failed first provider login leaves no unnamed ghost connection', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-failed-login-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const service = new SignedInService(new MemorySecretStore(), paths);
  const config: SignedInProjectConfig = {
    ...baseConfig,
    providers: {
      demo: {
        ...baseConfig.providers.demo!,
        cli: { command: 'false', delivery: 'session' },
        session: { loginArgs: ['login'], retain: true },
        signIn: 'interactive',
      },
    },
  };
  service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });

  const result = await service.loginProvider({
    alias: 'work',
    callbacks: { onStderr: () => undefined, onStdout: () => undefined },
    cwd: root,
    projectId: 'test-project',
    providerId: 'demo',
  });

  assert.equal(result.exitCode, 1);
  assert.equal(result.status, undefined);
  assert.equal(service.serviceStatuses('test-project').find((candidate) => candidate.id === 'demo')?.accounts.length, 0);
});

test('an expired refresh session becomes an exit-75 recovery state for the next login', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-expired-session-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const store = new MemorySecretStore();
  const service = new SignedInService(store, paths);
  const config: SignedInProjectConfig = {
    ...baseConfig,
    providers: {
      demo: {
        ...baseConfig.providers.demo!,
        cli: { command: 'false', delivery: 'proxy' },
        session: {
          loginArgs: ['login'],
          resolvers: [{ args: [], format: 'text', persist: false, targetField: 'token' }],
        },
        signIn: 'interactive',
      },
    },
  };
  service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
  const connection = service.putCredentials({ account: 'default', fields: { token: 'expired' }, projectId: 'test-project', providerId: 'demo' });
  store.set(connectionSessionStoreKey('demo', connection.connectionId), { files: [], updatedAt: '2026-01-01T00:00:00.000Z' });

  await assert.rejects(
    service.runNative({ args: ['list'], cwd: root, projectId: 'test-project', providerId: 'demo' }, { onStderr: () => undefined, onStdout: () => undefined }),
    (error: unknown) => error instanceof SignedInError
      && error.code === 'AUTH_REQUIRED'
      && (error.details as { remedy?: string } | undefined)?.remedy === 'signed-in login demo@primary',
  );
  const status = service.serviceStatuses('test-project').find((candidate) => candidate.id === 'demo')?.accounts[0];
  assert.equal(status?.ready, false);
});

test('v1 project credentials migrate inside the service into machine accounts', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-migration-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  const store = new MemorySecretStore();
  const legacyConfig = {
    environment: 'production',
    project: { id: 'legacy', name: 'Legacy' },
    providers: {
      demo: {
        credentialMode: 'shared',
        credentials: [{ helpUrl: 'https://example.com', id: 'token', label: 'Token', portable: true }],
        http: { auth: { field: 'token', type: 'bearer' }, baseUrl: 'https://api.example.com' },
        label: 'Demo',
      },
    },
    schemaVersion: 1,
  } as const;
  writeFileSync(paths.stateFile, JSON.stringify({
    activeProject: 'legacy',
    projects: {
      legacy: { configPath: path.join(root, 'signed-in.config.json'), fingerprint: 'old', id: 'legacy', name: 'Legacy', roots: [root], trustedAt: '2026-01-01T00:00:00.000Z' },
    },
    schemaVersion: 1,
  }));
  store.set(trustedProjectStoreKey('legacy'), { config: legacyConfig, fingerprint: 'old', trustedAt: '2026-01-01T00:00:00.000Z' });
  store.set(credentialStoreKey('legacy', 'demo'), { fields: { token: 'migrated-secret' }, updatedAt: '2026-01-01T00:00:00.000Z' });
  const service = new SignedInService(store, paths);
  assert.equal(loadMachineState(paths.stateFile).schemaVersion, 2);
  assert.equal(store.has(credentialStoreKey('legacy', 'demo')), false);
  const migrated = service.serviceStatuses('legacy').find((candidate) => candidate.id === 'demo')?.accounts[0];
  assert.ok(migrated);
  assert.equal(migrated.account, 'primary');
  assert.equal(store.has(accountCredentialStoreKey('demo', 'default')), false);
  assert.equal(store.has(connectionCredentialStoreKey('demo', migrated.connectionId)), true);
  assert.equal(migrated.ready, true);
  assert.deepEqual(service.migrationNotice(), { migrated: true });
  assert.deepEqual(service.migrationNotice(), { migrated: false });
});

test('alias-keyed machine accounts migrate to immutable domain-named connections', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-connections-migration-'));
  const paths = testPaths(root);
  mkdirSync(paths.configDir, { recursive: true });
  mkdirSync(paths.dataDir, { recursive: true });
  writeFileSync(paths.stateFile, JSON.stringify({ projects: {}, schemaVersion: 2 }));
  const store = new MemorySecretStore();
  const timestamp = '2026-08-04T00:00:00.000Z';
  store.set(machineAccountsStoreKey(), {
    schemaVersion: 1,
    services: {
      gcp: {
        accounts: {
          default: {
            configuredFields: ['accessToken'],
            createdAt: timestamp,
            hasSession: false,
            identity: 'alex@acme.example',
            updatedAt: timestamp,
          },
        },
        default: 'default',
      },
    },
  });
  store.set(accountCredentialStoreKey('gcp', 'default'), { fields: { accessToken: 'migrated-token' }, updatedAt: timestamp });
  const service = new SignedInService(store, paths);
  const connection = service.serviceStatuses().find((candidate) => candidate.id === 'gcp')?.accounts[0];
  assert.ok(connection);
  assert.equal(connection.account, 'acme');
  assert.equal(connection.aliasSource, 'domain');
  assert.equal(connection.default, true);
  assert.equal(store.has(accountCredentialStoreKey('gcp', 'default')), false);
  assert.equal(store.has(connectionCredentialStoreKey('gcp', connection.connectionId)), true);
});

// Runs the real TypeScript entry point against private temporary homes so interface tests cannot touch operator state.
function runSignedInCli(
  args: string[],
  stateRoot: string,
): { status: number | null; stderr: string; stdout: string } {
  const result = spawnSync(process.execPath, [
    path.resolve(import.meta.dirname, '../node_modules/tsx/dist/cli.mjs'),
    path.resolve(import.meta.dirname, '../packages/signed-in/src/cli.ts'),
    ...args,
  ], {
    cwd: path.resolve(import.meta.dirname, '..'),
    encoding: 'utf8',
    env: {
      ...process.env,
      SIGNED_IN_CONFIG_HOME: path.join(stateRoot, 'config'),
      SIGNED_IN_DATA_HOME: path.join(stateRoot, 'data'),
      SIGNED_IN_RUNTIME_DIR: path.join(stateRoot, 'runtime'),
      NO_COLOR: '1',
    },
    timeout: 10_000,
  });
  return { status: result.status, stderr: result.stderr, stdout: result.stdout };
}

// Gives test services a complete private path layout without using the developer's real signed-in home.
function testPaths(root: string): SignedInPaths {
  return {
    auditFile: path.join(root, 'data', 'audit.jsonl'),
    configDir: path.join(root, 'config'),
    daemonLogFile: path.join(root, 'data', 'daemon.log'),
    dataDir: path.join(root, 'data'),
    runtimeDir: path.join(root, 'run'),
    socketPath: process.platform === 'win32'
      ? `\\\\.\\pipe\\signed-in-test-${createHash('sha256').update(root).digest('hex').slice(0, 12)}`
      : path.join(root, 'run', 'daemon.sock'),
    stateFile: path.join(root, 'config', 'state.json'),
    vaultDir: path.join(root, 'data', 'vault'),
  };
}

// Binds an ephemeral local port before the gateway integration test begins.
function listen(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
}

// Closes the integration server and surfaces any listener shutdown error.
function close(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

// Creates a local-only upstream certificate so the proxy test can exercise a real TLS interception path.
function createSelfSignedCertificate(commonName: string): { cert: string; key: string } {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = '01';
  certificate.validity.notBefore = new Date(Date.now() - 60_000);
  certificate.validity.notAfter = new Date(Date.now() + 60 * 60 * 1000);
  const attributes = [{ name: 'commonName', value: commonName }];
  certificate.setSubject(attributes);
  certificate.setIssuer(attributes);
  certificate.setExtensions([{ altNames: [{ type: 2, value: commonName }], name: 'subjectAltName' }]);
  certificate.sign(keys.privateKey, forge.md.sha256.create());
  return {
    cert: forge.pki.certificateToPem(certificate),
    key: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

// Speaks CONNECT and TLS directly so the native proxy is tested without depending on a platform curl binary.
function requestThroughConnectProxy(proxyUrl: string, ca: string, authority: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const proxy = new URL(proxyUrl);
    const socket = net.connect(Number(proxy.port), proxy.hostname);
    let connectResponse = Buffer.alloc(0);
    socket.once('connect', () => {
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
    });
    socket.on('data', function handleConnectData(chunk: Buffer) {
      connectResponse = Buffer.concat([connectResponse, chunk]);
      const boundary = connectResponse.indexOf('\r\n\r\n');
      if (boundary < 0) return;
      socket.off('data', handleConnectData);
      const remaining = connectResponse.subarray(boundary + 4);
      if (!connectResponse.subarray(0, boundary).toString('utf8').includes('200')) {
        reject(new Error('Proxy rejected CONNECT'));
        socket.destroy();
        return;
      }
      if (remaining.length > 0) socket.unshift(remaining);
      const secure = tls.connect({ ca, servername: 'localhost', socket }, () => {
        secure.write(`GET /echo HTTP/1.1\r\nHost: ${authority}\r\nAuthorization: Bearer dummy-value\r\nConnection: close\r\n\r\n`);
      });
      const response: Buffer[] = [];
      secure.on('data', (data: Buffer) => response.push(data));
      secure.on('end', () => resolve(Buffer.concat(response).toString('utf8')));
      secure.on('error', reject);
    });
    socket.once('error', reject);
  });
}

// Exercises the plain-HTTP Unix transport used by CLIs that can opt out of local TLS interception.
function requestThroughUnixSocket(socketPath: string, authority: string): Promise<{ body: string; statusCode: number }> {
  return new Promise((resolve, reject) => {
    const request = http.request({
      headers: { authorization: 'Bearer dummy-value', host: authority },
      method: 'GET',
      path: '/echo',
      socketPath,
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => chunks.push(chunk));
      response.on('end', () => resolve({
        body: Buffer.concat(chunks).toString('utf8'),
        statusCode: response.statusCode ?? 0,
      }));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end();
  });
}

// Buffers one small fixture request so gateway tests can assert exactly what crossed the HTTP boundary.
function readIncomingBody(request: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

// Mirrors the public versioned card without importing private key helpers into service-level tests.
function encodeIdentity(identity: ReturnType<typeof publicMachineIdentity>): string {
  return `signedin1:${Buffer.from(JSON.stringify(identity), 'utf8').toString('base64url')}`;
}
