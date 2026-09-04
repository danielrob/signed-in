import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { builtInServices } from '../packages/signed-in/src/catalog.js';
import { resolveCliInstallPlan } from '../packages/signed-in/src/cli-install.js';
import { validateServiceCatalog } from '../packages/signed-in/src/config.js';
import { allowsGwsGmailCommand, gwsLoginSecrets, isolateGwsSandbox, seedGwsClientConfig } from '../packages/signed-in/src/gws.js';
import { findProviderLoginUrl } from '../packages/signed-in/src/external-url.js';
import { StreamRedactor } from '../packages/signed-in/src/redact.js';
import { evaluatePolicy } from '../packages/signed-in/src/policy.js';
import { ProviderAuthenticationError, runProviderCommand, runProviderLogin } from '../packages/signed-in/src/runner.js';
import { createSessionSandbox } from '../packages/signed-in/src/session.js';
import { MemorySecretStore, connectionSessionStoreKey } from '../packages/signed-in/src/secrets.js';
import { SignedInError, SignedInService } from '../packages/signed-in/src/service.js';
import type { SignedInPaths } from '../packages/signed-in/src/paths.js';
import type { ServiceConfig, SessionBundle, SignedInProjectConfig } from '../packages/signed-in/src/types.js';

const gmail = builtInServices.gws!;
const profile = ['gmail', 'users', 'getProfile', '--params', '{"userId":"me"}'];
const list = ['gmail', 'users', 'messages', 'list'];
const clientPath = '.config/gws/client_secret.json';

// Keeps installation, consent scope, health checks, and identity extraction aligned with the advertised email capability.
test('gws catalog provides isolated Gmail reads with cross-platform installers', () => {
  assert.equal(gmail.cli?.adapter, 'gws-gmail');
  assert.equal(gmail.cli?.delivery, 'session');
  assert.equal(gmail.existingLogin, undefined);
  assert.deepEqual(gmail.session?.loginArgs, ['auth', 'login', '--scopes', 'https://www.googleapis.com/auth/gmail.readonly']);
  assert.deepEqual(gmail.ping, { args: profile, interface: 'native' });
  assert.equal(gmail.identityJsonField, 'emailAddress');
  assert.deepEqual(resolveCliInstallPlan('gws', { platform: 'darwin', available: () => true })?.args, ['install', 'googleworkspace-cli']);
  assert.deepEqual(resolveCliInstallPlan('gws', { platform: 'win32', available: () => true }), {
    args: ['install', '--global', '@googleworkspace/cli'], command: 'npm.cmd', displayCommand: 'npm install --global @googleworkspace/cli',
  });
  assert.throws(() => validateServiceCatalog({ schemaVersion: 1, services: { gws: { ...gmail, cli: { ...gmail.cli, adapter: 'unknown' } } } }, 'test'), /adapter is unsupported/u);
  assert.throws(() => validateServiceCatalog({ schemaVersion: 1, services: { gws: { ...gmail, cli: { ...gmail.cli, prefixArgs: ['auth'] } } } }, 'test'), /without prefixArgs/u);
  assert.throws(() => validateServiceCatalog({ schemaVersion: 1, services: { gws: { ...gmail, identityArgs: undefined } } }, 'test'), /requires identityArgs/u);
});

// Rejects every unreviewed command or option even when trusted project rules would otherwise allow it.
test('Gmail policy is fail-closed for writes, other services, credentials, and file arguments', () => {
  for (const args of [
    profile, [...list, '--params', '{"userId":"me","q":"in:inbox","maxResults":10}', '--page-all', '--page-limit=2'],
    ['gmail', 'users', 'messages', 'attachments', 'get', '--params', '{"userId":"me","messageId":"m","id":"a"}'],
    ['gmail', 'users', 'threads', 'list', '--format=table'], ['gmail', 'users', 'drafts', 'get'],
    ['gmail', 'users', 'labels', 'list'], ['gmail', 'users', 'history', 'list'],
    ['gmail', '--help'], ['gmail', 'users', 'messages', '--help'], ['--help'], ['--version'],
  ]) assert.equal(allowsGwsGmailCommand(args), true, JSON.stringify(args));
  const config = projectConfig(gmail);
  config.policies = [{ effect: 'allow', id: 'allow-everything', reason: 'Test restrictive adapter precedence.' }];
  for (const args of [
    ['auth', 'export', '--unmasked'], ['auth', 'login'], ['auth', 'setup'], ['auth', 'logout'],
    ['drive', 'files', 'list'], ['gmail:v1', 'users', 'messages', 'list'], ['schema', 'gmail.users.messages.list'],
    ['gmail', '+send'], ['gmail', 'users', 'messages', 'send'], ['gmail', 'users', 'messages', 'batchDelete'],
    ['gmail', 'users', 'messages', 'trash'], ['gmail', 'users', 'messages', 'modify'],
    ['gmail', 'users', 'settings', 'forwardingAddresses', 'list'],
    [...list, '--params', '@credentials.json'], [...list, '--params', 'null'], [...list, '--params', '[]'],
    [...list, '--params', '{"access_token":"alternate"}'], [...list, '--params', '{"userId":"someone@example.com"}'],
    [...list, '--output', '/tmp/mail'], [...list, '--upload=x'], [...list, '--api-version=v2'],
    [...list, '--sanitize=x'], [...list, '--params'], [...list, '--format', '--output'],
    [...list, '--params={}', '--params={}'], [...list, '--page-all=false'], [...list, '--format=unknown'],
    [...list, '--page-limit=-1'], [...list, '--', 'auth', 'export'], ['--help', 'auth', 'export'],
  ]) {
    const decision = evaluatePolicy(config, { args, interface: 'native', providerId: 'gws' });
    assert.equal(decision.effect, 'deny', JSON.stringify(args));
    assert.deepEqual(decision.matchedRules, ['signed-in:gmail-readonly']);
  }
});

// Exercises alias isolation without loading anything from the real operator home or machine keyring.
test('GWS isolation removes ambient auth and stops dotenv traversal', () => {
  const sandbox = createSessionSandbox(undefined, undefined, {
    GOOGLE_WORKSPACE_CLI_CONFIG_DIR: '/ambient', GOOGLE_WORKSPACE_PROJECT_ID: 'ambient',
    GWS_SANITIZE_TEMPLATE: 'outside', GOOGLE_APPLICATION_CREDENTIALS: '/adc',
    CLOUDSDK_CONFIG: '/cloud', RUST_LOG: 'trace', PATH: process.env.PATH,
  });
  try {
    isolateGwsSandbox(sandbox);
    assert.equal(sandbox.env.GOOGLE_WORKSPACE_CLI_CONFIG_DIR, path.join(sandbox.home, '.config', 'gws'));
    assert.equal(sandbox.env.GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND, 'file');
    for (const name of ['GOOGLE_WORKSPACE_PROJECT_ID', 'GWS_SANITIZE_TEMPLATE', 'GOOGLE_APPLICATION_CREDENTIALS', 'RUST_LOG']) assert.equal(sandbox.env[name], undefined);
    assert.equal(readFileSync(path.join(sandbox.home, '.env'), 'utf8'), '');
    assert.equal(sandbox.env.HOME, sandbox.home);
  } finally { sandbox.cleanup(); }
  assert.equal(existsSync(sandbox.home), false);
});

// Ensures setup imports only a reviewed application configuration and never adopts an existing user's credentials.
test('GWS login seeds only the client config and preserves reconnect state', () => {
  const source = mkdtempSync(path.join(tmpdir(), 'signed-in-gws-source-'));
  const sandbox = createSessionSandbox(undefined, undefined, {});
  try {
    assert.throws(() => seedGwsClientConfig(sandbox, source), /gws auth setup/u);
    mkdirSync(path.join(source, '.config', 'gws'), { recursive: true });
    writeFileSync(path.join(source, clientPath), '{"installed":{"client_secret":"synthetic-client-secret"}}');
    writeFileSync(path.join(source, '.config/gws/credentials.enc'), 'ambient-user-credential');
    writeFileSync(path.join(source, '.config/gws/.encryption_key'), 'ambient-key');
    seedGwsClientConfig(sandbox, source);
    assert.deepEqual(sandbox.snapshot().files.map((file) => file.path), [clientPath]);
    const first = readFileSync(path.join(sandbox.home, clientPath), 'utf8');
    writeFileSync(path.join(source, clientPath), 'changed-ambient-client');
    seedGwsClientConfig(sandbox, source);
    assert.equal(readFileSync(path.join(sandbox.home, clientPath), 'utf8'), first);
    assert.equal(readFileSync(path.join(source, '.config/gws/credentials.enc'), 'utf8'), 'ambient-user-credential');
  } finally { sandbox.cleanup(); rmSync(source, { recursive: true, force: true }); }
});

// Prevents the seed path from following either leaf or parent symlinks outside the declared home boundary.
test('GWS login refuses symlinked OAuth configuration', { skip: process.platform === 'win32' }, () => {
  const source = mkdtempSync(path.join(tmpdir(), 'signed-in-gws-links-'));
  const sandbox = createSessionSandbox(undefined, undefined, {});
  try {
    mkdirSync(path.join(source, 'elsewhere/gws'), { recursive: true });
    writeFileSync(path.join(source, 'elsewhere/gws/client_secret.json'), '{}');
    symlinkSync(path.join(source, 'elsewhere'), path.join(source, '.config'));
    assert.throws(() => seedGwsClientConfig(sandbox, source), /must not use symlinks/u);
  } finally { sandbox.cleanup(); rmSync(source, { recursive: true, force: true }); }
});

// Proves the runner changes cwd, round-trips refreshed state, and removes the temporary session after a command.
test('GWS native runner retains refreshed per-alias state without using project cwd', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-gws-runner-'));
  const stdout: Buffer[] = [];
  try {
    const fixture = path.join(root, 'fixture.cjs');
    writeFileSync(fixture, `const fs = require('node:fs'); const path = require('node:path');
      const home = process.env.HOME;
      if (process.cwd() !== fs.realpathSync(home) || fs.readFileSync(path.join(home, '.env'), 'utf8') !== '') process.exit(9);
      if (process.env.GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND !== 'file') process.exit(10);
      fs.writeFileSync(path.join(home, '.config/gws/token_cache.json'), 'synthetic-refreshed-ciphertext');
      console.log(JSON.stringify({ cwd: process.cwd(), keyring: process.env.GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND }));`);
    const result = await runProviderCommand({
      args: profile, callbacks: { onStderr: () => undefined, onStdout: (chunk) => stdout.push(chunk) },
      config: projectConfig(gmail), credentials: { fields: {}, updatedAt: '' }, cwd: root,
      provider: { ...gmail, cli: { ...gmail.cli!, trustedExecutable: process.execPath, prefixArgs: [fixture] } },
      providerId: 'gws', session: syntheticSession(),
    });
    assert.equal(result.exitCode, 0);
    assert.ok(result.session?.files.some((file) => file.path === '.config/gws/token_cache.json'));
    const output = JSON.parse(Buffer.concat(stdout).toString('utf8')) as { cwd: string };
    assert.notEqual(output.cwd, root);
    assert.equal(existsSync(output.cwd), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

// Verifies Gmail identity extraction, connection persistence, policy denial, and exact expired-login remedies end to end.
test('GWS service verifies login and reports an expired connection', { skip: process.platform === 'win32' }, async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-gws-service-'));
  try {
    const executable = path.join(root, 'gws-fixture');
    writeFileSync(executable, `#!/bin/sh
if [ "$1" = auth ]; then exit 0; fi
if [ "$4" = list ]; then exit 2; fi
printf '%s\\n' '{"emailAddress":"alex@example.com","messagesTotal":12,"threadsTotal":7}'
`);
    chmodSync(executable, 0o700);
    const store = new MemorySecretStore();
    const service = new SignedInService(store, fixturePaths(root));
    const serviceId = 'gmail-fixture';
    const config = projectConfig({ ...gmail, cli: { ...gmail.cli!, command: executable } }, serviceId);
    service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
    const connection = service.putCredentials({ account: 'mail', fields: {}, projectId: 'gws-test', providerId: serviceId });
    store.set(connectionSessionStoreKey(serviceId, connection.connectionId), syntheticSession());
    const login = await service.loginProvider({
      account: 'mail', approved: true, callbacks: { onStderr: () => undefined, onStdout: () => undefined },
      cwd: root, projectId: 'gws-test', providerId: serviceId,
    });
    assert.equal(login.exitCode, 0);
    assert.equal(login.status?.identity, 'alex@example.com');
    assert.equal(login.status?.ready, true);
    await assert.rejects(service.runNative({ args: ['auth', 'export'], cwd: root, projectId: 'gws-test', providerId: serviceId }, { onStderr: () => undefined, onStdout: () => undefined }),
      (error: unknown) => error instanceof SignedInError && error.code === 'POLICY_DENIED');
    await assert.rejects(service.runNative({ args: list, cwd: root, projectId: 'gws-test', providerId: serviceId }, { onStderr: () => undefined, onStdout: () => undefined }),
      (error: unknown) => error instanceof SignedInError && error.code === 'AUTH_REQUIRED'
        && (error.details as { remedy?: string })?.remedy === 'signed-in login gmail-fixture@mail');
    assert.equal(service.serviceStatuses('gws-test').find((item) => item.id === serviceId)?.accounts[0]?.ready, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

// Preserves complete public OAuth links while the provider waits, without weakening reusable-secret redaction.
test('GWS OAuth URLs remain intact and arrive before the provider finishes waiting', () => {
  const clientId = 'synthetic-public-client-id.apps.googleusercontent.com';
  const clientSecret = 'synthetic-private-client-secret';
  const authUri = 'https://accounts.google.com/o/oauth2/auth';
  const session: SessionBundle = {
    files: [{ contents: Buffer.from(JSON.stringify({ installed: { client_id: clientId, client_secret: clientSecret, auth_uri: authUri } })).toString('base64'), mode: 0o600, path: clientPath }], updatedAt: '',
  };
  const secrets = gwsLoginSecrets(session);
  assert.deepEqual(secrets, [clientSecret]);
  const url = `${authUri}?client_id=${clientId}&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.readonly&redirect_uri=http%3A%2F%2Flocalhost%3A12345&response_type=code`;
  const message = `Open this URL in your browser to authenticate:\n\n  ${url}\n`;
  const redactor = new StreamRedactor(secrets);
  let received = '';
  for (const chunk of [message.slice(0, 110), message.slice(110, -10), message.slice(-10)]) {
    received += redactor.push(chunk) + redactor.flushPrompt(true);
  }
  assert.equal(received, message);
  assert.equal(findProviderLoginUrl('gws', received), url);
  assert.equal(findProviderLoginUrl('gws', received.trimEnd()), undefined);
  assert.equal(findProviderLoginUrl('gws', received.replace('accounts.google.com', 'accounts.google.com.attacker.example')), undefined);
  const secretRedactor = new StreamRedactor(secrets);
  const masked = secretRedactor.push(`${clientSecret}\n`) + secretRedactor.flushPrompt(true) + secretRedactor.finish();
  assert.equal(masked.includes(clientSecret), false);
});

// Keeps failed Gmail verification private and prevents successful consent alone from marking a login usable.
test('GWS consent is not saved as a successful login when Gmail rejects the profile probe', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-gws-failed-probe-'));
  const stdout: Buffer[] = [];
  try {
    const fixture = path.join(root, 'fixture.cjs');
    writeFileSync(fixture, `if (process.argv[2] === 'auth') process.exit(0);
      console.log('synthetic-private-probe-response'); process.exit(2);`);
    await assert.rejects(runProviderLogin({
      callbacks: {
        onStderr: () => undefined, onStdout: (chunk) => stdout.push(chunk),
      },
      credentials: { fields: {}, updatedAt: '' }, cwd: root, remote: false,
      provider: { ...gmail, cli: { ...gmail.cli!, trustedExecutable: process.execPath, prefixArgs: [fixture] } },
      session: syntheticSession(),
    }), ProviderAuthenticationError);
    assert.equal(Buffer.concat(stdout).toString('utf8'), '');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

// Supplies synthetic sealed state so tests never need to inspect the real operator OAuth configuration.
function syntheticSession(): SessionBundle {
  return { files: [{ contents: Buffer.from('{"installed":{"client_secret":"synthetic-client-secret"}}').toString('base64'), mode: 0o600, path: clientPath }], updatedAt: new Date().toISOString() };
}

// Gives policy and service tests the same minimal trusted binding without depending on repository-local machine state.
function projectConfig(provider: ServiceConfig, serviceId = 'gws'): SignedInProjectConfig {
  return { schemaVersion: 2, project: { id: 'gws-test', name: 'GWS test' }, providers: { [serviceId]: provider }, services: { [serviceId]: true }, policies: [] };
}

// Keeps service receipts and state in a disposable test root, away from the operator's daemon files.
function fixturePaths(root: string): SignedInPaths {
  return {
    configDir: root, dataDir: root, auditFile: path.join(root, 'audit.jsonl'), runtimeDir: path.join(root, 'run'),
    daemonLogFile: path.join(root, 'daemon.log'), vaultDir: path.join(root, 'vault'),
    stateFile: path.join(root, 'state.json'), socketPath: path.join(root, 'daemon.sock'),
  };
}
