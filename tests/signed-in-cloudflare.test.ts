import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { builtInServices } from '../packages/signed-in/src/catalog.js';
import { validateServiceCatalog } from '../packages/signed-in/src/config.js';
import { evaluatePolicy } from '../packages/signed-in/src/policy.js';
import { assertNativeProxyRequestAllowed } from '../packages/signed-in/src/runner.js';
import { connectionSessionStoreKey, MemorySecretStore } from '../packages/signed-in/src/secrets.js';
import { SignedInService } from '../packages/signed-in/src/service.js';
import type { SignedInPaths } from '../packages/signed-in/src/paths.js';
import type { ServiceConfig, SessionBundle, SignedInProjectConfig } from '../packages/signed-in/src/types.js';

const cloudflare = builtInServices.cloudflare!;
const directVerificationRequest = { method: 'GET' as const, path: '/user/tokens/verify' };
const verificationRequest = { method: 'GET' as const, path: '/client/v4/user/tokens/verify' };

// Keeps Cloudflare's user identity and Wrangler's internal token check explicit in the packaged adapter.
test('Cloudflare adapter declares identity and one exact native proxy exception', () => {
  assert.deepEqual(cloudflare.cli?.proxyPolicyAllowlist, [verificationRequest]);
  assert.deepEqual(cloudflare.identityArgs, ['whoami', '--json']);
  assert.equal(cloudflare.identityJsonField, 'email');

  for (const proxyPolicyAllowlist of [
    [{ method: 'POST', path: verificationRequest.path }],
    [{ method: 'GET', path: 'https://api.cloudflare.com/user/tokens/verify' }],
    [{ method: 'GET', path: `${verificationRequest.path}?token=value` }],
    [verificationRequest, verificationRequest],
  ]) {
    assert.throws(() => validateServiceCatalog({
      schemaVersion: 1,
      services: { cloudflare: { ...cloudflare, cli: { ...cloudflare.cli, proxyPolicyAllowlist } } },
    }, 'test catalog'), /proxyPolicyAllowlist/u);
  }
  assert.throws(() => validateServiceCatalog({
    schemaVersion: 1,
    services: { cloudflare: { ...cloudflare, cli: { ...cloudflare.cli, delivery: 'session' } } },
  }, 'test catalog'), /requires proxy delivery/u);
});

// Ensures the native-only exception cannot be used as a direct agent route to credential endpoints.
test('Cloudflare token verification remains denied through the direct HTTP gateway', () => {
  const decision = evaluatePolicy(projectConfig('cloudflare', cloudflare), {
    interface: 'http', method: 'GET', path: directVerificationRequest.path, providerId: 'cloudflare',
  });
  assert.equal(decision.classification, 'credential-control');
  assert.equal(decision.effect, 'deny');
});

// Reproduces Wrangler's preflight policy decision while rejecting broader token-endpoint requests.
test('native proxy permits the reviewed Cloudflare verification preflight only', () => {
  const baseProvider: ServiceConfig = {
    cli: { command: 'wrangler', delivery: 'proxy' },
    credentials: [{ env: 'CLOUDFLARE_API_TOKEN', helpUrl: 'https://example.invalid', id: 'token', label: 'Token', secret: true }],
    http: { auth: { field: 'token', type: 'bearer' }, baseUrl: 'https://api.cloudflare.com/client/v4' },
    label: 'Cloudflare fixture', signIn: 'manual',
  };
  const allowedProvider: ServiceConfig = {
    ...baseProvider,
    cli: { ...baseProvider.cli!, proxyPolicyAllowlist: [verificationRequest] },
  };
  assert.doesNotThrow(() => assertNativeProxyRequestAllowed({
    config: projectConfig('cloudflare-fixture', allowedProvider), provider: allowedProvider,
    providerId: 'cloudflare-fixture', request: verificationRequest,
  }));
  for (const request of [
    verificationRequest,
    { method: 'POST', path: verificationRequest.path },
    { method: 'GET', path: `${verificationRequest.path}?expanded=true` },
  ]) {
    const provider = request === verificationRequest ? baseProvider : allowedProvider;
    assert.throws(() => assertNativeProxyRequestAllowed({
      config: projectConfig('cloudflare-fixture', provider), provider,
      providerId: 'cloudflare-fixture', request,
    }), /Credential-control endpoint denied/u);
  }
});

// Proves rotating session refreshes never overlap for one alias but independent aliases can still progress together.
test('connection operations serialize per alias without serializing the whole provider', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-cloudflare-concurrency-'));
  const coordination = path.join(root, 'coordination');
  mkdirSync(coordination);
  const resolver = path.join(root, 'rotating-resolver');
  writeFileSync(resolver, `#!/bin/sh
set -eu
alias_name="$(cat "$HOME/.fixture/alias")"
mode="$(cat "$HOME/.fixture/mode")"
if [ "$mode" = same ]; then
  if ! mkdir "$1/same-lock" 2>/dev/null; then exit 9; fi
  sleep 0.15
  rmdir "$1/same-lock"
else
  : > "$1/$alias_name.ready"
  other=alpha
  if [ "$alias_name" = alpha ]; then other=beta; fi
  count=0
  while [ ! -f "$1/$other.ready" ] && [ "$count" -lt 100 ]; do sleep 0.01; count=$((count + 1)); done
  [ -f "$1/$other.ready" ] || exit 10
fi
printf '%s\n' '{"token":"synthetic-refreshed-token"}'
`);
  chmodSync(resolver, 0o700);
  const upstream = http.createServer((_request, response) => response.end('{"ok":true}'));
  await listen(upstream);
  const address = upstream.address();
  assert.ok(address && typeof address !== 'string');
  const store = new MemorySecretStore();
  const service = new SignedInService(store, fixturePaths(root));
  const provider: ServiceConfig = {
    cli: { command: resolver, delivery: 'proxy' },
    credentials: [{ env: 'FIXTURE_TOKEN', helpUrl: 'https://example.invalid', id: 'token', label: 'Token', secret: true }],
    http: { auth: { field: 'token', type: 'bearer' }, baseUrl: `http://127.0.0.1:${address.port}` },
    label: 'Rotating OAuth fixture', signIn: 'interactive',
    session: {
      loginArgs: ['login'], retain: true,
      resolvers: [{ args: [coordination], fieldMap: { token: '/token' }, format: 'json', persist: false }],
    },
  };
  const config = projectConfig('fixture', provider);
  service.trustProject({ approved: true, config, configPath: path.join(root, 'signed-in.config.json'), roots: [root] });
  try {
    const alpha = service.putCredentials({ account: 'alpha', fields: { token: 'initial-alpha' }, projectId: 'test-project', providerId: 'fixture' });
    store.set(connectionSessionStoreKey('fixture', alpha.connectionId), fixtureSession('alpha', 'same'));
    await Promise.all([
      service.request({ account: 'alpha', method: 'GET', path: '/', projectId: 'test-project', providerId: 'fixture' }),
      service.request({ account: 'alpha', method: 'GET', path: '/', projectId: 'test-project', providerId: 'fixture' }),
    ]);

    const beta = service.putCredentials({ account: 'beta', fields: { token: 'initial-beta' }, projectId: 'test-project', providerId: 'fixture' });
    store.set(connectionSessionStoreKey('fixture', alpha.connectionId), fixtureSession('alpha', 'different'));
    store.set(connectionSessionStoreKey('fixture', beta.connectionId), fixtureSession('beta', 'different'));
    await Promise.all([
      service.request({ account: 'alpha', method: 'GET', path: '/', projectId: 'test-project', providerId: 'fixture' }),
      service.request({ account: 'beta', method: 'GET', path: '/', projectId: 'test-project', providerId: 'fixture' }),
    ]);
  } finally {
    await close(upstream);
    rmSync(root, { force: true, recursive: true });
  }
});

// Creates the smallest sealed session capable of identifying a synthetic connection to its resolver process.
function fixtureSession(alias: string, mode: string): SessionBundle {
  return {
    files: [
      { contents: Buffer.from(alias).toString('base64'), mode: 0o600, path: '.fixture/alias' },
      { contents: Buffer.from(mode).toString('base64'), mode: 0o600, path: '.fixture/mode' },
    ],
    updatedAt: new Date().toISOString(),
  };
}

// Supplies isolated state paths so concurrency tests cannot touch the operator daemon or vault.
function fixturePaths(root: string): SignedInPaths {
  return {
    auditFile: path.join(root, 'audit.jsonl'), configDir: root, daemonLogFile: path.join(root, 'daemon.log'),
    dataDir: root, runtimeDir: path.join(root, 'run'), socketPath: path.join(root, 'daemon.sock'),
    stateFile: path.join(root, 'state.json'), vaultDir: path.join(root, 'vault'),
  };
}

// Builds one minimal trusted provider binding for policy, runner, and service integration tests.
function projectConfig(providerId: string, provider: ServiceConfig): SignedInProjectConfig {
  return {
    policies: [], project: { id: 'test-project', name: 'Test project' }, providers: { [providerId]: provider },
    schemaVersion: 2, services: { [providerId]: true },
  };
}

// Starts a disposable HTTP service before returning control to the test body.
function listen(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
}

// Closes a disposable HTTP service without leaking a listener into the rest of the suite.
function close(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
