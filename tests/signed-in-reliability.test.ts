import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, unlinkSync, writeFileSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import net, { type Server } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { callDaemon, SignedInClientError } from '../packages/signed-in/src/client.js';
import { startSignedInDaemon } from '../packages/signed-in/src/daemon.js';
import { signedInBuild, type SignedInPaths } from '../packages/signed-in/src/paths.js';
import { eraseLocalSignedInState } from '../packages/signed-in/src/recovery.js';
import { MemorySecretStore } from '../packages/signed-in/src/secrets.js';
import type { SignedInProjectConfig } from '../packages/signed-in/src/types.js';

test('concurrent daemon starts serialize without replacing the winning socket', async () => {
  const paths = testPaths(mkdtempSync(path.join(tmpdir(), 'signed-in-race-')));
  const starts = await Promise.allSettled([
    startSignedInDaemon(paths, new MemorySecretStore()),
    startSignedInDaemon(paths, new MemorySecretStore()),
  ]);
  const winners = starts.filter((result): result is PromiseFulfilledResult<Awaited<ReturnType<typeof startSignedInDaemon>>> => result.status === 'fulfilled');
  assert.equal(winners.length, 1);
  const loser = starts.find((result): result is PromiseRejectedResult => result.status === 'rejected');
  assert.ok(loser);
  assert.equal((loser.reason as { code?: unknown }).code, 'DAEMON_ALREADY_RUNNING');
  const ping = await callDaemon(paths, 'ping').result as { build: string; protocol: number };
  assert.deepEqual({ build: ping.build, protocol: ping.protocol }, { build: signedInBuild, protocol: 1 });
  await winners[0].value.close();
});

test('malformed request and EOF ordering errors stay connection-local', async () => {
  const paths = testPaths(mkdtempSync(path.join(tmpdir(), 'signed-in-frames-')));
  const daemon = await startSignedInDaemon(paths, new MemorySecretStore());
  try {
    const malformed = await exchange(paths.socketPath, '{not-json}\n');
    assert.equal(JSON.parse(malformed) .error.code, 'BAD_REQUEST');

    const id = 'eof-order';
    const frames = [
      { id, method: 'ping', params: {}, version: 1 },
      { event: 'stdin-end', id },
      { event: 'stdin', id, payload: Buffer.from('late').toString('base64') },
    ].map((frame) => JSON.stringify(frame)).join('\n');
    const invalidOrder = await exchange(paths.socketPath, `${frames}\n`);
    const invalidEvents = invalidOrder.split('\n').map((line) => JSON.parse(line));
    assert.ok(invalidEvents.some((event) => event.error?.code === 'BAD_REQUEST'));

    const ping = await callDaemon(paths, 'ping').result as { pid: number };
    assert.equal(ping.pid, process.pid);
  } finally {
    await daemon.close();
  }
});

test('daemon accepts an empty body for bodyless HTTP requests', async () => {
  const paths = testPaths(mkdtempSync(path.join(tmpdir(), 'signed-in-empty-body-')));
  const daemon = await startSignedInDaemon(paths, new MemorySecretStore());
  try {
    await assert.rejects(
      callDaemon(paths, 'http.request', {
        body: '',
        bodyEncoding: 'base64',
        headers: {},
        method: 'GET',
        path: '/v1/products',
        providerId: 'polar',
      }).result,
      (error: unknown) => error instanceof SignedInClientError && error.code === 'AUTH_REQUIRED',
    );
  } finally {
    await daemon.close();
  }
});

test('daemon routes service ping through the credential boundary', async () => {
  const paths = testPaths(mkdtempSync(path.join(tmpdir(), 'signed-in-service-ping-')));
  const daemon = await startSignedInDaemon(paths, new MemorySecretStore());
  try {
    await assert.rejects(
      callDaemon(paths, 'service.ping', { cwd: process.cwd(), providerId: 'polar' }).result,
      (error: unknown) => error instanceof SignedInClientError && error.code === 'AUTH_REQUIRED',
    );
  } finally {
    await daemon.close();
  }
});

test('client turns malformed daemon JSON into a structured protocol failure', async () => {
  const paths = testPaths(mkdtempSync(path.join(tmpdir(), 'signed-in-client-json-')));
  const server = net.createServer((socket) => socket.once('data', () => socket.end('not-json\n')));
  await listen(server, paths.socketPath);
  try {
    await assert.rejects(callDaemon(paths, 'ping').result, (error: unknown) =>
      error instanceof SignedInClientError && error.code === 'DAEMON_PROTOCOL');
  } finally {
    await close(server, paths.socketPath);
  }
});

test('client bounds a daemon that accepts a request but never sends its first frame', async () => {
  const paths = testPaths(mkdtempSync(path.join(tmpdir(), 'signed-in-client-timeout-')));
  const server = net.createServer((socket) => socket.on('data', () => undefined));
  await listen(server, paths.socketPath);
  try {
    await assert.rejects(callDaemon(paths, 'ping', {}, { firstFrameTimeoutMs: 50 }).result, (error: unknown) =>
      error instanceof SignedInClientError && error.code === 'DAEMON_TIMEOUT');
  } finally {
    await close(server, paths.socketPath);
  }
});

test('an accepted frame keeps a quiet long-running operation alive until its result', async () => {
  const paths = testPaths(mkdtempSync(path.join(tmpdir(), 'signed-in-client-accepted-')));
  const server = net.createServer((socket) => socket.once('data', (chunk) => {
    const request = JSON.parse(chunk.toString('utf8').trim()) as { id: string };
    socket.write(`${JSON.stringify({ event: 'accepted', id: request.id })}\n`);
    setTimeout(() => socket.end(`${JSON.stringify({ event: 'result', id: request.id, result: { ok: true } })}\n`), 75);
  }));
  await listen(server, paths.socketPath);
  try {
    const result = await callDaemon(paths, 'quiet.operation', {}, { firstFrameTimeoutMs: 25 }).result;
    assert.deepEqual(result, { ok: true });
  } finally {
    await close(server, paths.socketPath);
  }
});

test('client never classifies an accepted operation as safe to replay after disconnect', async () => {
  const paths = testPaths(mkdtempSync(path.join(tmpdir(), 'signed-in-client-disconnect-')));
  const server = net.createServer((socket) => socket.once('data', (chunk) => {
    const request = JSON.parse(chunk.toString('utf8').trim()) as { id: string };
    socket.write(`${JSON.stringify({ event: 'accepted', id: request.id })}\n`, () => socket.destroy());
  }));
  await listen(server, paths.socketPath);
  try {
    await assert.rejects(
      callDaemon(paths, 'accepted.operation').result,
      (error: unknown) => error instanceof SignedInClientError && error.code === 'DAEMON_DISCONNECTED',
    );
  } finally {
    await close(server, paths.socketPath);
  }
});

test('an idle-only upgrade handoff preserves an active authenticated operation', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-drain-'));
  const paths = testPaths(root);
  let releaseResponse!: () => void;
  let markRequestStarted!: () => void;
  const responseGate = new Promise<void>((resolve) => { releaseResponse = resolve; });
  const requestStarted = new Promise<void>((resolve) => { markRequestStarted = resolve; });
  const upstream = createHttpServer((_request, response) => {
    markRequestStarted();
    void responseGate.then(() => {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{}');
    });
  });
  await new Promise<void>((resolve, reject) => {
    upstream.once('error', reject);
    upstream.listen(0, '127.0.0.1', () => resolve());
  });
  const address = upstream.address();
  assert.ok(address && typeof address === 'object');
  const config: SignedInProjectConfig = {
    environment: 'test',
    policies: [],
    project: { id: 'drain-test', name: 'Drain Test' },
    providers: {
      demo: {
        credentials: [{
          helpUrl: 'https://example.com/tokens',
          id: 'token',
          label: 'Token',
          portable: true,
        }],
        http: { auth: { field: 'token', type: 'bearer' }, baseUrl: `http://127.0.0.1:${address.port}` },
        label: 'Demo',
        signIn: 'manual',
      },
    },
    schemaVersion: 2,
    services: { demo: true },
  };
  const daemon = await startSignedInDaemon(paths, new MemorySecretStore());
  try {
    await callDaemon(paths, 'project.trust', {
      approved: true,
      config,
      configPath: path.join(root, 'signed-in.config.json'),
      roots: [root],
    }).result;
    await callDaemon(paths, 'credential.put', {
      fields: { token: 'private-test-token' },
      projectId: 'drain-test',
      providerId: 'demo',
    }).result;
    const activeRequest = callDaemon(paths, 'http.request', {
      body: '',
      bodyEncoding: 'base64',
      headers: {},
      method: 'GET',
      path: '/slow',
      projectId: 'drain-test',
      providerId: 'demo',
    }).result;
    await requestStarted;
    await assert.rejects(
      callDaemon(paths, 'daemon.shutdown', { ifIdle: true }).result,
      (error: unknown) => error instanceof SignedInClientError && error.code === 'DAEMON_BUSY',
    );
    const stillRunning = await callDaemon(paths, 'ping').result as { pid: number };
    assert.equal(stillRunning.pid, process.pid);
    releaseResponse();
    await activeRequest;
    assert.deepEqual(await callDaemon(paths, 'daemon.shutdown', { ifIdle: true }).result, { stopping: true });
  } finally {
    releaseResponse();
    await daemon.close();
    await new Promise<void>((resolve, reject) => upstream.close((error) => error ? reject(error) : resolve()));
  }
});

test('offline recovery erases local state without reading a corrupt record', () => {
  const paths = testPaths(mkdtempSync(path.join(tmpdir(), 'signed-in-recovery-')));
  for (const directory of [paths.configDir, paths.dataDir, paths.vaultDir]) mkdirSync(directory, { mode: 0o700, recursive: true });
  writeFileSync(paths.stateFile, '{corrupt');
  writeFileSync(paths.auditFile, '{corrupt');
  writeFileSync(paths.daemonLogFile, 'old failure');
  const store = new MemorySecretStore();
  store.set('corrupt', { unreadable: true });
  eraseLocalSignedInState(paths, store);
  assert.equal(store.has('corrupt'), false);
  assert.equal(existsSync(paths.stateFile), false);
  assert.equal(existsSync(paths.auditFile), false);
  assert.equal(existsSync(paths.daemonLogFile), false);
});

// Gives every lifecycle test an isolated owner-only filesystem layout and short Unix socket path.
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

// Exchanges one raw request batch so malformed framing can be tested without trusting the production client.
function exchange(socketPath: string, payload: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let response = '';
    socket.setEncoding('utf8');
    socket.once('connect', () => socket.write(payload));
    socket.on('data', (chunk: string) => { response += chunk; });
    socket.once('end', () => resolve(response.trim()));
    socket.once('error', reject);
  });
}

// Binds a private Unix socket before a fake daemon test begins.
function listen(server: Server, socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    mkdirSync(path.dirname(socketPath), { mode: 0o700, recursive: true });
    server.once('error', reject);
    server.listen(socketPath, () => resolve());
  });
}

// Closes a fake daemon and removes only its exact temporary socket artifact.
async function close(server: Server, socketPath: string): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  if (existsSync(socketPath)) unlinkSync(socketPath);
}
