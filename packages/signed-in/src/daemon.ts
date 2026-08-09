import { chmodSync, closeSync, existsSync, lstatSync, openSync, readFileSync, unlinkSync, writeSync } from 'node:fs';
import net, { type Server, type Socket } from 'node:net';
import path from 'node:path';

import { ensureSignedInDirectories, signedInBuild, type SignedInPaths } from './paths.js';
import { EncryptedVault, type SecretStore } from './secrets.js';
import { SignedInError, SignedInService, safeErrorMessage } from './service.js';
import type { IpcControl, IpcEvent, IpcPingResult, IpcRequest } from './types.js';

const maximumFrameBytes = 64 * 1024 * 1024;
const maximumQueuedInputBytes = 1024 * 1024;
const maximumStdinChunkBytes = 256 * 1024;

export interface SignedInDaemon {
  close: () => Promise<void>;
  server: Server;
}

// Starts the only process permitted to decrypt signed-in vault records and exposes a narrow operation-only socket API.
export async function startSignedInDaemon(paths: SignedInPaths, providedStore?: SecretStore): Promise<SignedInDaemon> {
  ensureSignedInDirectories(paths);
  const releaseStartupLock = await acquireStartupLock(paths);
  try {
    await removeStaleSocket(paths.socketPath);
    const store = providedStore ?? new EncryptedVault(paths.vaultDir);
    const service = new SignedInService(store, paths);
    const sockets = new Set<Socket>();
    const activeOperations = new Set<Socket>();
    const activeChildren = new Map<Socket, { kill: (signal?: NodeJS.Signals) => boolean; stdin: NodeJS.WritableStream }>();
    let closeDaemon!: () => Promise<void>;
    const server = net.createServer((socket) => {
      sockets.add(socket);
      socket.once('close', () => {
        sockets.delete(socket);
        activeOperations.delete(socket);
        activeChildren.delete(socket);
      });
      handleConnection(socket, service, closeDaemon, activeOperations, (child) => activeChildren.set(socket, child));
    });
    await listen(server, paths.socketPath);
    if (process.platform !== 'win32') chmodSync(paths.socketPath, 0o600);
    const socketIdentity = process.platform === 'win32' ? undefined : fileIdentity(paths.socketPath);
    let closing: Promise<void> | undefined;
    const close = (): Promise<void> => {
      if (closing) return closing;
      closing = (async () => {
        for (const child of activeChildren.values()) terminateChild(child);
        for (const socket of sockets) socket.end();
        const forceTimer = setTimeout(() => {
          for (const socket of sockets) socket.destroy();
        }, 1_000);
        try {
          await closeServer(server);
        } finally {
          clearTimeout(forceTimer);
          unlinkOwnedSocket(paths.socketPath, socketIdentity);
        }
      })();
      return closing;
    };
    closeDaemon = close;
    return { close, server };
  } finally {
    releaseStartupLock();
  }
}

// Accepts one operation per connection while retaining control frames for stdin and cancellation.
function handleConnection(
  socket: Socket,
  service: SignedInService,
  shutdownDaemon: () => Promise<void>,
  activeOperations: Set<Socket>,
  registerChild: (child: { kill: (signal?: NodeJS.Signals) => boolean; stdin: NodeJS.WritableStream }) => void,
): void {
  let buffer = '';
  let requestStarted = false;
  let requestId = 'unknown';
  let finished = false;
  let inputEnded = false;
  let cancelRequested = false;
  let queuedInputBytes = 0;
  const operationAbort = new AbortController();
  let activeChild: { kill: (signal?: NodeJS.Signals) => boolean; stdin: NodeJS.WritableStream } | undefined;
  const queuedInput: Buffer[] = [];

  socket.setEncoding('utf8');
  socket.on('data', (chunk: string) => {
    if (finished) return;
    buffer += chunk;
    while (buffer.includes('\n')) {
      const newline = buffer.indexOf('\n');
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      if (!line.trim()) continue;
      try {
        if (Buffer.byteLength(line, 'utf8') > maximumFrameBytes) throw new SignedInError('BAD_REQUEST', 'IPC frame exceeded 64 MiB');
        const message = JSON.parse(line) as unknown;
        if (!requestStarted) {
          const request = parseRequest(message);
          requestStarted = true;
          requestId = request.id;
          if (!['daemon.shutdown', 'ping'].includes(request.method)) activeOperations.add(socket);
          send(socket, { event: 'accepted', id: request.id });
          void dispatchRequest(request, service, {
            activeOperationCount: () => activeOperations.size,
            onChild: (child) => {
              activeChild = child;
              registerChild(child);
              if (cancelRequested || finished) terminateChild(child);
              else {
                for (const queued of queuedInput.splice(0)) child.stdin.write(queued);
                if (inputEnded) child.stdin.end();
              }
            },
            send: (event) => send(socket, event),
            signal: operationAbort.signal,
            shutdown: async () => {
              socket.end();
              await shutdownDaemon();
            },
          }).then((result) => {
            if (finished) return;
            finished = true;
            activeOperations.delete(socket);
            send(socket, { event: 'result', id: request.id, result });
            socket.end();
          }).catch((error) => {
            if (finished) return;
            finished = true;
            activeOperations.delete(socket);
            send(socket, errorEvent(request.id, error));
            socket.end();
          });
        } else {
          const control = parseControl(message);
          if (control.id !== requestId) throw new SignedInError('BAD_REQUEST', 'IPC control id did not match its request');
          if (control.event === 'cancel') {
            cancelRequested = true;
            operationAbort.abort();
            if (activeChild) terminateChild(activeChild);
          }
          if (control.event === 'stdin-end') {
            inputEnded = true;
            activeChild?.stdin.end();
          }
          if (control.event === 'stdin') {
            if (inputEnded) throw new SignedInError('BAD_REQUEST', 'IPC stdin arrived after stdin-end');
            const chunkBuffer = decodeInput(control.payload);
            if (activeChild) activeChild.stdin.write(chunkBuffer);
            else {
              queuedInputBytes += chunkBuffer.length;
              if (queuedInputBytes > maximumQueuedInputBytes) throw new SignedInError('BAD_REQUEST', 'Queued IPC stdin exceeded 1 MiB');
              queuedInput.push(chunkBuffer);
            }
          }
        }
      } catch (error) {
        finished = true;
        activeOperations.delete(socket);
        operationAbort.abort();
        if (activeChild) terminateChild(activeChild);
        send(socket, errorEvent(requestId, error instanceof SyntaxError
          ? new SignedInError('BAD_REQUEST', 'IPC message was not valid JSON')
          : error));
        socket.end();
        return;
      }
    }
    if (Buffer.byteLength(buffer, 'utf8') > maximumFrameBytes) {
      finished = true;
      send(socket, errorEvent(requestId, new SignedInError('BAD_REQUEST', 'IPC frame exceeded 64 MiB')));
      socket.end();
    }
  });
  socket.on('error', () => {
    activeOperations.delete(socket);
    if (!finished) operationAbort.abort();
    if (!finished && activeChild) terminateChild(activeChild);
    finished = true;
  });
  socket.on('close', () => {
    activeOperations.delete(socket);
    if (!finished) operationAbort.abort();
    if (!finished && activeChild) terminateChild(activeChild);
    finished = true;
  });
}

// Maps the deliberately small socket protocol onto service methods without ever adding a generic secret getter or shell runner.
async function dispatchRequest(
  request: IpcRequest,
  service: SignedInService,
  context: {
    activeOperationCount: () => number;
    onChild: (child: { kill: (signal?: NodeJS.Signals) => boolean; stdin: NodeJS.WritableStream }) => void;
    send: (event: IpcEvent) => void;
    signal: AbortSignal;
    shutdown: () => Promise<void>;
  },
): Promise<unknown> {
  const params = requireRecord(request.params ?? {}, request.method);
  const callbacks = {
    onChild: context.onChild,
    onStderr: (chunk: Buffer) => context.send(outputEvent(request.id, 'stderr', chunk)),
    onStdout: (chunk: Buffer) => context.send(outputEvent(request.id, 'stdout', chunk)),
  };
  switch (request.method) {
    case 'ping':
      return { build: signedInBuild, pid: process.pid, protocol: 1, version: 1 } satisfies IpcPingResult;
    case 'daemon.shutdown':
      if (optionalBoolean(params.ifIdle) && context.activeOperationCount() > 0) {
        const activeOperations = context.activeOperationCount();
        throw new SignedInError('DAEMON_BUSY', `Background helper is finishing ${activeOperations} active ${activeOperations === 1 ? 'operation' : 'operations'}; it was left running.`, {
          activeOperations,
          remedy: 'Wait for the active signed-in command to finish, then try again.',
        });
      }
      setImmediate(() => void context.shutdown());
      return { stopping: true };
    case 'project.trust':
      return service.trustProject({
        approved: optionalBoolean(params.approved),
        config: params.config,
        configPath: requireString(params.configPath, 'configPath'),
        roots: requireStringArray(params.roots, 'roots'),
      });
    case 'project.list':
      return service.listProjects();
    case 'project.describe':
      return service.describeProject(requireString(params.projectId, 'projectId'));
    case 'project.forget':
      return service.forgetProject({
        approved: optionalBoolean(params.approved),
        projectId: requireString(params.projectId, 'projectId'),
      });
    case 'provider.status':
    case 'service.status':
      return service.serviceStatuses(optionalString(params.projectId));
    case 'service.cli.status':
      return service.cliAvailability({
        projectId: optionalString(params.projectId),
        providerId: requireString(params.providerId, 'providerId'),
      });
    case 'credential.put':
      return service.putCredentials({
        account: optionalString(params.account),
        approved: optionalBoolean(params.approved),
        fields: requireStringRecord(params.fields, 'fields'),
        projectId: optionalString(params.projectId),
        providerId: requireString(params.providerId, 'providerId'),
        replace: optionalBoolean(params.replace),
      });
    case 'provider.login':
      return service.loginProvider({
        account: optionalString(params.account),
        alias: optionalString(params.alias),
        approved: optionalBoolean(params.approved),
        callbacks,
        cwd: requireString(params.cwd, 'cwd'),
        projectId: optionalString(params.projectId),
        providerId: requireString(params.providerId, 'providerId'),
        remote: optionalBoolean(params.remote),
      });
    case 'provider.adoption.discover':
      return service.discoverExistingLogin({
        cwd: requireString(params.cwd, 'cwd'),
        projectId: optionalString(params.projectId),
        providerId: requireString(params.providerId, 'providerId'),
      });
    case 'provider.adoption.import':
      return service.adoptExistingLogin({
        account: optionalString(params.account),
        alias: optionalString(params.alias),
        approved: optionalBoolean(params.approved),
        callbacks,
        cwd: requireString(params.cwd, 'cwd'),
        projectId: optionalString(params.projectId),
        providerId: requireString(params.providerId, 'providerId'),
      });
    case 'provider.run':
      return service.runNative({
        approved: optionalBoolean(params.approved),
        args: requireStringArray(params.args, 'args'),
        account: optionalString(params.account),
        cwd: requireString(params.cwd, 'cwd'),
        projectId: optionalString(params.projectId),
        providerId: requireString(params.providerId, 'providerId'),
      }, callbacks);
    case 'service.ping':
      return service.pingService({
        account: optionalString(params.account),
        cwd: requireString(params.cwd, 'cwd'),
        projectId: optionalString(params.projectId),
        providerId: requireString(params.providerId, 'providerId'),
      }, { onChild: callbacks.onChild }, context.signal);
    case 'provider.logout':
      return service.logoutProvider({
        account: optionalString(params.account),
        approved: optionalBoolean(params.approved),
        projectId: optionalString(params.projectId),
        providerId: requireString(params.providerId, 'providerId'),
      });
    case 'account.use':
      return service.useAccount({
        account: requireString(params.account, 'account'),
        approved: optionalBoolean(params.approved),
        providerId: requireString(params.providerId, 'providerId'),
      });
    case 'account.rename':
      return service.renameAccount({
        account: requireString(params.account, 'account'),
        approved: optionalBoolean(params.approved),
        newName: requireString(params.newName, 'newName'),
        preview: optionalBoolean(params.preview),
        providerId: requireString(params.providerId, 'providerId'),
      });
    case 'service.trust':
      return service.trustService({
        approved: optionalBoolean(params.approved),
        providerId: requireString(params.providerId, 'providerId'),
      });
    case 'http.request':
      return service.request({
        approved: optionalBoolean(params.approved),
        body: optionalText(params.body, 'body'),
        bodyEncoding: params.bodyEncoding === 'base64' ? 'base64' : 'utf8',
        headers: params.headers === undefined ? undefined : requireStringRecord(params.headers, 'headers'),
        method: requireString(params.method, 'method'),
        path: requireString(params.path, 'path'),
        account: optionalString(params.account),
        projectId: optionalString(params.projectId),
        providerId: requireString(params.providerId, 'providerId'),
      }, context.signal);
    case 'policy.explain':
      return service.explainPolicy({
        args: params.args === undefined ? undefined : requireStringArray(params.args, 'args'),
        interface: params.interface === 'http' ? 'http' : 'native',
        method: optionalString(params.method),
        path: optionalString(params.path),
        account: optionalString(params.account),
        projectId: optionalString(params.projectId),
        providerId: requireString(params.providerId, 'providerId'),
      });
    case 'machine.identity':
      return service.publicIdentity();
    case 'pair.export':
      return service.exportPairing({
        approved: optionalBoolean(params.approved),
        recipient: requireString(params.recipient, 'recipient'),
      });
    case 'pair.import':
      return service.importPairing({
        approved: optionalBoolean(params.approved),
        envelope: requireRecord(params.envelope, 'envelope') as never,
      });
    case 'doctor':
      return service.doctor(optionalString(params.projectId));
    case 'migration.notice':
      return service.migrationNotice();
    case 'vault.reset':
      if (params.approved !== true) throw new SignedInError('CONFIRMATION_REQUIRED', 'Reset needs explicit confirmation');
      return service.resetAll();
    case 'audit.list':
      return service.readAudit(typeof params.limit === 'number' ? params.limit : undefined);
    default:
      throw new SignedInError('UNKNOWN_METHOD', `Unknown daemon method '${request.method}'`);
  }
}

// Parses the first frame strictly so malformed input cannot reach secret-bearing service methods.
function parseRequest(value: unknown): IpcRequest {
  const record = requireRecord(value, 'request');
  if (record.version !== 1) {
    throw new SignedInError('IPC_VERSION_MISMATCH', 'Unsupported IPC protocol version', {
      requested: record.version,
      supported: 1,
    });
  }
  return {
    id: requireString(record.id, 'id'),
    method: requireString(record.method, 'method'),
    params: record.params,
    version: 1,
  };
}

// Accepts only base64 stdin bytes or cancellation after an operation has begun.
function parseControl(value: unknown): IpcControl {
  const record = requireRecord(value, 'control');
  if (record.event !== 'stdin' && record.event !== 'stdin-end' && record.event !== 'cancel') {
    throw new SignedInError('BAD_REQUEST', 'Unknown IPC control event');
  }
  if (record.event === 'stdin' && typeof record.payload !== 'string') {
    throw new SignedInError('BAD_REQUEST', 'IPC stdin control needs a base64 payload');
  }
  return {
    event: record.event,
    id: requireString(record.id, 'id'),
    ...(typeof record.payload === 'string' ? { payload: record.payload } : {}),
  };
}

// Encodes provider output so arbitrary bytes can share a newline-delimited JSON protocol safely.
function outputEvent(id: string, event: 'stderr' | 'stdout', chunk: Buffer): IpcEvent {
  return { data: chunk.toString('base64'), encoding: 'base64', event, id };
}

// Serializes errors with safe messages and stable codes while withholding internal stack traces.
function errorEvent(id: string, error: unknown): IpcEvent {
  return {
    error: {
      code: error instanceof SignedInError ? error.code : 'INTERNAL_ERROR',
      ...(error instanceof SignedInError && error.details !== undefined ? { details: error.details } : {}),
      message: safeErrorMessage(error),
    },
    event: 'error',
    id,
  };
}

// Writes one complete event frame and lets the socket provide backpressure for command output.
function send(socket: Socket, event: IpcEvent): void {
  if (!socket.destroyed) socket.write(`${JSON.stringify(event)}\n`);
}

// Removes only a proven stale Unix socket and refuses to unlink arbitrary filesystem entries.
async function removeStaleSocket(socketPath: string): Promise<void> {
  if (process.platform === 'win32' || !existsSync(socketPath)) return;
  if (!lstatSync(socketPath).isSocket()) throw new Error(`Refusing to replace non-socket path: ${socketPath}`);
  const active = await socketResponds(socketPath);
  if (active) throw new SignedInError('DAEMON_ALREADY_RUNNING', 'signed-in daemon is already running');
  unlinkSync(socketPath);
}

// Decodes canonical bounded stdin bytes so Buffer's permissive base64 parser cannot hide malformed controls.
function decodeInput(value: string | undefined): Buffer {
  if (value === undefined) throw new SignedInError('BAD_REQUEST', 'IPC stdin control needs a payload');
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length > maximumStdinChunkBytes) throw new SignedInError('BAD_REQUEST', 'IPC stdin chunk exceeded 256 KiB');
  if (decoded.toString('base64') !== value) throw new SignedInError('BAD_REQUEST', 'IPC stdin payload was not valid base64');
  return decoded;
}

// Sends TERM immediately and escalates only if a provider ignores cancellation or loses its client terminal.
function terminateChild(child: { kill: (signal?: NodeJS.Signals) => boolean; stdin: NodeJS.WritableStream }): void {
  child.stdin.end();
  child.kill('SIGTERM');
  const timer = setTimeout(() => child.kill('SIGKILL'), 3_000);
  timer.unref();
}

// Serializes stale-socket inspection and bind across concurrently auto-started daemon processes.
async function acquireStartupLock(paths: SignedInPaths): Promise<() => void> {
  const lockPath = path.join(paths.runtimeDir || paths.dataDir, 'daemon-start.lock');
  const owner = `${process.pid}:${Date.now()}`;
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try {
      const descriptor = openSync(lockPath, 'wx', 0o600);
      try { writeSync(descriptor, owner); } finally { closeSync(descriptor); }
      return () => {
        try {
          if (readFileSync(lockPath, 'utf8') === owner) unlinkSync(lockPath);
        } catch {
          // A removed or replaced startup lock no longer belongs to this process.
        }
      };
    } catch (error) {
      const code = error instanceof Error && 'code' in error ? (error as NodeJS.ErrnoException).code : undefined;
      if (code !== 'EEXIST') throw error;
      try {
        const pid = Number(readFileSync(lockPath, 'utf8').split(':', 1)[0]);
        if (Number.isInteger(pid) && !processIsAlive(pid)) unlinkSync(lockPath);
      } catch {
        // The owner may still be writing its short record; the next bounded retry will inspect it again.
      }
      await delay(25);
    }
  }
  throw new SignedInError('DAEMON_START_BUSY', 'Another signed-in daemon is still starting');
}

// Checks a startup-lock PID without sending it a state-changing signal.
function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error instanceof Error && 'code' in error && (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

// Captures the bound socket inode so an older daemon cannot unlink a newer daemon's replacement during shutdown.
function fileIdentity(socketPath: string): { dev: number; ino: number } {
  const stat = lstatSync(socketPath);
  return { dev: stat.dev, ino: stat.ino };
}

// Removes a Unix socket only while it is still the exact filesystem object this daemon bound.
function unlinkOwnedSocket(socketPath: string, identity: { dev: number; ino: number } | undefined): void {
  if (process.platform === 'win32' || !identity || !existsSync(socketPath)) return;
  const current = lstatSync(socketPath);
  if (current.isSocket() && current.dev === identity.dev && current.ino === identity.ino) unlinkSync(socketPath);
}

// Provides a short cooperative wait while another daemon finishes its serialized startup.
function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

// Probes a pre-existing socket briefly before deciding it is abandoned.
function socketResponds(socketPath: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.createConnection(socketPath);
    const timer = setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, 250);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(true);
    });
    socket.once('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

// Binds the owner-only Unix socket or Windows named pipe before the daemon reports readiness.
function listen(server: Server, socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.off('error', reject);
      resolve();
    });
  });
}

// Stops accepting new authority-bearing operations and waits for the listener to close.
function closeServer(server: Server): Promise<void> {
  if (!server.listening) return Promise.resolve();
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

// Narrows untrusted IPC objects before individual field validation.
function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new SignedInError('BAD_REQUEST', `${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

// Rejects missing identifiers and paths with precise protocol errors.
function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value === '') throw new SignedInError('BAD_REQUEST', `${label} must be a string`);
  return value;
}

// Preserves optional string fields without coercing other JSON values.
function optionalString(value: unknown): string | undefined {
  return value === undefined ? undefined : requireString(value, 'value');
}

// Accepts empty protocol text where emptiness is meaningful, such as an explicitly bodyless HTTP request.
function optionalText(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new SignedInError('BAD_REQUEST', `${label} must be a string`);
  return value;
}

// Preserves optional approval flags without accepting truthy strings from hand-built clients.
function optionalBoolean(value: unknown): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'boolean') throw new SignedInError('BAD_REQUEST', 'approval flag must be boolean');
  return value;
}

// Validates argv and project roots as arrays whose members cannot change type after parsing.
function requireStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) {
    throw new SignedInError('BAD_REQUEST', `${label} must be an array of strings`);
  }
  return value;
}

// Validates secret field maps without ever interpolating their values into an error message.
function requireStringRecord(value: unknown, label: string): Record<string, string> {
  const record = requireRecord(value, label);
  if (!Object.values(record).every((item) => typeof item === 'string')) {
    throw new SignedInError('BAD_REQUEST', `${label} must contain only strings`);
  }
  return record as Record<string, string>;
}
