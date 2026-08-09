import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { closeSync, existsSync, openSync } from 'node:fs';
import net, { type Socket } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ensureSignedInDirectories, signedInBuild, type SignedInPaths } from './paths.js';
import type { IpcControl, IpcEvent, IpcPingResult, IpcRequest } from './types.js';

const connectTimeoutMs = 2_000;
const defaultFirstFrameTimeoutMs = 15_000;
const maximumFrameBytes = 64 * 1024 * 1024;
const maximumQueuedInputBytes = 1024 * 1024;
const maximumStdinChunkBytes = 256 * 1024;
const startupTimeoutMs = 8_000;
const daemonStarts = new Map<string, Promise<void>>();

export class SignedInClientError extends Error {
  readonly code: string;
  readonly details?: unknown;

  // Preserves daemon error codes for approval retries and polished CLI guidance.
  constructor(code: string, message: string, details?: unknown) {
    super(message);
    this.name = 'SignedInClientError';
    this.code = code;
    this.details = details;
  }
}

export interface DaemonCallHandlers {
  firstFrameTimeoutMs?: number;
  onStderr?: (chunk: Buffer) => void;
  onStdout?: (chunk: Buffer) => void;
}

export interface StreamingCall {
  cancel: () => void;
  endStdin: () => void;
  result: Promise<unknown>;
  sendStdin: (chunk: Buffer) => void;
}

// Calls one daemon method while bounding connection, first-response, parsing, and pre-connect input memory.
export function callDaemon(
  paths: SignedInPaths,
  method: string,
  params: unknown = {},
  handlers: DaemonCallHandlers = {},
): StreamingCall {
  const id = randomUUID();
  const socket = net.createConnection(paths.socketPath);
  const queuedControls: IpcControl[] = [];
  let buffer = '';
  let firstFrameReceived = false;
  let queuedInputBytes = 0;
  let requestSent = false;
  let settled = false;
  let resolveResult!: (value: unknown) => void;
  let rejectResult!: (error: Error) => void;
  const result = new Promise<unknown>((resolve, reject) => {
    resolveResult = resolve;
    rejectResult = reject;
  });
  const connectTimer = setTimeout(() => {
    fail(new SignedInClientError('DAEMON_CONNECT_TIMEOUT', "signed-in's background helper could not be reached", {
      socketPath: paths.socketPath,
      timeoutMs: connectTimeoutMs,
    }));
  }, connectTimeoutMs);
  const firstFrameTimer = setTimeout(() => {
    fail(new SignedInClientError('DAEMON_TIMEOUT', "signed-in's background helper stopped responding", {
      method,
      remedy: 'signed-in daemon restart',
      timeoutMs: handlers.firstFrameTimeoutMs ?? defaultFirstFrameTimeoutMs,
    }));
  }, handlers.firstFrameTimeoutMs ?? defaultFirstFrameTimeoutMs);

  // Settles a failed call exactly once and tears down the transport so the daemon cancels any active child.
  function fail(error: Error): void {
    if (settled) return;
    settled = true;
    clearTimeout(connectTimer);
    clearTimeout(firstFrameTimer);
    rejectResult(error);
    socket.destroy();
  }

  // Settles a successful call only after a validated terminal result frame arrives.
  function succeed(value: unknown): void {
    if (settled) return;
    settled = true;
    clearTimeout(connectTimer);
    clearTimeout(firstFrameTimer);
    resolveResult(value);
    socket.end();
  }

  // Marks the first complete frame so streaming provider commands are not capped by a wall-clock deadline.
  function acceptEvent(event: IpcEvent): void {
    if (!firstFrameReceived) {
      firstFrameReceived = true;
      clearTimeout(firstFrameTimer);
    }
    if (event.event === 'accepted') return;
    if (event.event === 'stdout') handlers.onStdout?.(decodeBase64(event.data, 'stdout'));
    if (event.event === 'stderr') handlers.onStderr?.(decodeBase64(event.data, 'stderr'));
    if (event.event === 'result') succeed(event.result);
    if (event.event === 'error') fail(new SignedInClientError(event.error.code, event.error.message, event.error.details));
  }

  // Queues controls until the request frame is written, preserving request-first framing even on immediate cancellation.
  function sendOrQueue(control: IpcControl): void {
    if (settled) return;
    if (!requestSent) {
      queuedControls.push(control);
      return;
    }
    sendControl(socket, control);
  }

  socket.setEncoding('utf8');
  socket.once('connect', () => {
    clearTimeout(connectTimer);
    const request: IpcRequest = { id, method, params, version: 1 };
    requestSent = true;
    socket.write(`${JSON.stringify(request)}\n`);
    for (const control of queuedControls.splice(0)) sendControl(socket, control);
  });
  socket.on('data', (chunk: string) => {
    if (settled) return;
    buffer += chunk;
    try {
      while (buffer.includes('\n')) {
        const newline = buffer.indexOf('\n');
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        if (!line.trim()) continue;
        if (Buffer.byteLength(line, 'utf8') > maximumFrameBytes) throw protocolError('IPC response frame exceeded 64 MiB');
        acceptEvent(parseEvent(JSON.parse(line) as unknown, id));
        if (settled) return;
      }
      if (Buffer.byteLength(buffer, 'utf8') > maximumFrameBytes) throw protocolError('IPC response frame exceeded 64 MiB');
    } catch (error) {
      fail(error instanceof SignedInClientError ? error : protocolError('IPC response was not valid JSON'));
    }
  });
  socket.once('error', (error: NodeJS.ErrnoException) => {
    const requestMayHaveRun = requestSent || firstFrameReceived;
    if (!settled) fail(new SignedInClientError(requestMayHaveRun ? 'DAEMON_DISCONNECTED' : 'DAEMON_UNAVAILABLE', requestMayHaveRun
      ? 'signed-in daemon disconnected before replying'
      : "signed-in's background helper is not running", {
      ...(error.code ? { cause: error.code } : {}),
      ...(requestMayHaveRun ? { method, remedy: 'signed-in daemon restart' } : {}),
      socketPath: paths.socketPath,
    }));
  });
  socket.once('close', () => {
    if (!settled) fail(new SignedInClientError('DAEMON_DISCONNECTED', 'signed-in daemon disconnected before replying', {
      method,
      remedy: 'signed-in daemon restart',
    }));
  });
  result.catch(() => undefined);
  return {
    cancel: () => sendOrQueue({ event: 'cancel', id }),
    endStdin: () => sendOrQueue({ event: 'stdin-end', id }),
    result,
    sendStdin: (chunk) => {
      if (settled || chunk.length === 0) return;
      if (!requestSent && queuedInputBytes + chunk.length > maximumQueuedInputBytes) {
        fail(new SignedInClientError('IPC_INPUT_LIMIT', 'Too much provider input was queued before the daemon connected'));
        return;
      }
      if (!requestSent) queuedInputBytes += chunk.length;
      for (let offset = 0; offset < chunk.length; offset += maximumStdinChunkBytes) {
        sendOrQueue({ event: 'stdin', id, payload: chunk.subarray(offset, offset + maximumStdinChunkBytes).toString('base64') });
      }
    },
  };
}

// Coalesces same-process callers while the daemon's startup lock serializes callers from separate processes.
export async function ensureDaemon(paths: SignedInPaths): Promise<void> {
  const existing = daemonStarts.get(paths.socketPath);
  if (existing) return existing;
  const pending = ensureDaemonOnce(paths).finally(() => daemonStarts.delete(paths.socketPath));
  daemonStarts.set(paths.socketPath, pending);
  return pending;
}

// Restarts a protocol-compatible older build once, then launches and verifies the bundled daemon.
async function ensureDaemonOnce(paths: SignedInPaths): Promise<void> {
  ensureSignedInDirectories(paths);
  let probe = await probeDaemon(paths);
  if (probe.state === 'ready') return;
  if (probe.state === 'skew') {
    await stopSkewedDaemon(paths);
    probe = await probeDaemon(paths);
  }
  if (probe.state === 'ready') return;
  if (probe.state === 'unresponsive' || probe.state === 'incompatible') throw probe.error;
  const daemonEntry = locateDaemonEntry();
  const logDescriptor = openSync(paths.daemonLogFile, 'a', 0o600);
  let childFailure: { code: number | null; signal: NodeJS.Signals | null } | undefined;
  try {
    const child = spawn(process.execPath, [...runtimeLoaderArgs(daemonEntry), daemonEntry], {
      detached: true,
      env: { ...process.env, SIGNED_IN_DAEMONIZED: '1', SIGNED_IN_EXPECTED_BUILD: signedInBuild },
      stdio: ['ignore', logDescriptor, logDescriptor],
    });
    child.once('exit', (code, signal) => { childFailure = { code, signal }; });
    child.unref();
  } catch (error) {
    throw new SignedInClientError('DAEMON_START_FAILED', "signed-in's background helper could not be launched", {
      logFile: paths.daemonLogFile,
      reason: error instanceof Error ? error.message : String(error),
    });
  } finally {
    closeSync(logDescriptor);
  }
  const deadline = Date.now() + startupTimeoutMs;
  while (Date.now() < deadline) {
    await delay(50);
    probe = await probeDaemon(paths);
    if (probe.state === 'ready') return;
    if (probe.state === 'skew' || probe.state === 'incompatible' || probe.state === 'unresponsive') throw probe.error;
  }
  throw new SignedInClientError(childFailure ? 'DAEMON_START_CRASHED' : 'DAEMON_START_TIMEOUT', "signed-in's background helper didn't start", {
    ...(childFailure ? { exitCode: childFailure.code, signal: childFailure.signal } : {}),
    logFile: paths.daemonLogFile,
    remedy: 'signed-in doctor',
  });
}

type DaemonProbe =
  | { state: 'absent' }
  | { error: SignedInClientError; state: 'incompatible' | 'skew' | 'unresponsive' }
  | { ping: IpcPingResult; state: 'ready' };

// Uses a short protocol ping to distinguish absence, build skew, malformed peers, and a wedged active listener.
async function probeDaemon(paths: SignedInPaths): Promise<DaemonProbe> {
  try {
    const value = await callDaemon(paths, 'ping', {}, { firstFrameTimeoutMs: 500 }).result;
    if (!isRecord(value) || typeof value.pid !== 'number') throw protocolError('Daemon ping response was malformed');
    const protocol = value.protocol ?? value.version;
    if (protocol !== 1) {
      return { error: new SignedInClientError('IPC_VERSION_MISMATCH', 'signed-in was upgraded while its helper was running', {
        daemonProtocol: protocol,
        remedy: 'signed-in daemon restart',
      }), state: 'incompatible' };
    }
    if (typeof value.build !== 'string' || value.build !== signedInBuild) {
      return { error: new SignedInClientError('DAEMON_BUILD_MISMATCH', 'signed-in was upgraded while its helper was running', {
        daemonBuild: typeof value.build === 'string' ? value.build : 'legacy',
        clientBuild: signedInBuild,
        remedy: 'signed-in daemon restart',
      }), state: 'skew' };
    }
    return { ping: { build: value.build, pid: value.pid, protocol: 1, version: 1 }, state: 'ready' };
  } catch (error) {
    if (error instanceof SignedInClientError && error.code === 'DAEMON_UNAVAILABLE') return { state: 'absent' };
    if (error instanceof SignedInClientError && ['DAEMON_TIMEOUT', 'DAEMON_CONNECT_TIMEOUT'].includes(error.code)) {
      return { error, state: 'unresponsive' };
    }
    return {
      error: error instanceof SignedInClientError ? error : protocolError('Daemon ping failed'),
      state: 'incompatible',
    };
  }
}

// Requests a graceful upgrade handoff and refuses to claim success until the old listener is actually gone.
async function stopSkewedDaemon(paths: SignedInPaths): Promise<void> {
  try {
    await callDaemon(paths, 'daemon.shutdown', { ifIdle: true }, { firstFrameTimeoutMs: 2_000 }).result;
  } catch (error) {
    if (!(error instanceof SignedInClientError) || !['DAEMON_DISCONNECTED', 'DAEMON_UNAVAILABLE'].includes(error.code)) throw error;
  }
  const deadline = Date.now() + 3_000;
  while (Date.now() < deadline) {
    await delay(50);
    const probe = await probeDaemon(paths);
    if (probe.state === 'absent' || probe.state === 'ready') return;
  }
  throw new SignedInClientError('DAEMON_RESTART_FAILED', "signed-in's older background helper did not stop", {
    remedy: 'signed-in daemon restart',
  });
}

// Validates a daemon event before any untrusted field reaches output handlers or promise settlement.
function parseEvent(value: unknown, expectedId: string): IpcEvent {
  if (!isRecord(value) || value.id !== expectedId || typeof value.event !== 'string') throw protocolError('IPC response frame was malformed');
  if (value.event === 'accepted') return { event: 'accepted', id: expectedId };
  if (value.event === 'result') return { event: 'result', id: expectedId, result: value.result };
  if (value.event === 'stdout' || value.event === 'stderr') {
    if (value.encoding !== 'base64' || typeof value.data !== 'string') throw protocolError('IPC output frame was malformed');
    decodeBase64(value.data, value.event);
    return { data: value.data, encoding: 'base64', event: value.event, id: expectedId };
  }
  if (value.event === 'error' && isRecord(value.error) && typeof value.error.code === 'string' && typeof value.error.message === 'string') {
    return {
      error: { code: value.error.code, ...(value.error.details !== undefined ? { details: value.error.details } : {}), message: value.error.message },
      event: 'error',
      id: expectedId,
    };
  }
  throw protocolError('IPC response event was unknown');
}

// Decodes only canonical base64 so malformed output cannot be silently truncated or reinterpreted.
function decodeBase64(value: string, label: string): Buffer {
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) throw protocolError(`IPC ${label} payload was not valid base64`);
  return decoded;
}

// Creates the stable structured error used for every malformed daemon frame.
function protocolError(message: string): SignedInClientError {
  return new SignedInClientError('DAEMON_PROTOCOL', message, { remedy: 'signed-in daemon restart' });
}

// Narrows decoded JSON without trusting inherited or array properties as protocol records.
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// Locates the compiled sibling in installations and the TypeScript sibling under `tsx` development.
function locateDaemonEntry(): string {
  const directory = path.dirname(fileURLToPath(import.meta.url));
  const compiled = path.join(directory, 'daemon-entry.js');
  const source = path.join(directory, 'daemon-entry.ts');
  if (existsSync(compiled)) return compiled;
  if (existsSync(source)) return source;
  throw new SignedInClientError('DAEMON_ENTRY_MISSING', 'Cannot locate signed-in daemon entry point');
}

// Reuses the current tsx loader only when launching a TypeScript source entry.
function runtimeLoaderArgs(entry: string): string[] {
  return entry.endsWith('.ts') ? process.execArgv : [];
}

// Writes control frames only after the request and silently ignores controls after transport teardown.
function sendControl(socket: Socket, control: IpcControl): void {
  if (!socket.destroyed && socket.writable) socket.write(`${JSON.stringify(control)}\n`);
}

// Provides a non-blocking retry interval while daemon lifecycle transitions remain responsive.
function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
