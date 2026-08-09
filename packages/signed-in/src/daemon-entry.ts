#!/usr/bin/env node

import { appendFileSync } from 'node:fs';
import process from 'node:process';

import { startSignedInDaemon, type SignedInDaemon } from './daemon.js';
import { resolveSignedInPaths, signedInBuild } from './paths.js';
import { safeErrorMessage, SignedInError } from './service.js';

const paths = resolveSignedInPaths();
let daemon: SignedInDaemon | undefined;
let shutdown: Promise<never> | undefined;

// Appends a safe structured fatal record because detached operation has no terminal to explain startup or runtime crashes.
function reportFatalError(error: unknown): void {
  try {
    appendFileSync(paths.daemonLogFile, `${JSON.stringify({
      code: error instanceof SignedInError ? error.code : 'INTERNAL_ERROR',
      level: 'error',
      message: safeErrorMessage(error),
      timestamp: new Date().toISOString(),
    })}\n`, { mode: 0o600 });
  } catch {
    // The original failure remains the most useful exit signal when even the log directory is unavailable.
  }
}

// Closes sockets and provider children once before using an explicit process exit as the final bounded lifecycle step.
function stopDaemon(exitCode: number, error?: unknown): Promise<never> {
  if (shutdown) return shutdown;
  shutdown = (async () => {
    if (error !== undefined) reportFatalError(error);
    try {
      await daemon?.close();
    } catch (closeError) {
      reportFatalError(closeError);
      exitCode = 1;
    }
    process.exit(exitCode);
  })();
  return shutdown;
}

try {
  const expectedBuild = process.env.SIGNED_IN_EXPECTED_BUILD;
  if (expectedBuild && expectedBuild !== signedInBuild) {
    throw new SignedInError('DAEMON_BUILD_MISMATCH', 'The launched daemon entry did not match its client build');
  }
  daemon = await startSignedInDaemon(paths);
  for (const signal of ['SIGHUP', 'SIGINT', 'SIGTERM'] as const) {
    process.once(signal, () => { void stopDaemon(0); });
  }
  process.once('uncaughtException', (error) => { void stopDaemon(1, error); });
  process.once('unhandledRejection', (error) => { void stopDaemon(1, error); });
} catch (error) {
  if (error instanceof SignedInError && error.code === 'DAEMON_ALREADY_RUNNING') process.exit(0);
  reportFatalError(error);
  process.exit(1);
}
