import { existsSync } from 'node:fs';
import path from 'node:path';

// Bypasses Windows command shims so repository automation remains argument-safe and portable.
export function packageManagerCommand(manager) {
  if (process.platform !== 'win32') return { executable: manager, prefixArgs: [] };
  const cliPath = manager === 'pnpm'
    ? process.env.npm_execpath
    : path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
  if (!cliPath || !existsSync(cliPath)) {
    throw new Error(`Could not locate the ${manager} JavaScript entrypoint on Windows`);
  }
  return { executable: process.execPath, prefixArgs: [cliPath] };
}
