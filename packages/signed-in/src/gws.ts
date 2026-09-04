import { existsSync, lstatSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';

import { materializeBundle, snapshotDeclaredPaths, type SessionSandbox } from './session.js';
import type { SessionBundle } from './types.js';

const readCommands = [
  ['gmail', 'users', 'getProfile'],
  ['gmail', 'users', 'messages', 'list'],
  ['gmail', 'users', 'messages', 'get'],
  ['gmail', 'users', 'messages', 'attachments', 'get'],
  ['gmail', 'users', 'threads', 'list'],
  ['gmail', 'users', 'threads', 'get'],
  ['gmail', 'users', 'labels', 'list'],
  ['gmail', 'users', 'labels', 'get'],
  ['gmail', 'users', 'drafts', 'list'],
  ['gmail', 'users', 'drafts', 'get'],
  ['gmail', 'users', 'history', 'list'],
];
const booleanFlags = new Set(['--help', '-h', '--dry-run', '--page-all']);
const valueFlags = new Set(['--params', '--format', '--page-limit', '--page-delay']);
const readParameters = new Set([
  'userId', 'id', 'messageId', 'q', 'maxResults', 'pageToken', 'labelIds', 'labelId',
  'includeSpamTrash', 'format', 'metadataHeaders', 'startHistoryId', 'historyTypes',
  'fields', 'alt', 'prettyPrint',
]);
const clientConfigPath = '.config/gws/client_secret.json';

// Redacts reusable login material without treating public OAuth client IDs and endpoint URLs as bearer secrets.
export function gwsLoginSecrets(session: SessionBundle): string[] {
  return session.files.flatMap((file) => {
    const contents = Buffer.from(file.contents, 'base64').toString('utf8');
    if (file.path === '.config/gws/.encryption_key') return [contents.trim()];
    if (file.path !== clientConfigPath) return [];
    try {
      const config = JSON.parse(contents) as { installed?: { client_secret?: unknown } };
      return typeof config.installed?.client_secret === 'string' ? [config.installed.client_secret] : [];
    } catch { return []; }
  });
}

// Keeps this email capability fail-closed as upstream adds services, helpers, or file/credential flags.
export function allowsGwsGmailCommand(args: string[]): boolean {
  if (args.length === 1 && ['--help', '-h', '--version', '-V'].includes(args[0]!)) return true;
  const command = readCommands.find((candidate) => candidate.every((word, index) => args[index] === word));
  if (!command) {
    // Permit help on a known read-command ancestor, but never execute an unreviewed command.
    return ['--help', '-h'].includes(args.at(-1) ?? '')
      && args.length > 1
      && readCommands.some((candidate) => args.slice(0, -1).every((word, index) => candidate[index] === word));
  }
  const seen = new Set<string>();
  for (let index = command.length; index < args.length; index += 1) {
    const argument = args[index]!;
    const separator = argument.indexOf('=');
    const flag = separator < 0 ? argument : argument.slice(0, separator);
    if (seen.has(flag)) return false;
    seen.add(flag);
    if (booleanFlags.has(flag)) {
      if (separator >= 0) return false;
      continue;
    }
    if (!valueFlags.has(flag)) return false;
    const value = separator < 0 ? args[++index] : argument.slice(separator + 1);
    if (!value) return false;
    if (flag === '--params') {
      // Inline JSON only: @file inputs must not turn a read into private-file disclosure.
      try {
        const parsed: unknown = JSON.parse(value);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return false;
        if (Object.keys(parsed).some((key) => !readParameters.has(key))) return false;
        if ('userId' in parsed && parsed.userId !== 'me') return false;
      } catch { return false; }
    } else if (flag === '--format') {
      if (!['json', 'table', 'yaml', 'csv'].includes(value)) return false;
    } else if (!/^\d+$/u.test(value)) return false;
  }
  return true;
}

// Prevents dotenv discovery, ambient Google auth, and machine-keyring coupling across Gmail aliases.
export function isolateGwsSandbox(sandbox: SessionSandbox): void {
  for (const name of Object.keys(sandbox.env)) {
    if (/^(?:GOOGLE_|GWS_|GCLOUD_|CLOUDSDK_|RUST_LOG$)/iu.test(name)) delete sandbox.env[name];
  }
  Object.assign(sandbox.env, {
    GOOGLE_WORKSPACE_CLI_CONFIG_DIR: path.join(sandbox.home, '.config', 'gws'),
    GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND: 'file',
    CLOUDSDK_CONFIG: path.join(sandbox.home, '.config', 'gcloud'),
  });
  // dotenvy stops at this empty file instead of walking into the project or shared temp parents.
  writeFileSync(path.join(sandbox.home, '.env'), '', { mode: 0o600 });
}

// Copies only the OAuth application configuration during human-started login, never an ambient user session.
export function seedGwsClientConfig(sandbox: SessionSandbox, sourceHome = homedir()): void {
  if (existsSync(path.join(sandbox.home, clientConfigPath))) return;
  for (const relative of ['.config', '.config/gws', clientConfigPath]) {
    const source = path.join(sourceHome, relative);
    if (existsSync(source) && lstatSync(source).isSymbolicLink()) {
      throw new Error('GWS OAuth client configuration must not use symlinks. See signed-in help gws.');
    }
  }
  const bundle = snapshotDeclaredPaths(sourceHome, [{ source: clientConfigPath, target: clientConfigPath }], 64 * 1024);
  if (bundle.files.length !== 1) {
    throw new Error('GWS needs an OAuth desktop client configured first. Run gws auth setup in your terminal, then signed-in login gws. See signed-in help gws.');
  }
  materializeBundle(sandbox.home, bundle);
}
