import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

// Keeps the primary help small while proving every deeper human route remains discoverable.
test('signed-in help stays progressive and daemon-free', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-ux-help-'));
  const help = runCli(['--help'], stateRoot);
  assert.equal(help.status, 0, help.stderr);
  assert.ok(help.stdout.trimEnd().split('\n').length <= 27);
  assert.match(help.stdout, /signed-in aws s3 ls/u);
  assert.match(help.stdout, /signed-in demo\s+preview fictional connections/u);
  assert.match(help.stdout, /help connections/u);
  assert.match(help.stdout, /help troubleshooting/u);
  assert.doesNotMatch(help.stdout, /daemon lifecycle|recipient-bound ciphertext/u);

  for (const topic of ['connections', 'machines', 'projects', 'troubleshooting']) {
    const group = runCli(['help', topic], stateRoot);
    assert.equal(group.status, 0, group.stderr);
    assert.match(group.stdout, new RegExp(topic, 'iu'));
  }
  for (const command of ['projects', 'setup']) {
    const compatibility = runCli([command, '--help'], stateRoot);
    assert.equal(compatibility.status, 0, compatibility.stderr);
  }
  assert.equal(existsSync(path.join(stateRoot, 'runtime')), false);
});

// Uses an unreadable fixture state to prove the public demo route never discovers accounts or starts the daemon.
test('demo renders fictional connections without consulting machine state', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-ux-demo-'));
  const configDir = path.join(stateRoot, 'config');
  const statePath = path.join(configDir, 'state.json');
  mkdirSync(configDir);
  writeFileSync(statePath, '{invalid machine state');

  const screen = runCli(['demo'], stateRoot);
  assert.equal(screen.status, 0, screen.stderr);
  assert.match(screen.stdout, /13 services connected · 34 connections/u);
  assert.match(screen.stdout, /production · also staging, sandbox/u);
  assert.match(screen.stdout, /acme1 · also acme2, personal/u);
  assert.equal(screen.stderr, '');
  assert.doesNotMatch(screen.stdout, /What would you like to do/u);

  const json = runCli(['demo', '--json'], stateRoot);
  assert.equal(json.status, 0, json.stderr);
  const payload = JSON.parse(json.stdout) as { demo: boolean; serviceCount: number; connectionCount: number; services: unknown[] };
  assert.equal(payload.demo, true);
  assert.equal(payload.serviceCount, payload.services.length);
  assert.equal(payload.connectionCount, 34);
  assert.equal(json.stderr, '');

  const quiet = runCli(['--quiet', 'demo'], stateRoot);
  assert.equal(quiet.status, 0, quiet.stderr);
  assert.equal(quiet.stdout, '');
  assert.equal(quiet.stderr, '');
  for (const args of [['demo', '--help'], ['help', 'demo']]) {
    const help = runCli(args, stateRoot);
    assert.equal(help.status, 0, help.stderr);
    assert.match(help.stdout, /signed-in demo/u);
    assert.match(help.stdout, /fictional/u);
  }
  for (const args of [['demo', 'unexpected'], ['demo', '--unexpected']]) {
    const rejected = runCli(args, stateRoot);
    assert.equal(rejected.status, 1, rejected.stderr);
    assert.match(rejected.stderr, /Unexpected demo argument|Unknown option/u);
  }
  assert.equal(readFileSync(statePath, 'utf8'), '{invalid machine state');
  assert.equal(existsSync(path.join(stateRoot, 'runtime')), false);
  assert.equal(existsSync(path.join(stateRoot, 'data')), false);
});

// Exercises the packaged skill command through its real CLI boundary without touching personal agent directories.
test('skill install is local, idempotent, and protects modified copies', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-ux-skill-state-'));
  const projectRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-ux-skill-project-'));
  mkdirSync(path.join(projectRoot, '.git'));
  const destination = path.join(projectRoot, '.agents', 'skills', 'signed-in', 'SKILL.md');
  const args = ['skill', 'install', '--local', '--agent', 'codex', '--root', projectRoot, '--json'];

  const installed = runCli(args, stateRoot);
  assert.equal(installed.status, 0, installed.stderr);
  assert.equal((JSON.parse(installed.stdout) as { results: Array<{ outcome: string }> }).results[0]?.outcome, 'installed');
  assert.match(readFileSync(destination, 'utf8'), /name: signed-in/u);

  const current = runCli(args, stateRoot);
  assert.equal(current.status, 0, current.stderr);
  assert.equal((JSON.parse(current.stdout) as { results: Array<{ outcome: string }> }).results[0]?.outcome, 'current');

  writeFileSync(destination, 'operator copy\n');
  const protectedCopy = runCli(args, stateRoot);
  assert.equal(protectedCopy.status, 1, protectedCopy.stderr);
  assert.match(protectedCopy.stderr, /modified[\s\S]*--force/u);
  assert.equal(readFileSync(destination, 'utf8'), 'operator copy\n');

  const updated = runCli([...args, '--force'], stateRoot);
  assert.equal(updated.status, 0, updated.stderr);
  assert.equal((JSON.parse(updated.stdout) as { results: Array<{ outcome: string }> }).results[0]?.outcome, 'updated');
  assert.match(readFileSync(destination, 'utf8'), /name: signed-in/u);
  assert.equal(existsSync(path.join(stateRoot, 'runtime')), false);
});

// Exercises the real redirected status surface at phone-sized terminal width without relying on color or glyphs.
test('status remains plain and readable in narrow and ASCII terminals', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-ux-narrow-'));
  const status = runCli(['status', '--all'], stateRoot, {
    COLUMNS: '48',
    SIGNED_IN_ASCII: '1',
  });
  assert.equal(status.status, 0, status.stderr);
  assert.match(status.stdout, /AWS\s+- not connected/u);
  assert.match(status.stdout, /DatoCMS\s+- not connected/u);
  assert.match(status.stdout, /Cloud infrastructure, release storage/u);
  assert.doesNotMatch(status.stdout, /\u001b\[/u);
  assert.ok(status.stdout.trimEnd().split('\n').every((line) => Array.from(line).length <= 48));
  assert.equal(existsSync(path.join(stateRoot, 'runtime')), false);
});

// Locks the prompt-free automation shapes for pristine status, JSON, and quiet operation.
test('pristine automation receives one JSON result or true silence', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-ux-automation-'));
  const json = runCli(['status', '--json'], stateRoot);
  assert.equal(json.status, 0, json.stderr);
  assert.equal(json.stderr, '');
  const payload = JSON.parse(json.stdout) as { catalog: { configured: number }; schema: number; services: unknown[] };
  assert.equal(payload.schema, 1);
  assert.equal(payload.catalog.configured, 0);
  assert.deepEqual(payload.services, []);

  const quiet = runCli(['status', '--quiet'], stateRoot);
  assert.equal(quiet.status, 0, quiet.stderr);
  assert.equal(quiet.stdout, '');
  assert.equal(quiet.stderr, '');
  assert.equal(existsSync(path.join(stateRoot, 'runtime')), false);
});

// Ensures input mistakes fail before the human-required gate and always include one runnable recovery line.
test('non-interactive input errors are actionable without masquerading as login prompts', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-ux-errors-'));
  const unknown = runCli(['login', 'not-a-service'], stateRoot);
  assert.equal(unknown.status, 1, unknown.stderr);
  assert.match(unknown.stderr, /Unknown service 'not-a-service'/u);
  assert.match(unknown.stderr, /signed-in status --all/u);
  assert.doesNotMatch(unknown.stderr, /needs a person/u);

  const conflictingBody = runCli(['request', 'polar', 'POST', '/v1/products', '--stdin', '--data', '{}'], stateRoot);
  assert.equal(conflictingBody.status, 1, conflictingBody.stderr);
  assert.match(conflictingBody.stderr, /Choose only one request body source/u);
  assert.match(conflictingBody.stderr, /signed-in request --help/u);

  const duplicateBody = runCli(['request', 'polar', 'POST', '/v1/products', '--data', 'one', '--data', 'two'], stateRoot);
  assert.equal(duplicateBody.status, 1, duplicateBody.stderr);
  assert.match(duplicateBody.stderr, /--data can be supplied only once/u);
  runCli(['daemon', 'stop'], stateRoot);
});

// Proves upward config discovery binds the config directory rather than whichever nested shell invoked trust.
test('project trust defaults its root to the config directory', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-ux-project-'));
  const projectRoot = path.join(stateRoot, 'project');
  const nested = path.join(projectRoot, 'packages', 'web');
  const configPath = path.join(projectRoot, 'signed-in.config.json');
  mkdirSync(nested, { recursive: true });
  writeFileSync(configPath, JSON.stringify({
    project: { id: 'ux-project', name: 'UX Project' },
    providers: {},
    schemaVersion: 2,
    services: { aws: true },
  }));
  const canonicalProjectRoot = realpathSync(projectRoot);
  const canonicalNested = realpathSync(nested);

  const trust = runCli(['--json', 'project', 'trust'], stateRoot, {}, nested);
  assert.equal(trust.status, 75, trust.stderr);
  const failure = JSON.parse(trust.stderr) as { error: { remedy: string } };
  assert.match(failure.error.remedy, new RegExp(`--root ${escapeRegExp(JSON.stringify(canonicalProjectRoot))}`, 'u'));
  assert.doesNotMatch(failure.error.remedy, new RegExp(escapeRegExp(canonicalNested), 'u'));
  runCli(['daemon', 'stop'], stateRoot);
});

// Keeps one malformed MCP frame from taking the agent transport down before the next valid request.
test('MCP reports parse errors and continues serving the stream', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-ux-mcp-'));
  const result = runCli(
    ['mcp'],
    stateRoot,
    {},
    path.resolve(import.meta.dirname, '..'),
    '{bad-json}\n{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n',
  );
  assert.equal(result.status, 0, result.stderr);
  const responses = result.stdout.trim().split('\n').map((line) => JSON.parse(line));
  assert.equal(responses[0]?.error?.code, -32700);
  assert.equal(responses[1]?.result?.serverInfo?.name, 'signed-in');
  runCli(['daemon', 'stop'], stateRoot);
});

// Proves every restart remedy printed by the client is a real, truthful lifecycle command.
test('daemon restart replaces the live helper and remains healthy', () => {
  const stateRoot = mkdtempSync(path.join(tmpdir(), 'signed-in-ux-restart-'));
  const started = runCli(['daemon', 'start'], stateRoot);
  assert.equal(started.status, 0, started.stderr);
  const firstPid = started.stdout.match(/pid (\d+)/u)?.[1];
  assert.ok(firstPid);
  const restarted = runCli(['daemon', 'restart'], stateRoot);
  assert.equal(restarted.status, 0, restarted.stderr);
  const secondPid = restarted.stdout.match(/pid (\d+)/u)?.[1];
  assert.ok(secondPid);
  assert.notEqual(secondPid, firstPid);
  const status = runCli(['daemon', 'status'], stateRoot);
  assert.equal(status.status, 0, status.stderr);
  assert.match(status.stdout, new RegExp(`pid ${secondPid}`, 'u'));
  runCli(['daemon', 'stop'], stateRoot);
});

// Runs the source CLI against isolated homes so UX tests cannot read or mutate operator state.
function runCli(
  args: string[],
  stateRoot: string,
  environment: NodeJS.ProcessEnv = {},
  cwd = path.resolve(import.meta.dirname, '..'),
  input?: string,
): { status: number | null; stderr: string; stdout: string } {
  const result = spawnSync(process.execPath, [
    path.resolve(import.meta.dirname, '../node_modules/tsx/dist/cli.mjs'),
    path.resolve(import.meta.dirname, '../packages/signed-in/src/cli.ts'),
    ...args,
  ], {
    cwd,
    encoding: 'utf8',
    ...(input !== undefined ? { input } : {}),
    env: {
      ...process.env,
      NO_COLOR: '1',
      SIGNED_IN_CONFIG_HOME: path.join(stateRoot, 'config'),
      SIGNED_IN_DATA_HOME: path.join(stateRoot, 'data'),
      SIGNED_IN_RUNTIME_DIR: path.join(stateRoot, 'runtime'),
      TERM: 'xterm-256color',
      ...environment,
    },
    timeout: 15_000,
  });
  return { status: result.status, stderr: result.stderr, stdout: result.stdout };
}

// Escapes temporary paths before they become literal regular-expression assertions.
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}
