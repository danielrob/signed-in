#!/usr/bin/env node

import { execFile, execFileSync, spawn } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import { allocateAlias, normalizeAlias } from './aliases.js';
import { builtInServices } from './catalog.js';
import { callDaemon, ensureDaemon, SignedInClientError, type StreamingCall } from './client.js';
import { commandAvailable, installCli, resolveCliInstallPlan } from './cli-install.js';
import { discoverProjectConfig, isSafeAccountName, loadMachineState, loadProjectConfig, reservedAccountNames, selectRegisteredProject } from './config.js';
import { credentialValidationMessage } from './credential-validation.js';
import { installDaemonService, uninstallDaemonService } from './daemon-install.js';
import { renderDemoScreen } from './demo.js';
import { findProviderLoginUrl, openExternalUrl } from './external-url.js';
import type { GatewayResponse } from './http-gateway.js';
import { runMcpServer } from './mcp.js';
import { ensureSignedInDirectories, resolveSignedInPaths } from './paths.js';
import {
  formatConnectionRepairTargets,
  selectConnectionPingTargets,
  type ConnectionPingTarget,
} from './ping-targets.js';
import { confirm, promptText } from './prompt.js';
import { eraseLocalSignedInState } from './recovery.js';
import {
  bundledSkillDirectory,
  detectSkillAgents,
  findSkillProjectRoot,
  inspectSkillInstall,
  installSkill,
  skillAgent,
  skillAgents,
  skillInstallDestination,
  type SkillAgentId,
  type SkillInstallScope,
  type SkillInstallState,
} from './skill-install.js';
import {
  TuiCancelledError,
  tuiConfirm,
  tuiHint,
  tuiIntro,
  tuiMultiselect,
  tuiNote,
  tuiOutro,
  tuiPassword,
  tuiSelect,
  tuiSelectOrDefault,
  tuiSkipped,
  tuiStep,
  tuiSuccess,
  tuiTask,
  tuiText,
  tuiWarning,
  type TuiChoice,
} from './tui.js';
import type {
  ExistingLoginDiscovery,
  MachineIdentityPublic,
  MachineState,
  PairingEnvelope,
  PolicyDecision,
  ProjectVerificationResult,
  ProjectServiceBinding,
  ProviderStatus,
  ServiceConfig,
  ServicePingResult,
  ServiceStatus,
  SignedInProjectConfig,
  TrustedProject,
} from './types.js';
import {
  configureUi,
  printBrand,
  printCancelled,
  printFailure,
  printHeading,
  printJson,
  printParagraph,
  printRows,
  printSuccess,
  printWarning,
  symbols,
  ui,
} from './ui.js';

const paths = resolveSignedInPaths();
const rawArguments = process.argv.slice(process.argv[2] === '--' ? 3 : 2);
const aliasNamingHint = 'Prefer <project>-<environment>, for example acme-production.';
const builtInCommands = new Set([
  '__complete', '__home', 'alias', 'audit', 'completion', 'connections', 'daemon', 'demo', 'doctor', 'help', 'login', 'logout', 'mcp', 'pair',
  'ping', 'policy', 'project', 'projects', 'rename', 'request', 'reset', 'setup', 'share-auth', 'skill', 'status', 'trust', 'use', 'verify',
]);
interface HelpPage {
  examples?: string[];
  notes?: string[];
  summary: string;
  usage: string[];
}

const commandHelp: Record<string, HelpPage> = {
  alias: {
    examples: ['signed-in alias clerk@acme-prod acme-production'],
    notes: [aliasNamingHint],
    summary: 'Rename a human routing alias without moving or replacing its stored authority.',
    usage: ['signed-in alias <service>@<alias> <new-alias>'],
  },
  audit: {
    examples: ['signed-in audit --limit 25', 'signed-in audit --json'],
    summary: 'Print recent secret-free authority receipts.',
    usage: ['signed-in audit [--limit <count>] [--json]'],
  },
  completion: {
    summary: 'Print dynamic shell completion without starting the daemon.',
    usage: ['signed-in completion [zsh|bash|fish]'],
  },
  daemon: {
    notes: ['Explicit stop and restart remain immediate. Use --if-idle for upgrade tooling that must not interrupt active work.'],
    summary: 'Inspect or manage the private user-scoped daemon.',
    usage: ['signed-in daemon <status|start|stop|restart|install|uninstall>', 'signed-in daemon stop --if-idle'],
  },
  doctor: {
    examples: ['signed-in doctor --json'],
    summary: 'Check the vault, project drift, machine identity, and provider binaries.',
    usage: ['signed-in doctor [--project <id>] [--json]'],
  },
  demo: {
    examples: ['signed-in demo'],
    notes: [
      'Shows fictional personal, team, project, and environment connections. No saved accounts, daemon, or provider access is needed.',
      'In a terminal, clears the screen and opens the home menu for screenshots. Enter or Ctrl+C exits without performing an action.',
    ],
    summary: 'Preview the home screen with fictional connections.',
    usage: ['signed-in demo [--json] [--quiet]'],
  },
  help: {
    examples: ['signed-in help agent', 'signed-in help aws', 'signed-in login --help'],
    notes: ['For an underlying provider CLI\'s own help, run signed-in <service> --help.'],
    summary: 'Show signed-in commands, the agent operating guide, or one service access page.',
    usage: ['signed-in help [agent|<command>|<service>]', 'signed-in [command] --help'],
  },
  login: {
    examples: ['signed-in login', 'signed-in login aws github@work', 'signed-in login --all'],
    notes: [
      'When a supported provider CLI has a working, copyable login, signed-in offers to copy and verify that account before starting a fresh login.',
      'The copied connection becomes independent; later changes to the original CLI login do not retarget signed-in or project aliases.',
      'After saving a connection, the interactive flow offers its safe authentication test as the default next action.',
      'Login is the human workflow. Automated callers receive exit 75 and a runnable remedy when a person is required.',
    ],
    summary: 'Guide a person through one or more service sign-ins; no project is required.',
    usage: ['signed-in login [service[@alias]…] [--all] [--remote|--local] [--json]'],
  },
  logout: {
    summary: 'Remove one connection from this machine after interactive confirmation.',
    usage: ['signed-in logout <service>[@alias] [--json]'],
  },
  mcp: {
    notes: ['MCP uses the same connections, policies, redaction, and audit path as the CLI.'],
    summary: 'Run the optional stdio MCP adapter.',
    usage: ['signed-in mcp [--project <id>]'],
  },
  pair: {
    summary: 'Exchange destination-bound encrypted connection bundles between trusted machines.',
    usage: [
      'signed-in pair public-key|identity [--raw] [--json]',
      'signed-in pair export --recipient <signedin1:...> [--json]',
      'signed-in pair import [bundle.json|-] [--json]',
    ],
  },
  ping: {
    examples: ['signed-in ping polar', 'signed-in ping github@work', 'signed-in ping --all', 'signed-in ping --json'],
    notes: ['With no service, ping checks the selected connection for every connected service. Use --all to check every saved alias on the machine. The interactive home screen offers to repair exactly the aliases that fail. Inside a trusted project, ordinary ping automatically enforces that project\'s identities, targets, and capability checks. Provider response bodies are discarded inside the daemon.'],
    summary: 'Prove that stored service authority still performs one safe authenticated read.',
    usage: ['signed-in ping [service[@alias] | --all] [--project <id>] [--json]'],
  },
  verify: {
    notes: ['This spelling is retained so existing commands keep working. New commands should use signed-in ping.'],
    summary: 'Compatibility alias for signed-in ping.',
    usage: ['signed-in verify [service[@alias] | --all] [--project <id>] [--json]'],
  },
  policy: {
    examples: ['signed-in policy explain aws --json -- s3 ls', 'signed-in policy explain polar --http GET /v1/products --json'],
    summary: 'Explain whether a native command or HTTP request is allowed, denied, or needs confirmation.',
    usage: ['signed-in policy explain <service>[@alias] [--http <METHOD> <path> | -- <native args>] [--json]'],
  },
  project: {
    notes: ['Projects are optional alias maps and restrictive policy overlays; service login remains machine-wide.'],
    summary: 'Inspect or manage optional repository bindings.',
    usage: [
      'signed-in project trust [--config <path>] [--root <dir>]…',
      'signed-in project list|show [id]',
      'signed-in project forget <id>',
    ],
  },
  projects: {
    notes: ['Compatibility spelling. New scripts should use signed-in project list.'],
    summary: 'List optional per-project connection rules.',
    usage: ['signed-in project list'],
  },
  rename: {
    summary: 'Compatibility spelling for signed-in alias.',
    usage: ['signed-in rename <service>@<alias> <new-alias>'],
  },
  request: {
    examples: ['signed-in request polar GET /v1/products', 'signed-in request clerk POST /v1/users --data-file body.json --json'],
    notes: ['signed-in supplies authentication inside the daemon. Do not provide Authorization, cookies, or API-key headers.'],
    summary: 'Call a documented provider API with brokered authentication.',
    usage: ['signed-in request <service>[@alias] <METHOD> <path> [--data <text>|--data-file <path>|--stdin] [-H <header>] [--include] [--json]'],
  },
  reset: {
    notes: ['This removes the local vault, connections, trust, audit receipts, and machine identity. It always requires an interactive confirmation.'],
    summary: 'Perform deliberate destructive local recovery.',
    usage: ['signed-in reset [--json]'],
  },
  setup: {
    notes: ['Setup is no longer a prerequisite. Projects can be added later when a repository needs exact connection rules.'],
    summary: 'Compatibility help for the old project-first setup flow.',
    usage: ['signed-in login', 'signed-in project trust [--config <path>]'],
  },
  'share-auth': {
    examples: ['signed-in share-auth example-machine'],
    notes: ['Only fields explicitly declared portable are transferred; provider sessions remain local.'],
    summary: 'Discover a trusted machine and deliver portable connections as recipient-bound ciphertext.',
    usage: ['signed-in share-auth [ssh-host] [--no-reauth] [--json]'],
  },
  skill: {
    examples: [
      'signed-in skill install',
      'signed-in skill install --global --agent codex --agent claude',
      'signed-in skill install --local --agent all',
      'signed-in skill status',
    ],
    notes: [
      'Global installs follow each agent’s native user skill directory; local installs use the current repository root.',
      'Supported agents: codex, claude, cursor, copilot, gemini, and opencode.',
      'Existing modified copies require confirmation or --force; current copies are left untouched.',
    ],
    summary: 'Teach local coding agents to use signed-in without exposing credentials.',
    usage: [
      'signed-in skill install [--global|--local] [--agent <name>]… [--root <dir>] [--force] [--json]',
      'signed-in skill status [--global|--local] [--agent <name>]… [--root <dir>] [--json]',
    ],
  },
  status: {
    examples: ['signed-in status', 'signed-in status aws', 'signed-in status --all --json'],
    summary: 'Show configured connections or browse the complete built-in service catalog.',
    usage: ['signed-in status [service] [--all] [--json]'],
  },
  trust: {
    summary: 'Re-pin changed provider executables after human review.',
    usage: ['signed-in trust [service…]'],
  },
  use: {
    summary: 'Choose the machine default connection for a service.',
    usage: ['signed-in use <service>@<alias>'],
  },
};

const agentHelp: HelpPage = {
  examples: [
    'signed-in status --all --json',
    'signed-in ping --json',
    'signed-in help aws',
    'signed-in aws s3 ls',
    'signed-in request polar GET /v1/products --json',
    'signed-in policy explain aws --json -- s3 rm s3://bucket/key',
  ],
  notes: [
    'Never search for, print, or request the underlying credential. signed-in performs authentication inside its daemon.',
    'Omit @alias for the service default; use it only when status shows more than one connection.',
    'stdout carries results only. Prompts, progress, warnings, and errors use stderr. Nothing prompts without a terminal.',
    '--json emits one JSON document on stdout; errors are one JSON document on stderr.',
    'Exit 75 means a person must run the supplied remedy. Exit 77 is a policy denial; do not bypass it.',
    'Exit 78 means a person declined. Otherwise native commands return the vendor CLI exit status.',
    'Do not send Authorization, Cookie, or API-key headers; signed-in supplies authentication.',
  ],
  summary: 'Discover and use authenticated vendor access without handling reusable credentials.',
  usage: ['signed-in help agent'],
};

const helpGroups: Record<string, HelpPage> = {
  connections: {
    summary: 'Manage, repair, name, select, or disconnect service connections.',
    usage: [
      'signed-in connections [service[@alias]]',
      'signed-in status [service]',
      'signed-in ping --all',
      'signed-in use <service>@<alias>',
      'signed-in alias <service>@<alias> <new-alias>',
      'signed-in logout <service>[@alias]',
    ],
  },
  machines: {
    summary: 'Move portable sign-ins between trusted machines as recipient-bound ciphertext.',
    usage: [
      'signed-in share-auth [ssh-host]',
      'signed-in pair public-key --raw',
      'signed-in pair export --recipient <machine-identity>',
      'signed-in pair import [bundle.json|-]',
    ],
  },
  projects: {
    notes: ['Projects are optional. They select existing connections and may only narrow machine policy.'],
    summary: 'Add or inspect per-project connection rules.',
    usage: [
      'signed-in project trust [--config <path>] [--root <dir>]…',
      'signed-in project list',
      'signed-in project show [id]',
      'signed-in project forget <id>',
    ],
  },
  troubleshooting: {
    summary: 'Check this machine and repair only the part that needs attention.',
    usage: [
      'signed-in doctor [--project <id>]',
      'signed-in trust [service…]',
      'signed-in daemon status|start|stop|restart|install|uninstall',
      'signed-in reset',
    ],
  },
};

let jsonMode = false;
let quietMode = false;
let recoveryProjectOverride: string | undefined;

// Distinguishes an intentional human decline from policy denial and operational failure.
class CliCancelledError extends Error {}

// Adds one runnable recovery command to local input and discovery errors without changing their JSON code.
class ActionableCliError extends Error {
  readonly remedy: string;

  // Keeps the recovery path structured so humans and agents receive the same single next step.
  constructor(message: string, remedy: string) {
    super(message);
    this.remedy = remedy;
  }
}

// Carries the agent-actionable exit-75 contract for every operation that genuinely needs a person.
class HumanRequiredError extends Error {
  readonly code = 'HUMAN_REQUIRED';
  readonly remedy: string;

  // Keeps a runnable remedy attached when a prompt cannot safely be shown.
  constructor(message: string, remedy: string) {
    super(message);
    this.remedy = remedy;
  }
}

try {
  const leading = extractLeadingOptions(rawArguments);
  const command = leading.args[0] ?? (interactiveTerminal() ? '__home' : 'status');
  const ownedCommandArguments = builtInCommands.has(command) ? leading.args.slice(1) : [];
  jsonMode = leading.rootFlags.has('--json') || hasOwnedFlag(ownedCommandArguments, '--json');
  quietMode = leading.rootFlags.has('--quiet') || hasOwnedFlag(ownedCommandArguments, '--quiet');
  configureUi({ color: !leading.rootFlags.has('--no-color'), quiet: quietMode });
  const commandArgs = [
    ...(builtInCommands.has(command) && leading.rootFlags.has('--json') ? ['--json'] : []),
    ...(builtInCommands.has(command) && leading.rootFlags.has('--quiet') ? ['--quiet'] : []),
    ...leading.args.slice(1),
  ];
  recoveryProjectOverride = leading.projectOverride
    ?? (builtInCommands.has(command) ? ownedOptionValue(commandArgs, '--project') : undefined);
  if (leading.rootFlags.has('--version')) process.stdout.write(`${readPackageVersion()}\n`);
  else if (leading.rootFlags.has('--help') || leading.rootFlags.has('-h')) printHelp();
  else if (command === 'help') printCommandHelp(leading.args[1]);
  else if (builtInCommands.has(command) && hasHelpFlag(commandArgs)) printCommandHelp(command);
  else if (builtInCommands.has(command) && hasOwnedFlag(commandArgs, '--version')) process.stdout.write(`${readPackageVersion()}\n`);
  else if (command === 'completion') await runCompletion(commandArgs);
  else if (command === '__complete') runComplete(commandArgs);
  else if (command === 'demo') await runDemo(commandArgs);
  else if (command === 'skill') await runSkillCommand(commandArgs);
  else if (command === 'status' && !leading.projectOverride && !hasOwnedFlag(commandArgs, '--project') && machineAppearsPristine()) {
    await runStatus(commandArgs, undefined, pristineServiceStatuses());
  }
  else {
    ensureSignedInDirectories(paths);
    if (command === 'daemon') await runDaemonCommand(commandArgs);
    else if (command === 'reset') await runReset(commandArgs);
    else {
      await ensureDaemon(paths);
      if (!jsonMode && !quietMode) {
        const notice = await call('migration.notice') as { migrated: boolean };
        if (notice.migrated) printWarning('signed-in moved existing credentials into machine-wide connections. Nothing was re-entered or exposed.');
      }
      await dispatchCli(command, commandArgs, leading.projectOverride);
    }
  }
} catch (error) {
  await handleCliFailure(error, recoveryProjectOverride);
}

// Routes the fictional preview before any account discovery, state initialization, or daemon startup.
async function runDemo(commandArgs: string[]): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: ['--json', '--quiet'], repeated: [], values: [] });
  if (parsed.positionals.length > 0) throw new Error(`Unexpected demo argument '${parsed.positionals[0]}'`);
  await renderDemoScreen({ json: jsonMode, quiet: quietMode });
}

// Gives every authentication-required failure the same human recovery path while keeping automation prompt-free.
async function handleCliFailure(error: unknown, projectOverride?: string): Promise<void> {
  let failure = error;
  if (canOfferSignIn(failure)) {
    try {
      await offerSignIn(failure, projectOverride);
      return;
    } catch (recoveryError) {
      failure = recoveryError;
    }
  }
  if (failure instanceof TuiCancelledError) {
    process.exitCode = 78;
    return;
  }
  if (failure instanceof CliCancelledError || isUserAbort(failure)) {
    if (jsonMode) process.stderr.write(`${JSON.stringify({ error: { code: 'CANCELLED', message: 'Cancelled.' } })}\n`);
    else printCancelled();
    process.exitCode = 78;
    return;
  }
  const rendered = renderError(failure);
  if (jsonMode) process.stderr.write(`${JSON.stringify({ error: rendered }, null, 2)}\n`);
  else {
    printFailure(rendered.message);
    if (rendered.remedy) process.stderr.write(`  ${ui.dim(symbols.remedy)} ${rendered.remedy}\n`);
  }
  process.exitCode = exitCodeForError(failure);
}

// Limits automatic recovery to a real terminal and a structured service identity supplied by the daemon.
function canOfferSignIn(error: unknown): error is SignedInClientError {
  if (!(error instanceof SignedInClientError) || error.code !== 'AUTH_REQUIRED') return false;
  if (jsonMode || quietMode || !interactiveTerminal()) return false;
  const details = typeof error.details === 'object' && error.details !== null ? error.details as Record<string, unknown> : {};
  return typeof details.service === 'string' && details.service.length > 0;
}

// Turns the daemon's exact login remedy into an Enter-to-continue handoff to the normal guided sign-in flow.
async function offerSignIn(error: SignedInClientError, projectOverride?: string): Promise<void> {
  const rendered = renderError(error);
  const details = typeof error.details === 'object' && error.details !== null ? error.details as Record<string, unknown> : {};
  const serviceId = String(details.service);
  const remedyTarget = rendered.remedy?.match(/^signed-in login ([a-z0-9-]+(?:@[a-z0-9-]+)?)$/u)?.[1];
  const account = typeof details.account === 'string' ? details.account : undefined;
  const target = remedyTarget ?? `${serviceId}${account && account !== 'default' ? `@${account}` : ''}`;
  const parsedTarget = parseServiceTarget(target);
  const label = builtInServices[serviceId]?.label ?? serviceId;
  tuiIntro('signed-in');
  tuiWarning(rendered.message);
  const signIn = await tuiConfirm(
    `Sign in to ${label}${parsedTarget.account ? ` · ${parsedTarget.account}` : ''} now?`,
    'Sign in',
    'Not now',
  );
  if (!signIn) {
    if (rendered.remedy) tuiNote(`${symbols.remedy} ${rendered.remedy}`, 'Run later');
    tuiOutro('Not signed in.');
    process.exitCode = 75;
    return;
  }
  await runLogin([target], projectOverride, true);
}

// Routes polished built-ins first, then treats service@alias as the native provider namespace.
async function dispatchCli(commandName: string, commandArgs: string[], projectOverride?: string): Promise<void> {
  switch (commandName) {
    case '__home': await runHome(projectOverride); return;
    case 'status': await runStatus(commandArgs, projectOverride); return;
    case 'connections': await runConnections(commandArgs); return;
    case 'login': await runLogin(commandArgs, projectOverride); return;
    case 'logout': await runLogout(commandArgs, projectOverride); return;
    case 'use': await runUse(commandArgs); return;
    case 'alias':
    case 'rename': await runRename(commandArgs); return;
    case 'trust': await runTrust(commandArgs); return;
    case 'project': await runProject(commandArgs, projectOverride); return;
    case 'projects': throw new ActionableCliError('The projects compatibility command moved.', 'signed-in project list');
    case 'setup': throw new ActionableCliError('Setup is no longer required; service connections are machine-wide.', 'signed-in login');
    case 'request': await runRequest(commandArgs, projectOverride); return;
    case 'ping': await runPing(commandArgs, projectOverride); return;
    case 'verify': await runPing(commandArgs, projectOverride); return;
    case 'policy': await runPolicy(commandArgs, projectOverride); return;
    case 'audit': await runAudit(commandArgs); return;
    case 'doctor': await runDoctor(commandArgs, projectOverride); return;
    case 'pair': await runPair(commandArgs); return;
    case 'share-auth': await runShareAuth(commandArgs); return;
    case 'mcp': await runMcpCommand(commandArgs, projectOverride); return;
    case 'reset': await runReset(commandArgs); return;
    default: await runProviderAlias(commandName, commandArgs, projectOverride);
  }
}

interface CliPingResult extends ServicePingResult {
  connection: string;
  label: string;
}

interface FailedCliPing {
  connection: string;
  error: ReturnType<typeof renderError>;
  label: string;
  ok: false;
}

interface PingRunSummary {
  failures: ConnectionPingTarget[];
  total: number;
}

// Runs one explicit probe or every configured service concurrently without returning provider response bodies.
async function runPing(commandArgs: string[], projectOverride?: string): Promise<PingRunSummary> {
  const parsed = parseOptions(commandArgs, { booleans: ['--all', '--json', '--quiet'], repeated: [], values: ['--project'] });
  if (parsed.positionals.length > 1) throw new Error(`Unexpected ping argument '${parsed.positionals[1]}'`);
  const everyConnection = parsed.booleans.has('--all');
  const explicit = parsed.positionals[0] ? parseServiceTarget(parsed.positionals[0]) : undefined;
  if (everyConnection && explicit) throw new Error('Choose one connection or --all, not both');
  const projectSelection = selectProjectOverride(parsed, projectOverride);
  if (everyConnection && projectSelection) throw new Error('--all tests machine connections and cannot be combined with --project');
  const projectId = everyConnection ? undefined : resolveProjectId(projectSelection);
  if (projectId && !explicit?.account) {
    const result = await runProjectPing(projectId, explicit?.service, parsed.booleans.has('--json'));
    return {
      failures: result.services.filter((service) => !service.ok).map((service) => ({
        account: service.account,
        service: service.providerId,
      })),
      total: result.services.length,
    };
  }
  if (explicit) {
    const checked = await pingTarget(explicit, projectId);
    if (parsed.booleans.has('--json')) printJson({ ok: checked.ok, result: checked, schema: 1 });
    else if (!quietMode) printPingResult(checked);
    if (!checked.ok) process.exitCode = 1;
    return {
      failures: checked.ok ? [] : [{ account: checked.account, service: checked.providerId }],
      total: 1,
    };
  }
  const services = await serviceStatuses(projectId);
  const targets = selectConnectionPingTargets(services, everyConnection);
  if (targets.length === 0) throw new ActionableCliError('Nothing is connected to ping.', 'signed-in login');
  const checked = await Promise.all(targets.map(async (target): Promise<CliPingResult | FailedCliPing> => {
    try {
      return await pingTarget(target, projectId);
    } catch (error) {
      if (!everyConnection && canOfferSignIn(error)) throw error;
      const config = await serviceConfig(target.service, projectId);
      return { connection: formatTarget(target), error: renderError(error), label: config.label, ok: false };
    }
  }));
  const ok = checked.every((result) => result.ok);
  if (parsed.booleans.has('--json')) {
    printJson({ ok, results: checked, schema: 1 });
  } else if (!quietMode) {
    printHeading('signed-in ping', `${checked.filter((result) => result.ok).length} of ${checked.length} authenticated`);
    printRows(checked.map((result) => ({
      detail: 'error' in result ? [result.connection, result.error.remedy].filter(Boolean).join(' · ') : result.connection,
      label: result.label,
      status: 'error' in result ? result.error.message : pingResultStatus(result),
      tone: result.ok ? 'good' as const : 'bad' as const,
    })));
  }
  if (!ok) process.exitCode = 1;
  return {
    failures: targets.filter((_, index) => !checked[index]?.ok),
    total: targets.length,
  };
}

// Turns a completed interactive audit into a focused reconnect batch while retaining a runnable fallback.
async function offerFailedPingRepairs(summary: PingRunSummary, embedded: boolean): Promise<void> {
  if (summary.failures.length === 0) {
    const message = `All ${summary.total} ${summary.total === 1 ? 'connection' : 'connections'} authenticated.`;
    if (embedded) tuiSuccess(message);
    else tuiOutro(message);
    return;
  }
  const targets = formatConnectionRepairTargets(summary.failures);
  const count = targets.length;
  const repair = await tuiConfirm(
    count === 1 ? `Repair ${targets[0]} now?` : `Repair ${count} failed connections now?`,
    'Repair',
    'Not now',
  );
  if (repair) {
    process.exitCode = undefined;
    await runLogin(targets, undefined, true, embedded);
    return;
  }
  tuiNote(`signed-in login ${targets.join(' ')}`, 'Run later');
  if (!embedded) tuiOutro('Connection test finished.');
}

// Resolves catalog metadata before invoking the daemon-owned probe for one service and alias.
async function pingTarget(target: ServiceTarget, projectId?: string): Promise<CliPingResult> {
  const config = await serviceConfig(target.service, projectId);
  if (!config.ping) throw new ActionableCliError(`${config.label} has no authentication probe.`, `signed-in status ${target.service}`);
  const result = await call('service.ping', {
    ...(target.account ? { account: target.account } : {}),
    cwd: process.cwd(),
    ...(projectId ? { projectId } : {}),
    providerId: target.service,
  }) as ServicePingResult;
  return { ...result, connection: `${target.service}@${result.account}`, label: config.label };
}

// Keeps single-service success and failure receipts compact enough to use as a shell health check.
function printPingResult(result: CliPingResult): void {
  const message = `${result.label} · ${result.account} · ${pingResultStatus(result)}`;
  if (result.ok) printSuccess(message);
  else printFailure(message);
}

// Describes the exact authenticated surface without exposing its response or implying broader permissions.
function pingResultStatus(result: ServicePingResult): string {
  const proof = result.interface === 'http' ? `HTTP ${result.status ?? 'failed'}` : `CLI exit ${result.exitCode ?? 1}`;
  const authentication = result.target
    ? result.ok ? 'account authenticated' : 'account authentication failed'
    : result.ok ? 'authenticated' : 'failed';
  const target = result.target
    ? result.target.value ? `${result.target.label} ${result.target.value}` : `no ${result.target.label} selected`
    : undefined;
  return [authentication, target, proof, `${result.durationMs} ms`].filter(Boolean).join(' · ');
}

// Deepens the ordinary ping automatically when a trusted project has identities, targets, or capabilities to prove.
async function runProjectPing(projectId: string, providerId: string | undefined, json: boolean): Promise<ProjectVerificationResult> {
  const result = await call('project.verify', {
    cwd: process.cwd(),
    projectId,
    ...(providerId ? { providerId } : {}),
  }) as ProjectVerificationResult;
  if (json) {
    printJson({ ...result, schema: 1 });
  } else if (!quietMode) {
    const project = await describeProject(projectId);
    printHeading('signed-in ping', `${project.config.project.name} · ${result.ok ? 'ready for agents' : 'needs attention'}`);
    printRows(result.services.flatMap((service) => {
      const config = project.config.providers[service.providerId] ?? builtInServices[service.providerId];
      const context = [service.account, service.identity].filter(Boolean).join(' · ');
      return [
        {
          detail: context,
          label: config?.label ?? service.providerId,
          status: pingResultStatus(service.ping),
          tone: service.ping.ok ? 'good' as const : 'bad' as const,
        },
        ...service.checks.map((check) => ({
          detail: `${check.method} ${check.path} · ${check.durationMs} ms`,
          label: `  ${check.label}`,
          status: `HTTP ${check.status}`,
          tone: check.ok ? 'good' as const : 'bad' as const,
        })),
      ];
    }));
  }
  if (!result.ok) process.exitCode = 1;
  return result;
}

// Renders configured connections by default and turns --all into the calm service-catalog browser.
async function runStatus(
  commandArgs: string[],
  projectOverride?: string,
  knownServices?: ServiceStatus[],
  readoutOnly = false,
): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: ['--all', '--json', '--quiet'], repeated: [], values: ['--project'] });
  if (parsed.positionals.length > 1) throw new Error(`Unexpected status argument '${parsed.positionals[1]}'`);
  const projectId = resolveProjectId(selectProjectOverride(parsed, projectOverride));
  const services = knownServices ?? await serviceStatuses(projectId);
  const selectedId = parsed.positionals[0];
  const selected = selectedId ? services.filter((service) => service.id === selectedId) : services;
  if (selectedId && selected.length === 0) throw new Error(`Unknown service '${selectedId}'. Try signed-in status --all.`);
  const accountCount = services.reduce((total, service) => total + service.accounts.length, 0);
  const configuredCount = services.filter((service) => service.accounts.length > 0).length;
  const visible = parsed.booleans.has('--all') || selectedId
    ? selected
    : selected.filter((service) => service.accounts.length > 0 || service.required);
  if (parsed.booleans.has('--json')) {
    const project = projectId ? (await describeProject(projectId)).config.project : null;
    printJson({ schema: 1, catalog: { configured: configuredCount, total: services.length }, project, services: visible });
    return;
  }
  if (quietMode) return;
  if (selectedId) {
    printServiceDetail(selected[0]!, await serviceConfig(selectedId, projectId));
    return;
  }
  if (accountCount === 0 && !projectId && !parsed.booleans.has('--all')) {
    printHeading('signed-in');
    process.stdout.write('No services are signed in on this machine yet.\n\n');
    if (!readoutOnly) {
      printRows([
        { label: 'Get started', status: 'signed-in login' },
        { label: 'For agents', status: 'signed-in help agent' },
      ]);
    }
    return;
  }
  const ready = visible.filter((service) => projectId ? projectServiceReady(service) : serviceReady(service)).length;
  const needsAttention = visible.filter((service) => service.accounts.length > 0 || service.required)
    .filter((service) => !(projectId ? projectServiceReady(service) : serviceReady(service)));
  const summary = [
    ready ? `${ready}${accountCount > configuredCount ? ' services' : ''} connected` : undefined,
    accountCount > configuredCount ? `${accountCount} connections` : undefined,
    needsAttention.length ? `${needsAttention.length} needs you` : undefined,
  ]
    .filter(Boolean).join(' · ') || 'nothing connected';
  if (projectId) {
    const project = await describeProject(projectId);
    printHeading(project.config.project.name, [project.config.environment, summary].filter(Boolean).join(' · '));
  } else printHeading('signed-in', summary);
  printRows(visible.map((service) => statusRow(service)));
  process.stdout.write('\n');
  if (readoutOnly) return;
  const firstAttention = needsAttention[0];
  if (firstAttention) {
    printRows([
      { label: `Fix ${firstAttention.label}`, status: firstAttention.remedy ?? `signed-in login ${loginTarget(firstAttention)}` },
      { label: parsed.booleans.has('--all') ? 'Connected only' : 'Add a service', status: parsed.booleans.has('--all') ? 'signed-in status' : 'signed-in login' },
      { label: 'Manage connections', status: 'signed-in connections' },
    ]);
  } else {
    printRows([
      { label: 'Add a service', status: 'signed-in login' },
      { label: parsed.booleans.has('--all') ? 'Connected only' : 'Everything', status: parsed.booleans.has('--all') ? 'signed-in status' : 'signed-in status --all' },
      { label: 'Manage connections', status: 'signed-in connections' },
    ]);
  }
}

// Turns connection correction into one discoverable human loop instead of a vocabulary test across login, alias, use, and logout.
async function runConnections(commandArgs: string[], introShown = false): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: ['--json', '--quiet'], repeated: [], values: [] });
  if (parsed.positionals.length > 1) throw new Error(`Unexpected connections argument '${parsed.positionals[1]}'`);
  if (!interactiveTerminal()) {
    throw new HumanRequiredError('Managing connections needs a person at an interactive terminal.', 'signed-in status --json');
  }
  if (!introShown) tuiIntro('signed-in connections');
  if (parsed.positionals[0]) {
    const target = parseServiceTarget(parsed.positionals[0]);
    const services = await serviceStatuses();
    const service = services.find((candidate) => candidate.id === target.service);
    const connection = target.account
      ? service?.accounts.find((candidate) => candidate.account === target.account)
      : service?.accounts.find((candidate) => candidate.default) ?? service?.accounts[0];
    if (!service || !connection) {
      throw new ActionableCliError(`${parsed.positionals[0]} is not a signed-in connection.`, `signed-in status ${target.service}`);
    }
    await manageConnection(service, connection);
    tuiOutro('Connections saved.');
    return;
  }
  while (true) {
    const services = await serviceStatuses();
    const choices = connectionManagerChoices(services);
    const attention = services.flatMap((service) => service.accounts.map((connection) => ({ connection, serviceId: service.id })))
      .find(({ connection }) => !connection.ready);
    const initial = attention ? `connection:${attention.serviceId}@${attention.connection.account}` : choices[0]?.value ?? 'add';
    const selected = await tuiSelect('Which connection do you want to manage?', [
      ...choices,
      ...(choices.length > 0 ? [{ hint: 'Makes one safe authenticated request for every saved alias', label: 'Test all connections', value: 'test' }] : []),
      { hint: 'Connect another vendor or account', label: 'Add a connection', value: 'add' },
      { label: 'Done', value: 'done' },
    ], initial);
    if (selected === 'done') {
      tuiOutro('Connections saved.');
      return;
    }
    if (selected === 'add') {
      await runLogin([], undefined, true, true);
      continue;
    }
    if (selected === 'test') {
      const summary = await runPing(['--all']);
      await offerFailedPingRepairs(summary, true);
      continue;
    }
    const target = parseServiceTarget(selected.slice('connection:'.length));
    const service = services.find((candidate) => candidate.id === target.service);
    const connection = service?.accounts.find((candidate) => candidate.account === target.account);
    if (!service || !connection) {
      tuiWarning('That connection changed while the list was open. Choose it again.');
      continue;
    }
    await manageConnection(service, connection);
  }
}

// Leads with aliases because they are the operator's lasting mental model while retaining service and identity as disambiguation.
function connectionManagerChoices(services: ServiceStatus[]): TuiChoice<string>[] {
  return services.flatMap((service) => service.accounts.map((connection) => ({
    hint: [connection.default ? 'default' : undefined, connection.identity ? conciseIdentity(service.id, connection.identity) : undefined, connectionOriginDetail(connection), connection.ready ? 'connected' : 'needs attention']
      .filter(Boolean).join(' · '),
    label: `${connection.account} · ${service.label}`,
    value: `connection:${service.id}@${connection.account}`,
  })));
}

// Keeps all mutations for one selected connection together and requires an extra confirmation only for irreversible removal.
async function manageConnection(service: ServiceStatus, connection: ProviderStatus): Promise<void> {
  const config = await serviceConfig(service.id);
  const actions: TuiChoice<'back' | 'default' | 'reconnect' | 'remove' | 'rename'>[] = [
    {
      hint: service.signIn === 'interactive' ? 'Runs the provider sign-in again' : 'The current credential remains hidden',
      label: replacementActionLabel(config),
      value: 'reconnect',
    },
    { hint: 'Changes only the human-readable alias', label: 'Rename alias', value: 'rename' },
    ...(!connection.default ? [{ hint: 'Used when @alias is omitted', label: 'Make default', value: 'default' as const }] : []),
    { hint: 'Deletes its stored authentication from this machine', label: 'Remove connection', value: 'remove' },
    { label: 'Back', value: 'back' },
  ];
  const action = await tuiSelect(`${service.label} · ${connection.account}`, actions, 'reconnect');
  if (action === 'back') return;
  if (action === 'reconnect') {
    if (service.signIn === 'manual' && config.credentials?.length) {
      await replaceManagedCredentials(service.id, config, connection);
    } else {
      await runLogin([`${service.id}@${connection.account}`], undefined, true, true);
    }
    return;
  }
  if (action === 'rename') {
    const newAlias = await promptManagedAlias(service, connection.account);
    const result = await call('account.rename', {
      account: connection.account,
      approved: true,
      newName: newAlias,
      providerId: service.id,
    }) as { projects: Array<{ configPath: string; name: string }> };
    tuiSuccess(`Renamed ${connection.account} to ${newAlias}.`);
    for (const project of result.projects) tuiWarning(`${project.name} still names the old alias in ${project.configPath}.`);
    return;
  }
  if (action === 'default') {
    await call('account.use', { account: connection.account, approved: true, providerId: service.id });
    tuiSuccess(`${connection.account} is now the default ${service.label} connection.`);
    return;
  }
  if (!await tuiConfirm(`Remove ${service.label} · ${connection.account} from this machine?`, 'Remove', 'Keep', false)) return;
  await call('provider.logout', { account: connection.account, approved: true, providerId: service.id });
  tuiSuccess(`${service.label} · ${connection.account} removed.`);
}

// Reuses each service's own credential noun so management says Replace secret key instead of a vague reconnect action.
function replacementActionLabel(service: ServiceConfig): string {
  if (service.signIn === 'interactive') return 'Sign in again';
  const credentialLabel = credentialActionLabel(service).replace(/^Enter /u, '').toLowerCase();
  return `Replace ${credentialLabel}`;
}

// Replaces an existing manual connection in place so project bindings and its human alias remain stable.
async function replaceManagedCredentials(serviceId: string, service: ServiceConfig, connection: ProviderStatus): Promise<void> {
  const fields: Record<string, string> = {};
  const promptFields = (service.credentials ?? []).filter((field) => field.required !== false);
  const helpUrl = promptFields.find((field) => field.helpUrl)?.helpUrl;
  if (helpUrl) tuiHint(`Find it at ${helpUrl}`);
  for (const field of promptFields) fields[field.id] = await promptCredentialField(field);
  const status = await call('credential.put', {
    account: connection.account,
    approved: true,
    fields,
    providerId: serviceId,
    replace: true,
  }) as ProviderStatus;
  tuiSuccess(`${service.label} · ${status.account} updated.`);
}

// Normalizes friendly input while preventing a rename from colliding with another route or the reserved default vocabulary.
async function promptManagedAlias(service: ServiceStatus, current: string): Promise<string> {
  const taken = new Set(service.accounts.map((connection) => connection.account));
  tuiHint(aliasNamingHint);
  while (true) {
    const candidate = normalizeAlias(await tuiText(`Rename ${current} to`));
    if (candidate && candidate !== 'default' && candidate !== current && !taken.has(candidate) && isSafeAccountName(candidate)) return candidate;
    tuiWarning('Use a new alias with lowercase letters, numbers, and hyphens.');
  }
}

interface HomeSkillState {
  current: SkillAgentId[];
  detected: SkillAgentId[];
}

// Shows the same useful foyer on every machine while choosing the safest useful Enter default from current state.
async function runHome(projectOverride?: string): Promise<void> {
  const projectId = resolveProjectId(projectOverride);
  const services = await serviceStatuses(projectId);
  const accountCount = services.reduce((total, service) => total + service.accounts.length, 0);
  await runStatus([], projectOverride, services, true);
  const needsAttention = services.filter((service) => service.accounts.length > 0 || service.required || service.projectConnectionMissing || service.projectConnectionPending)
    .filter((service) => !(projectId ? projectServiceReady(service) : serviceReady(service)));
  const reconnectable = needsAttention.filter((service) => service.remedy?.startsWith('signed-in login ') ?? true);
  const projectRoot = path.resolve(findSkillProjectRoot(process.cwd()));
  const skillState = inspectHomeSkillState(projectRoot);
  const loginLabel = reconnectable.length === 1
    ? `Repair ${reconnectable[0]!.label}`
    : accountCount > 0 ? 'Connect another service' : 'Connect a service';
  const loginHint = reconnectable.length > 0
    ? `${reconnectable.length === 1 ? reconnectable[0]!.label : `${reconnectable.length} services`} needs attention`
    : 'Sign in once; agents never receive the credential';
  const initial = reconnectable.length > 0 || accountCount === 0
    ? 'login'
    : skillState.detected.length > 0 && skillState.current.length === 0 ? 'skill' : 'done';
  tuiIntro('signed-in');
  const action = await tuiSelectOrDefault('What would you like to do?', [
    { hint: loginHint, label: loginLabel, value: 'login' },
    ...(accountCount > 0 ? [{ hint: 'Rename, switch, reconnect, or remove an account', label: 'Manage connections', value: 'connections' as const }] : []),
    ...(accountCount > 0 ? [{
      hint: `Makes one safe authenticated request for ${accountCount === 1 ? 'the saved connection' : `all ${accountCount} saved connections`}`,
      label: 'Test all connections',
      value: 'test' as const,
    }] : []),
    { hint: homeSkillHint(skillState), label: 'Install the agent skill', value: 'skill' },
    { label: 'Done', value: 'done' },
  ], initial, 'done');
  if (action === 'login') {
    await runLogin(reconnectable.map((service) => loginTarget(service)), projectId, true);
    return;
  }
  if (action === 'connections') {
    await runConnections([], true);
    return;
  }
  if (action === 'test') {
    const summary = await runPing(['--all']);
    await offerFailedPingRepairs(summary, false);
    return;
  }
  if (action === 'skill') {
    await runSkillInstall([], true);
    return;
  }
  tuiOutro('Ready.');
}

// Checks both discovery tiers so the home screen can recommend installation without hiding a valid local override.
function inspectHomeSkillState(projectRoot: string): HomeSkillState {
  const source = bundledSkillDirectory();
  const detected = detectSkillAgents({ root: projectRoot });
  const current = detected.filter((agent) => (['global', 'local'] as const).some((scope) => (
    inspectSkillInstall(source, skillInstallDestination(agent, scope, { root: projectRoot })) === 'current'
  )));
  return { current, detected };
}

// Keeps the home action useful whether the guide is new, partially installed, or already current somewhere.
function homeSkillHint(state: HomeSkillState): string {
  if (state.detected.length === 0) return 'Teach Codex, Claude Code, and other coding agents';
  const labels = state.detected.map((agent) => skillAgent(agent).label);
  const detected = labels.length <= 2 ? labels.join(' and ') : `${labels.slice(0, 2).join(', ')} +${labels.length - 2}`;
  if (state.current.length === 0) return `Teach ${detected} to use signed-in`;
  if (state.current.length === state.detected.length) return `Ready for ${detected} · manage or refresh`;
  return `${state.current.length}/${state.detected.length} detected agents ready · manage or refresh`;
}

// Guides one unified service selection through focused, sequential sign-in steps and preserves partial success.
async function runLogin(commandArgs: string[], projectOverride?: string, introShown = false, embedded = false): Promise<void> {
  const parsed = parseOptions(commandArgs, {
    booleans: ['--all', '--json', '--local', '--quiet', '--remote'], repeated: [], values: ['--project'],
  });
  if (parsed.booleans.has('--local') && parsed.booleans.has('--remote')) throw new Error('Choose --local or --remote, not both');
  const projectId = resolveProjectId(selectProjectOverride(parsed, projectOverride));
  const services = await serviceStatuses(projectId);
  const explicit = parsed.positionals.flatMap((value) => value.split(',')).filter(Boolean).map(parseServiceTarget);
  let targets = uniqueTargets(explicit);
  if (parsed.booleans.has('--all')) {
    targets = uniqueTargets([...targets, ...services.map((service) => ({ service: service.id }))]);
  } else if (targets.length === 0) {
    if (!interactiveTerminal() || parsed.booleans.has('--json') || quietMode) {
      throw new HumanRequiredError('Choosing services needs a person at an interactive terminal.', 'signed-in login <service>');
    }
    if (!introShown) {
      tuiIntro('signed-in');
      introShown = true;
    }
    const suggestions = suggestedLoginTargets(services, projectId);
    tuiHint('↑↓ move  ·  space toggle  ·  enter continue');
    const selected = await tuiMultiselect(
      services.every((service) => service.accounts.length > 0 && serviceReady(service))
        ? 'Everything is connected. Select a service to reconnect or add another connection.'
        : 'Which services do you use?',
      serviceSelectionChoices(services),
      suggestions.map((target) => target.service),
    );
    targets = selected.map((service) => suggestions.find((target) => target.service === service) ?? { service });
  }
  if (targets.length === 0) {
    if (embedded) tuiStep('Nothing selected.');
    else tuiOutro('Nothing selected.');
    return;
  }
  for (const target of targets) await serviceConfig(target.service, projectId);
  if (!interactiveTerminal()) {
    const target = formatTarget(targets[0]!);
    throw new HumanRequiredError('Signing in needs a person at an interactive terminal.', `signed-in login ${target}`);
  }
  if (!introShown && !parsed.booleans.has('--json') && !quietMode) tuiIntro('signed-in');
  const results: LoginResult[] = [];
  for (const [index, target] of targets.entries()) {
    const service = await serviceConfig(target.service, projectId);
    const status = services.find((candidate) => candidate.id === target.service);
    let account = target.account;
    let completedStatus: ProviderStatus | undefined;
    if (!parsed.booleans.has('--json') && !quietMode) tuiStep(`${index + 1} of ${targets.length}  ${service.label}`);
    try {
      if (!account && status && status.accounts.length > 0) {
        const connection = await chooseConnectionForLogin(status);
        if (connection === 'skip') {
          results.push({ outcome: 'skipped', service: target.service });
          if (!parsed.booleans.has('--json') && !quietMode) tuiSkipped(`${service.label} skipped for now.`);
          continue;
        }
        account = connection === 'new' ? undefined : connection;
      }
      const existing = account ? status?.accounts.find((candidate) => candidate.account === account) : undefined;
      const fallbackAlias = projectId ?? (status?.accounts.length ? `connection-${status.accounts.length + 1}` : 'primary');
      let allowExistingLogin = true;
      let skipped = false;
      while (!completedStatus && !skipped) {
        const action = await chooseLoginAction(target.service, service, status, account, { allowExistingLogin, projectId });
        if (action === 'skip') {
          skipped = true;
          break;
        }
        if (action === 'adopt') {
          if (!parsed.booleans.has('--json') && !quietMode) {
            tuiHint(`Copying the existing ${service.existingLogin?.source ?? service.cli?.command ?? service.label} login into signed-in. The original login will stay unchanged.`);
          }
          try {
            const response = await runStreaming('provider.adoption.import', {
              ...(account ? { account } : { alias: fallbackAlias }),
              approved: true,
              cwd: process.cwd(),
              ...(projectId ? { projectId } : {}),
              providerId: target.service,
            }, false, parsed.booleans.has('--json')) as { status: ProviderStatus };
            completedStatus = response.status;
          } catch (error) {
            if (!canRecoverFromAdoptionFailure(error)) throw error;
            if (!parsed.booleans.has('--json') && !quietMode) {
              tuiWarning(`That ${service.existingLogin?.source ?? service.label} login could not be copied. Nothing was changed — choose another way to connect ${service.label}.`);
            }
            allowExistingLogin = false;
          }
          continue;
        }
        if (action === 'provider') {
          const remote = parsed.booleans.has('--remote') || (!parsed.booleans.has('--local') && remoteLoginLikely());
          if (!parsed.booleans.has('--json') && !quietMode) {
            tuiHint(remote
              ? 'This machine has no browser. Follow the provider’s code or link on another device.'
              : 'Opening your browser. Finish sign-in there, then come back here.');
          }
          try {
            const response = await runStreaming('provider.login', {
              ...(account ? { account } : { alias: fallbackAlias }),
              ...(existing ? { approved: true } : {}),
              cwd: process.cwd(),
              ...(projectId ? { projectId } : {}),
              providerId: target.service,
              remote,
            }, true, parsed.booleans.has('--json'), createProviderLoginObserver(target.service, remote)) as {
              exitCode: number;
              pinned?: { path: string };
              status: ProviderStatus;
            };
            if (response.exitCode !== 0) throw new Error(`${service.label} login exited with ${response.exitCode}`);
            completedStatus = response.status;
          } catch (error) {
            if (!canRecoverFromMissingCli(error)) throw error;
            if (!parsed.booleans.has('--json') && !quietMode) {
              tuiWarning(`${service.label}'s command disappeared before sign-in started. Choose Install to repair it here.`);
            }
          }
          continue;
        }
        if (action === 'credentials') {
          const fields: Record<string, string> = {};
          const promptFields = existing ? (service.credentials ?? []).filter((field) => field.required !== false) : (service.credentials ?? []);
          const helpUrl = promptFields.find((field) => field.helpUrl)?.helpUrl;
          if (helpUrl && !parsed.booleans.has('--json') && !quietMode) tuiHint(`Find it at ${helpUrl}`);
          for (const field of promptFields) {
            const value = await promptCredentialField(field);
            if (!value) throw new Error(`${field.label} cannot be empty`);
            fields[field.id] = value;
          }
          completedStatus = await call('credential.put', {
            ...(account ? { account } : {}), ...(existing ? { approved: true } : {}), fields, ...(projectId ? { projectId } : {}),
            providerId: target.service, replace: Boolean(existing),
          }) as ProviderStatus;
        }
      }
      if (skipped) {
        results.push({ ...(account ? { account } : {}), outcome: 'skipped', service: target.service });
        if (!parsed.booleans.has('--json') && !quietMode) tuiSkipped(`${service.label} skipped for now.`);
        continue;
      }
      if (!completedStatus) throw new Error(`${service.label} sign-in did not complete`);
      completedStatus = await nameFallbackConnection(service, status, completedStatus, Boolean(existing || target.account), projectId);
      results.push({ account: completedStatus.account, identity: completedStatus.identity, outcome: 'ready', service: target.service, status: completedStatus });
      if (!parsed.booleans.has('--json') && !quietMode) tuiSuccess(formatLoginSuccess(service, completedStatus));
    } catch (error) {
      if (error instanceof TuiCancelledError) {
        if (embedded) throw error;
        if (completedStatus) {
          results.push({ account: completedStatus.account, identity: completedStatus.identity, outcome: 'ready', service: target.service, status: completedStatus });
        }
        const connected = results.filter((result) => result.outcome === 'ready').length;
        printWarning(connected > 0
          ? `Stopped. ${connected === 1 ? 'One connection is' : `${connected} connections are`} connected and saved; remaining services were not changed.`
          : 'Stopped. No connections were changed.');
        process.exitCode = 78;
        return;
      }
      const rendered = renderError(error);
      results.push({ ...(account ? { account } : {}), message: rendered.message, outcome: 'attention', service: target.service });
      if (!parsed.booleans.has('--json') && !quietMode) tuiWarning(`${service.label} needs attention · ${rendered.message}`);
    }
  }
  let ready = results.filter((result) => result.outcome === 'ready').length;
  let skipped = results.filter((result) => result.outcome === 'skipped').length;
  let attention = results.filter((result) => result.outcome === 'attention').length;
  let summary = loginSummary(ready, skipped, attention);
  if (parsed.booleans.has('--json')) printJson({ attention, ready, results, skipped });
  else if (!quietMode) {
    if (embedded) {
      tuiStep(summary);
      return;
    }
    const pendingTests = await loginTestTargets(results, projectId);
    let testsOffered = false;
    let shownRetryCommand: string | undefined;
    while (true) {
      ready = results.filter((result) => result.outcome === 'ready').length;
      skipped = results.filter((result) => result.outcome === 'skipped').length;
      attention = results.filter((result) => result.outcome === 'attention').length;
      summary = loginSummary(ready, skipped, attention);
      const availableTests = testsOffered ? [] : pendingTests;
      const retryTargets = results.filter((result) => result.outcome === 'attention').map((result) => formatTarget(result));
      const retryCommand = retryTargets.length > 0 ? `signed-in login ${retryTargets.join(' ')}` : undefined;
      if (availableTests.length === 0 && retryCommand && retryCommand !== shownRetryCommand) {
        tuiNote(`${symbols.remedy} ${retryCommand}`, 'Run later');
        shownRetryCommand = retryCommand;
      }
      const continuation = await chooseLoginContinuation(attention, availableTests);
      if (continuation === 'test') {
        testsOffered = true;
        await testLoginConnections(availableTests, projectId);
        continue;
      }
      if (continuation === 'retry') {
        await runLogin(retryTargets, projectId, true);
        return;
      }
      if (continuation === 'more') {
        await runLogin([], projectId, true);
        return;
      }
      tuiOutro(summary);
      break;
    }
  }
  if (attention > 0) process.exitCode = 1;
}

interface LoginResult extends ServiceTarget {
  identity?: string;
  message?: string;
  outcome: 'attention' | 'ready' | 'skipped';
  status?: ProviderStatus;
}

interface LoginTestTarget {
  config: ServiceConfig;
  result: LoginResult;
}

type LoginAction = 'adopt' | 'credentials' | 'provider' | 'skip';
type LoginContinuation = 'done' | 'more' | 'retry' | 'test';

interface LoginActionOptions {
  allowExistingLogin?: boolean;
  projectId?: string;
}

// Keeps the batch receipt truthful after an optional proof changes a newly saved connection into needs-attention.
function loginSummary(ready: number, skipped: number, attention: number): string {
  return [ready ? `${ready} connected` : undefined, skipped ? `${skipped} skipped` : undefined, attention ? `${attention} needs you` : undefined]
    .filter(Boolean).join(' · ') || 'Nothing changed';
}

// Limits the post-login offer to newly saved connections whose catalog defines a safe authentication probe.
async function loginTestTargets(results: LoginResult[], projectId?: string): Promise<LoginTestTarget[]> {
  const ready = results.filter((result) => result.outcome === 'ready');
  const targets = await Promise.all(ready.map(async (result) => ({ config: await serviceConfig(result.service, projectId), result })));
  return targets.filter((target) => Boolean(target.config.ping));
}

// Proves newly stored authority immediately and returns each failure to the existing focused repair path.
async function testLoginConnections(targets: LoginTestTarget[], projectId?: string): Promise<void> {
  for (const target of targets) {
    try {
      await tuiTask(
        `Testing ${target.config.label}…`,
        `${target.config.label} test passed · authenticated access confirmed`,
        `${target.config.label} test failed`,
        async () => {
          const result = await pingTarget(target.result, projectId);
          if (!result.ok) throw new Error(describePingFailure(target.config.label, result));
        },
      );
    } catch (error) {
      const rendered = renderError(error);
      target.result.message = rendered.message;
      target.result.outcome = 'attention';
      tuiWarning(rendered.message);
    }
  }
}

// Explains non-authentication HTTP failures without treating every provider outage or catalog defect as a bad credential.
function describePingFailure(label: string, result: ServicePingResult): string {
  if (result.interface === 'native') return `${label} could not prove authenticated access (CLI exit ${result.exitCode ?? 1})`;
  if (result.status === 403) return `${label} refused the verification request (HTTP 403); this credential may not have enough access`;
  if (result.status === 404) return `${label}'s verification endpoint was not found (HTTP 404); its signed-in integration needs attention`;
  if (result.status && result.status >= 500) return `${label} could not verify the connection because the provider returned HTTP ${result.status}`;
  return `${label} could not prove authenticated access (HTTP ${result.status ?? 'failed'})`;
}

// Makes immediate proof the one-Enter happy path, then returns to Done or a focused retry after that proof runs.
async function chooseLoginContinuation(attention: number, tests: LoginTestTarget[]): Promise<LoginContinuation> {
  const options: TuiChoice<LoginContinuation>[] = [];
  if (tests.length > 0) {
    const label = tests.length === 1 ? `Test ${tests[0]!.config.label} connection` : `Test ${tests.length} new connections`;
    options.push({ hint: 'Makes one safe authenticated request', label, value: 'test' });
  }
  if (attention > 0) {
    options.push({ label: `Try ${attention === 1 ? 'the one that failed' : `the ${attention} that failed`} again`, value: 'retry' });
  }
  options.push({ label: 'Done', value: 'done' });
  options.push({ label: 'Connect more services', value: 'more' });
  const initial = tests.length > 0 ? 'test' : attention > 0 ? 'retry' : 'done';
  return tuiSelectOrDefault('Anything else?', options, initial, 'done');
}

// Names only newly created fallback connections, after credentials are safely stored and identity derivation has had its chance.
async function nameFallbackConnection(
  service: ServiceConfig,
  previous: ServiceStatus | undefined,
  status: ProviderStatus,
  explicitOrExisting: boolean,
  projectId?: string,
): Promise<ProviderStatus> {
  if (explicitOrExisting || status.aliasSource !== 'fallback') return status;
  const alias = await promptConnectionAlias(service, previous, projectId);
  if (alias === status.account) return status;
  await call('account.rename', {
    account: status.account,
    approved: true,
    newName: alias,
    providerId: status.id,
  });
  return { ...status, account: alias, aliasSource: 'operator' };
}

// Lets a repeated service login add authority or deliberately repair one recognizable existing alias.
async function chooseConnectionForLogin(status: ServiceStatus): Promise<'new' | 'skip' | string> {
  const options: TuiChoice<string>[] = [
    { hint: 'Keep the existing connections', label: 'Add another connection', value: 'new' },
    ...status.accounts.map((connection) => ({
      hint: [connection.default ? 'default' : undefined, connection.identity, connection.ready ? 'ready' : 'needs attention'].filter(Boolean).join(' · '),
      label: `Reconnect ${connection.account}`,
      value: `alias:${connection.account}`,
    })),
    { label: 'Skip for now', value: 'skip' },
  ];
  const needsAttention = status.accounts.find((connection) => !connection.ready);
  const selected = await tuiSelect(`Which ${status.label} connection?`, options, needsAttention ? `alias:${needsAttention.account}` : 'new');
  return selected.startsWith('alias:') ? selected.slice('alias:'.length) : selected;
}

// Asks once when a provider cannot identify the organisation behind a new credential or session.
async function promptConnectionAlias(service: ServiceConfig, status: ServiceStatus | undefined, projectId?: string): Promise<string> {
  const taken = status?.accounts.map((connection) => connection.account) ?? [];
  const base = normalizeAlias(projectId ?? '') ?? (taken.length === 0 ? 'primary' : `connection-${taken.length + 1}`);
  const suggestion = allocateAlias(base, taken);
  tuiHint(aliasNamingHint);
  while (true) {
    const alias = await tuiText(`What is this ${service.label} connection for?`, suggestion);
    if (alias !== 'default' && isSafeAccountName(alias) && !taken.includes(alias)) return alias;
    tuiWarning('Use a different name with lowercase letters, numbers, and hyphens.');
  }
}

// Makes every completed login immediately inspectable by showing both its routing alias and provider identity.
function formatLoginSuccess(service: ServiceConfig, status: ProviderStatus): string {
  const target = `${status.id}@${status.account}`;
  const adopted = status.origin?.kind === 'adopted' && status.origin.source ? ` · adopted from ${status.origin.source}` : '';
  return `${service.label} is ready · ${target}${status.identity ? ` · ${status.identity}` : ''}${adopted}`;
}

// Suggests only unfinished project requirements or expired defaults without choosing for a fresh machine.
function suggestedLoginTargets(services: ServiceStatus[], projectId?: string): ServiceTarget[] {
  if (projectId) {
    return services.filter((service) => service.required && !projectServiceReady(service)).map((service) => ({
      ...(service.projectAccount ? { account: service.projectAccount } : {}), service: service.id,
    }));
  }
  return services.flatMap((service) => {
    const selected = service.accounts.find((account) => account.default) ?? service.accounts[0];
    return selected && !selected.ready ? [{ account: selected.account, service: service.id }] : [];
  });
}

// Gives the unified checklist useful state hints while deliberately omitting authentication mechanics.
function serviceSelectionChoices(services: ServiceStatus[]): TuiChoice<string>[] {
  const catalogOrder = new Map(Object.keys(builtInServices).map((id, index) => [id, index]));
  return [...services].sort((left, right) => {
    const stateDifference = serviceSelectionRank(left) - serviceSelectionRank(right);
    if (stateDifference !== 0) return stateDifference;
    const leftOrder = catalogOrder.get(left.id) ?? Number.MAX_SAFE_INTEGER;
    const rightOrder = catalogOrder.get(right.id) ?? Number.MAX_SAFE_INTEGER;
    return leftOrder - rightOrder || left.label.localeCompare(right.label);
  }).map((service) => {
    const selected = service.accounts.find((account) => account.default) ?? service.accounts[0];
    const hint = service.projectConnectionPending
      ? 'Needs you · project connection is not signed in on this machine'
      : service.projectConnectionMissing
      ? 'Needs you · project connection was removed'
      : selected?.ready
      ? `Connected${selected.account !== 'primary' ? ` · ${selected.account}` : ''}${selected.identity ? ` · ${conciseIdentity(service.id, selected.identity)}` : ''}`
      : selected ? 'Needs you' : service.description ?? 'Not connected';
    return { hint, label: service.label, value: service.id };
  });
}

// Keeps repairable connections above healthy ones and untouched catalog entries at the bottom of the checklist.
function serviceSelectionRank(service: ServiceStatus): number {
  if (service.accounts.length > 0 && !serviceReady(service)) return 0;
  if (serviceReady(service)) return 1;
  return 2;
}

// Keeps instructions inside a service step and returns only when the human chooses an actionable path.
async function chooseLoginAction(
  serviceId: string,
  service: ServiceConfig,
  status?: ServiceStatus,
  selectedAccount?: string,
  loginOptions: LoginActionOptions = {},
): Promise<LoginAction> {
  const allowExistingLogin = loginOptions.allowExistingLogin !== false;
  let installationGuideOpened = false;
  let missingWarningShown = false;
  let existingLogin: ExistingLoginDiscovery | undefined;
  let existingLoginChecked = false;
  let preferredMissingAction: 'check' | 'install' | 'instructions' | undefined;
  while (true) {
    const cliAvailable = service.cli ? await serviceCommandAvailable(serviceId, loginOptions.projectId) : false;
    const providerAvailable = service.signIn === 'interactive' && cliAvailable;
    const cliMissing = Boolean(service.cli) && !cliAvailable;
    const installPlan = cliMissing ? resolveCliInstallPlan(serviceId) : undefined;
    if (allowExistingLogin && providerAvailable && service.existingLogin && !existingLoginChecked) {
      existingLoginChecked = true;
      try {
        const discovered = await call('provider.adoption.discover', {
          cwd: process.cwd(),
          ...(loginOptions.projectId ? { projectId: loginOptions.projectId } : {}),
          providerId: serviceId,
        }) as ExistingLoginDiscovery;
        if (discovered.available) existingLogin = discovered;
      } catch {
        existingLogin = undefined;
      }
    }
    const duplicate = !selectedAccount && existingLogin?.identity
      ? status?.accounts.find((connection) => connection.identity?.trim().toLowerCase() === existingLogin!.identity!.trim().toLowerCase())
      : undefined;
    const options: TuiChoice<'adopt' | 'check' | 'credentials' | 'install' | 'instructions' | 'provider' | 'skip'>[] = [];
    if (existingLogin) {
      options.push({
        ...(duplicate ? { disabled: true } : {}),
        hint: duplicate
          ? `Already in signed-in as ${duplicate.account}`
          : `Copies the login into signed-in; ${existingLogin.source} stays unchanged`,
        label: existingLogin.identity
          ? `Use ${conciseIdentity(serviceId, existingLogin.identity)} from ${existingLogin.source}`
          : `Use existing login from ${existingLogin.source}`,
        value: 'adopt',
      });
    }
    if (providerAvailable) {
      options.push({ hint: `Starts the secure ${service.cli?.command ?? service.label} sign-in flow`, label: 'Sign in with your browser', value: 'provider' });
    } else if (cliMissing) {
      if (installPlan) options.push({ hint: installPlan.displayCommand, label: `Install ${service.label}`, value: 'install' });
      options.push({ hint: 'Opens the service’s install guide', label: 'Open install guide', value: 'instructions' });
      options.push({ hint: 'Checks your PATH without leaving this step', label: 'I installed it — check again', value: 'check' });
    }
    if (service.credentials && service.credentials.length > 0) {
      options.push({ hint: 'Stored encrypted on this machine', label: credentialActionLabel(service), value: 'credentials' });
    }
    if (!cliMissing) options.push({ hint: 'Opens the service documentation', label: 'Get instructions', value: 'instructions' });
    options.push({ label: 'Skip for now', value: 'skip' });
    if (cliMissing && !missingWarningShown) {
      tuiWarning(`${service.label} needs a global ${service.cli!.command} command. A project-local copy cannot be used as machine authority.`);
      missingWarningShown = true;
    }
    const message = `Connect ${service.label}`;
    const initialValue = existingLogin && !duplicate
      ? 'adopt'
      : providerAvailable
        ? 'provider'
        : cliMissing
          ? preferredMissingAction ?? (installPlan ? 'install' : installationGuideOpened ? 'check' : 'instructions')
          : (service.credentials?.length ? 'credentials' : 'instructions');
    const action = await tuiSelect(message, options, initialValue);
    if (action === 'install') {
      if (!installPlan) throw new Error(`No trusted automatic installer is available for ${service.label}.`);
      try {
        await tuiTask(
          `Installing ${service.label} with ${installPlan.command.replace(/\.cmd$/u, '')} · this can take a minute`,
          `${service.label} installed · continuing setup`,
          `${service.label} could not be installed`,
          () => installCli(installPlan),
        );
        existingLogin = undefined;
        existingLoginChecked = true;
        if (await serviceCommandAvailable(serviceId, loginOptions.projectId)) {
          if (service.signIn === 'interactive') continue;
          preferredMissingAction = undefined;
          continue;
        }
        tuiWarning(`${service.cli!.command} was installed but signed-in's background helper still cannot find it. Check again, or restart the helper.`);
        preferredMissingAction = 'check';
      } catch (error) {
        tuiWarning(error instanceof Error ? error.message : String(error));
        preferredMissingAction = 'instructions';
      }
      continue;
    }
    if (action === 'check') {
      if (await serviceCommandAvailable(serviceId, loginOptions.projectId)) {
        if (service.signIn === 'interactive') continue;
        preferredMissingAction = undefined;
        continue;
      }
      tuiWarning(`signed-in still can’t find a global ${service.cli!.command} command.`);
      installationGuideOpened = true;
      preferredMissingAction = installPlan ? 'install' : 'instructions';
      continue;
    }
    if (action !== 'instructions') return action;
    const destination = cliMissing
      ? service.installHint ?? service.docsUrl
      : service.credentials?.find((field) => field.helpUrl)?.helpUrl ?? service.docsUrl;
    if (!destination) {
      tuiWarning(`No setup page is configured for ${service.label}.`);
      continue;
    }
    await openExternalUrl(destination);
    tuiSuccess(`Opened ${service.label} instructions.`);
    installationGuideOpened = cliMissing;
    preferredMissingAction = cliMissing ? 'check' : undefined;
  }
}

// Keeps a rejected or uncopyable local login inside the same human sign-in step without masking daemon failures.
function canRecoverFromAdoptionFailure(error: unknown): error is SignedInClientError {
  return error instanceof SignedInClientError && ['ADOPTION_FAILED', 'AUTH_REQUIRED'].includes(error.code);
}

// Returns a disappearing executable to the same guided service step instead of leaving a partial batch failure.
function canRecoverFromMissingCli(error: unknown): error is SignedInClientError {
  return error instanceof SignedInClientError && error.code === 'CLI_NOT_INSTALLED';
}

// Uses the service's own credential vocabulary so Clerk says API key while multi-field services stay accurate.
function credentialActionLabel(service: ServiceConfig): string {
  const fields = service.credentials ?? [];
  if (fields.length !== 1) return 'Enter credentials';
  const label = fields[0]!.label.toLowerCase().replace(service.label.toLowerCase(), '').trim();
  if (label.includes('secret key')) return 'Enter secret key';
  if (label.includes('api key')) return 'Enter API key';
  if (label.includes('auth token')) return 'Enter auth token';
  if (label.includes('access token')) return 'Enter access token';
  if (label.includes('token')) return 'Enter token';
  if (label.includes('key')) return 'Enter key';
  return 'Enter credentials';
}

// Uses the daemon's global executable boundary so project-local PATH shims never masquerade as machine authority.
async function serviceCommandAvailable(serviceId: string, projectId?: string): Promise<boolean> {
  const status = await call('service.cli.status', {
    ...(projectId ? { projectId } : {}),
    providerId: serviceId,
  }) as { available: boolean };
  return status.available;
}

// Detects remote or headless environments early enough to give the right provider handoff instructions.
function remoteLoginLikely(): boolean {
  if (process.env.SSH_TTY || process.env.SSH_CONNECTION) return true;
  return process.platform === 'linux' && !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY;
}

// Accepts multiline credentials by file path while keeping ordinary secrets out of argv and terminal echo.
async function promptCredentialField(field: NonNullable<ServiceConfig['credentials']>[number]): Promise<string> {
  if (field.input === 'file') {
    const suppliedPath = await tuiText(`${field.label} file`);
    const inputPath = suppliedPath.startsWith('~/') ? path.join(process.env.HOME ?? '', suppliedPath.slice(2)) : path.resolve(suppliedPath);
    const metadata = statSync(inputPath);
    if (!metadata.isFile()) throw new Error(`${field.label} path is not a regular file`);
    if (metadata.size > 1024 * 1024) throw new Error(`${field.label} file exceeds the 1 MiB credential limit`);
    return readFileSync(inputPath, 'utf8');
  }
  if (field.input === 'text' || field.secret === false) return tuiText(field.label);
  return tuiPassword(field.label, (value) => credentialValidationMessage(field, value));
}

// Removes one account only after a visible confirmation in the active terminal.
async function runLogout(commandArgs: string[], projectOverride?: string): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: ['--json', '--quiet'], repeated: [], values: ['--project'] });
  const rawTarget = parsed.positionals[0];
  if (!rawTarget || parsed.positionals.length > 1) throw new Error('Usage: signed-in logout <service>[@alias]');
  const target = parseServiceTarget(rawTarget);
  await requireInteractiveApproval(
    `Remove ${formatTarget(target)} authentication from this machine?`,
    `signed-in logout ${formatTarget(target)}`,
  );
  const projectId = resolveProjectId(selectProjectOverride(parsed, projectOverride));
  const result = await call('provider.logout', {
    ...(target.account ? { account: target.account } : {}), approved: true,
    ...(projectId ? { projectId } : {}), providerId: target.service,
  });
  if (parsed.booleans.has('--json')) printJson(result);
  else printSuccess(`${formatTarget(target)} disconnected from this machine.`);
}

// Changes the machine default through the one uniform service@alias spelling.
async function runUse(commandArgs: string[]): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: ['--json', '--quiet'], repeated: [], values: [] });
  if (!parsed.positionals[0] || parsed.positionals.length > 1) throw new Error('Usage: signed-in use <service>@<alias>');
  const target = parseServiceTarget(parsed.positionals[0]);
  if (!target.account) throw new Error('use needs an explicit service@alias');
  let result: { changed: boolean; previous?: string };
  try {
    result = await call('account.use', { account: target.account, providerId: target.service }) as typeof result;
  } catch (error) {
    if (!(error instanceof SignedInClientError) || error.code !== 'APPROVAL_REQUIRED') throw error;
    await requireInteractiveApproval(`Use ${formatTarget(target)} by default?`, `signed-in use ${formatTarget(target)}`);
    result = await call('account.use', { account: target.account, approved: true, providerId: target.service }) as typeof result;
  }
  if (parsed.booleans.has('--json')) printJson(result);
  else if (result.changed) printSuccess(`${target.service} now defaults to ${target.account}.`);
  else printSuccess(`${target.service} already defaults to ${target.account}.`);
}

// Renames one alias without moving authority and identifies project source declarations that need the same edit.
async function runRename(commandArgs: string[]): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: ['--json', '--quiet'], repeated: [], values: [] });
  if (parsed.positionals.length !== 2) throw new Error('Usage: signed-in alias <service>@<alias> <new-alias>');
  const target = parseServiceTarget(parsed.positionals[0]!);
  if (!target.account) throw new Error('alias needs an explicit service@alias');
  const preview = await call('account.rename', {
    account: target.account, newName: parsed.positionals[1], preview: true, providerId: target.service,
  }) as { projects: Array<{ configPath: string; name: string }> };
  if (!parsed.booleans.has('--json') && !quietMode) {
    printHeading(`${target.service}@${target.account} → ${target.service}@${parsed.positionals[1]}`);
    if (preview.projects.length > 0) {
      process.stdout.write(`\n${ui.dim('Referenced by')}\n`);
      printRows(preview.projects.map((project) => ({ detail: project.configPath, label: project.name, status: 'source alias needs update' })));
    }
  }
  await requireInteractiveApproval(
    `Rename ${formatTarget(target)} to ${target.service}@${parsed.positionals[1]}?`,
    `signed-in alias ${formatTarget(target)} ${parsed.positionals[1]}`,
  );
  const result = await call('account.rename', {
    account: target.account, approved: true, newName: parsed.positionals[1], providerId: target.service,
  }) as { projects: Array<{ configPath: string; name: string }> };
  if (parsed.booleans.has('--json')) { printJson(result); return; }
  printSuccess(`Renamed ${target.service}@${target.account} to ${target.service}@${parsed.positionals[1]}. Stored authority did not move.`);
  for (const project of result.projects) printWarning(`${project.name} still resolves by immutable connection ID; edit ${project.configPath} before its next trust review.`);
}

// Re-pins explicit or drifted service executables without coupling trust to project setup.
async function runTrust(commandArgs: string[]): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: ['--json', '--quiet'], repeated: [], values: [] });
  const doctor = await call('doctor') as { services: Array<{ id: string; state?: string; trusted: boolean }> };
  const serviceIds = parsed.positionals.length > 0
    ? parsed.positionals
    : doctor.services.filter((service) => service.state ? service.state === 'changed' : !service.trusted && serviceCliAvailable(service.id)).map((service) => service.id);
  if (serviceIds.length === 0) {
    if (parsed.booleans.has('--json')) printJson({ trusted: [] });
    else printSuccess('No changed provider executables need trust.');
    return;
  }
  await requireInteractiveApproval(
    `Trust installed executables for ${serviceIds.join(', ')}?`,
    `signed-in trust ${serviceIds.join(' ')}`,
  );
  const trusted = [];
  for (const providerId of serviceIds) trusted.push({ providerId, pin: await call('service.trust', { approved: true, providerId }) });
  if (parsed.booleans.has('--json')) printJson({ trusted });
  else for (const item of trusted) printSuccess(`${item.providerId} executable trusted.`);
}

// Introduces optional repository bindings only when the human explicitly asks for project context.
async function runProject(commandArgs: string[], projectOverride?: string): Promise<void> {
  const parsed = parseOptions(commandArgs, {
    booleans: ['--json', '--quiet'], repeated: ['--root'], values: ['--config', '--project'],
  });
  const subcommand = parsed.positionals[0] ?? 'list';
  if (subcommand === 'list') {
    if (parsed.positionals.length > 1) throw new Error(`Unexpected project argument '${parsed.positionals[1]}'`);
    const state = await call('project.list') as MachineState;
    if (parsed.booleans.has('--json')) { printJson(state.projects); return; }
    if (Object.keys(state.projects).length === 0) { process.stdout.write('No project bindings are trusted on this machine.\n'); return; }
    printHeading('Trusted projects');
    printRows(Object.values(state.projects).map((project) => ({ detail: project.roots.join(', '), label: project.name, status: project.id })));
    return;
  }
  if (subcommand === 'show') {
    const projectId = parsed.positionals[1] ?? resolveProjectId(selectProjectOverride(parsed, projectOverride));
    if (!projectId) throw new Error('Name a project or run this inside a trusted root.');
    const project = await describeProject(projectId);
    if (parsed.booleans.has('--json')) { printJson(project); return; }
    const statuses = await serviceStatuses(projectId);
    printHeading(project.config.project.name, project.config.environment);
    printRows(Object.entries(project.config.services).map(([service, binding]) => {
      const resolved = projectBinding(binding);
      const status = statuses.find((candidate) => candidate.id === service);
      const activeAlias = status?.projectAccount;
      const configuredAlias = resolved.account && resolved.account !== activeAlias ? `configured as ${resolved.account}` : undefined;
      return {
        label: service,
        status: status?.projectConnectionPending ? 'sign-in pending' : status?.projectConnectionMissing ? 'connection removed' : activeAlias ?? 'machine default',
        detail: [
          resolved.required ? 'required' : 'optional',
          configuredAlias,
          resolved.expectedIdentity ? `expects ${resolved.expectedIdentity}` : undefined,
          resolved.target ? `target ${resolved.target}` : undefined,
          resolved.checks.length ? `${resolved.checks.length} capability ${resolved.checks.length === 1 ? 'check' : 'checks'}` : undefined,
          status?.projectConnectionMissing ? 'sign in, then re-trust' : undefined,
        ].filter(Boolean).join(' · '),
      };
    }));
    return;
  }
  if (subcommand === 'forget') {
    const projectId = parsed.positionals[1];
    if (!projectId || parsed.positionals.length > 2) throw new Error('Usage: signed-in project forget <id>');
    await requireInteractiveApproval(
      `Forget project '${projectId}'? Machine connections are kept.`,
      `signed-in project forget ${projectId}`,
    );
    const result = await call('project.forget', { approved: true, projectId });
    if (parsed.booleans.has('--json')) printJson(result); else printSuccess(`Forgot ${projectId}; machine connections were kept.`);
    return;
  }
  if (subcommand !== 'trust') throw new Error(`Unknown project command '${subcommand}'`);
  if (parsed.positionals.length > 1) throw new Error(`Unexpected project trust argument '${parsed.positionals[1]}'`);
  const discovered = parsed.values['--config'] ?? discoverProjectConfig(process.cwd());
  if (!discovered) throw new ActionableCliError('No signed-in.config.json was found here or in a parent directory.', 'signed-in project trust --config <path>');
  const configPath = path.resolve(discovered);
  const config = loadProjectConfig(configPath);
  const roots = parsed.repeated['--root'].length > 0 ? parsed.repeated['--root'].map((root) => path.resolve(root)) : [path.dirname(configPath)];
  if (!parsed.booleans.has('--json') && !quietMode) {
    printBrand();
    printHeading(`Trust ${config.project.name}`, path.basename(configPath));
    printRows(Object.entries(config.services).map(([service, binding]) => {
      const resolved = projectBinding(binding);
      return {
        label: service,
        status: resolved.account ?? 'machine default',
        detail: [
          resolved.required ? 'required' : 'optional',
          resolved.expectedIdentity ? `expects ${resolved.expectedIdentity}` : undefined,
          resolved.target ? `target ${resolved.target}` : undefined,
          resolved.checks.length ? `${resolved.checks.length} capability ${resolved.checks.length === 1 ? 'check' : 'checks'}` : undefined,
        ].filter(Boolean).join(' · '),
      };
    }));
    process.stdout.write(`\n${ui.dim('Connections stay machine-wide. If one is missing here, signed-in will connect it next.')}\n`);
  }
  await requireInteractiveApproval(
    `Trust the reviewed bindings and policy for ${config.project.name}?`,
    `signed-in project trust --config ${JSON.stringify(configPath)} ${roots.map((root) => `--root ${JSON.stringify(root)}`).join(' ')}`,
  );
  let result = await call('project.trust', { approved: true, config, configPath, roots }) as {
    missing: Array<{ alias?: string; service: string }>;
  };
  if (result.missing.length > 0 && !parsed.booleans.has('--json')) {
    tuiStep(`${config.project.name} needs ${result.missing.length} ${result.missing.length === 1 ? 'connection' : 'connections'} on this machine.`);
    await runLogin(result.missing.map(({ alias, service }) => `${service}${alias ? `@${alias}` : ''}`), config.project.id, true, true);
    result = await call('project.trust', { approved: true, config, configPath, roots }) as typeof result;
  }
  if (parsed.booleans.has('--json')) printJson(result);
  else if (result.missing.length === 0) {
    printSuccess(`${config.project.name} is trusted. Commands in ${roots[0]} now use its bindings.`);
    if (!quietMode) {
      const verify = await tuiConfirm(
        `Test ${config.project.name}'s connections now?`,
        'Test project',
        'Not now',
      );
      if (verify) await runPing([], config.project.id);
      else tuiNote(`${symbols.remedy} signed-in ping --project ${config.project.id}`, 'Run later');
    }
  }
  else {
    printWarning(`${config.project.name} is trusted, but ${result.missing.length} ${result.missing.length === 1 ? 'connection still needs' : 'connections still need'} sign-in.`);
    for (const missing of result.missing) process.stdout.write(`  ${symbols.remedy} signed-in login ${missing.service}${missing.alias ? `@${missing.alias}` : ''}\n`);
    process.exitCode = 1;
  }
}

// Executes a native service namespace with project policy and exact alias selection.
async function runProviderAlias(rawTarget: string, providerArgs: string[], projectOverride?: string): Promise<void> {
  const target = parseServiceTarget(rawTarget);
  const projectId = resolveProjectId(projectOverride);
  const service = await serviceConfig(target.service, projectId);
  if (!service.cli) throw new ActionableCliError(`${service.label} does not have a native CLI route.`, `signed-in help ${target.service}`);
  const decision = await call('policy.explain', {
    ...(target.account ? { account: target.account } : {}), args: providerArgs, interface: 'native',
    ...(projectId ? { projectId } : {}), providerId: target.service,
  }) as PolicyDecision;
  if (decision.effect === 'deny') throw new SignedInClientError('POLICY_DENIED', decision.reason, decision);
  const approved = decision.effect === 'confirm';
  if (approved) await requireInteractiveApproval(
    `${service.label}: ${decision.reason} Continue?`,
    `signed-in ${formatTarget(target)} ${providerArgs.join(' ')}`,
  );
  const result = await runStreaming('provider.run', {
    ...(target.account ? { account: target.account } : {}), approved, args: providerArgs, cwd: process.cwd(),
    ...(projectId ? { projectId } : {}), providerId: target.service,
  }, true, false) as { exitCode: number };
  process.exitCode = result.exitCode;
}

// Provides a curl-like authenticated request surface with the same service@alias resolution as native calls.
async function runRequest(commandArgs: string[], projectOverride?: string): Promise<void> {
  const parsed = parseOptions(commandArgs, {
    booleans: ['--include', '--json', '--quiet', '--stdin'], repeated: ['--header', '-H'], values: ['--data', '--data-file', '--project'],
  });
  const [rawTarget, method, requestPath] = parsed.positionals;
  if (!rawTarget || !method || !requestPath || parsed.positionals.length > 3) throw new Error('Usage: signed-in request <service>[@alias] <METHOD> <path>');
  const bodySources = Number(parsed.booleans.has('--stdin')) + Number(parsed.values['--data'] !== undefined) + Number(parsed.values['--data-file'] !== undefined);
  if (bodySources > 1) throw new ActionableCliError('Choose only one request body source: --stdin, --data, or --data-file.', 'signed-in request --help');
  const target = parseServiceTarget(rawTarget);
  const projectId = resolveProjectId(selectProjectOverride(parsed, projectOverride));
  const headers = parseHeaders([...parsed.repeated['--header'], ...parsed.repeated['-H']]);
  const body = parsed.booleans.has('--stdin') ? await readStdin() : parsed.values['--data-file'] ? readFileSync(path.resolve(parsed.values['--data-file'])) : Buffer.from(parsed.values['--data'] ?? '', 'utf8');
  const decision = await call('policy.explain', {
    ...(target.account ? { account: target.account } : {}), interface: 'http', method, path: requestPath,
    ...(projectId ? { projectId } : {}), providerId: target.service,
  }) as PolicyDecision;
  if (decision.effect === 'deny') throw new SignedInClientError('POLICY_DENIED', decision.reason, decision);
  const approved = decision.effect === 'confirm';
  if (approved) await requireInteractiveApproval(
    `${decision.reason} Continue?`,
    `signed-in request ${formatTarget(target)} ${method} ${requestPath}`,
  );
  const result = await call('http.request', {
    ...(target.account ? { account: target.account } : {}), approved, body: body.toString('base64'), bodyEncoding: 'base64', headers, method,
    path: requestPath,
    ...(projectId ? { projectId } : {}), providerId: target.service,
  }) as { response: GatewayResponse };
  if (parsed.booleans.has('--json')) { printJson(result); return; }
  if (parsed.booleans.has('--include')) {
    process.stdout.write(`HTTP ${result.response.status}\n`);
    for (const [name, value] of Object.entries(result.response.headers)) process.stdout.write(`${name}: ${value}\n`);
    process.stdout.write('\n');
  }
  const responseBody = Buffer.from(result.response.body, result.response.bodyEncoding === 'base64' ? 'base64' : 'utf8');
  process.stdout.write(responseBody);
  if (result.response.bodyEncoding === 'utf8' && responseBody.length > 0 && responseBody.at(-1) !== 10) process.stdout.write('\n');
}

// Exposes the daemon's exact classification before an operation is attempted.
async function runPolicy(commandArgs: string[], projectOverride?: string): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: ['--http', '--json', '--quiet'], repeated: [], values: ['--project'] });
  const [subcommand, rawTarget, ...operationArgs] = parsed.positionals;
  if (subcommand !== 'explain' || !rawTarget) throw new Error('Usage: signed-in policy explain <service>[@alias] [--http METHOD PATH | -- <args>]');
  const target = parseServiceTarget(rawTarget);
  const projectId = resolveProjectId(selectProjectOverride(parsed, projectOverride));
  const params = parsed.booleans.has('--http')
    ? { ...(target.account ? { account: target.account } : {}), interface: 'http', method: operationArgs[0] ?? 'GET', path: operationArgs[1] ?? '/', ...(projectId ? { projectId } : {}), providerId: target.service }
    : { ...(target.account ? { account: target.account } : {}), args: operationArgs, interface: 'native', ...(projectId ? { projectId } : {}), providerId: target.service };
  const decision = await call('policy.explain', params) as PolicyDecision & { account?: string };
  if (parsed.booleans.has('--json')) { printJson(decision); return; }
  printHeading(`${decision.effect.toUpperCase()} · ${decision.classification}`, decision.account ? `${target.service}@${decision.account}` : undefined);
  process.stdout.write(`${decision.reason}\n${ui.dim(decision.matchedRules.join(', '))}\n`);
}

// Renders recent secret-free receipts or returns them as stable JSON.
async function runAudit(commandArgs: string[]): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: ['--json', '--quiet'], repeated: [], values: ['--limit'] });
  if (parsed.positionals.length > 0) throw new Error(`Unexpected audit argument '${parsed.positionals[0]}'`);
  const receipts = await call('audit.list', { limit: Number(parsed.values['--limit'] ?? 30) }) as Array<Record<string, unknown>>;
  if (parsed.booleans.has('--json')) { printJson(receipts); return; }
  printHeading('Recent authority receipts', `${receipts.length} events`);
  for (const receipt of receipts) {
    const time = String(receipt.completedAt ?? receipt.startedAt ?? '').replace('T', ' ').slice(0, 19);
    const target = [receipt.providerId, receipt.interface, receipt.method, receipt.path].filter(Boolean).join(' ');
    process.stdout.write(`${ui.dim(time)}  ${formatAuditStatus(String(receipt.status))}  ${target}\n`);
  }
}

// Checks vault health, project drift, and machine-wide executable pins without provider calls.
async function runDoctor(commandArgs: string[], projectOverride?: string): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: ['--json', '--quiet'], repeated: [], values: ['--project'] });
  if (parsed.positionals.length > 0) throw new Error(`Unexpected doctor argument '${parsed.positionals[0]}'`);
  const projectId = resolveProjectId(selectProjectOverride(parsed, projectOverride));
  const result = await call('doctor', { ...(projectId ? { projectId } : {}) }) as {
    machine: MachineIdentityPublic;
    project?: { configDrift: boolean };
    services: Array<{
      configured?: boolean;
      executable?: string;
      id: string;
      label?: string;
      remedy?: string;
      state?: 'changed' | 'not-installed' | 'not-used' | 'ready';
      trusted: boolean;
    }>;
    vault: string;
  };
  if (parsed.booleans.has('--json')) { printJson(result); return; }
  printBrand();
  printHeading('Doctor', result.machine.label);
  const visibleServices = result.services.filter((service) => service.state
    ? service.state !== 'not-used' && (service.configured || service.state !== 'not-installed')
    : Boolean(service.executable));
  const serviceRows = visibleServices.flatMap((service) => {
    const state = service.state ?? (service.trusted ? 'ready' : 'changed');
    const command = builtInServices[service.id]?.cli?.command ?? service.id;
    const base = state === 'ready'
      ? { detail: service.executable, label: service.label ?? service.id, status: 'approved', tone: 'good' as const }
      : state === 'not-installed'
        ? { detail: `${command} is not installed`, label: service.label ?? service.id, status: 'needs you', tone: 'warn' as const }
        : { detail: `${command} changed since approval`, label: service.label ?? service.id, status: 'needs you', tone: 'warn' as const };
    return [base, ...(state !== 'ready' && service.remedy ? [{ label: `Fix ${service.label ?? service.id}`, status: service.remedy }] : [])];
  });
  printRows([
    { label: 'Encrypted storage', status: result.vault === 'ok' ? 'working' : result.vault, tone: 'good' },
    { detail: result.machine.fingerprint, label: 'Machine identity', status: 'present', tone: 'good' },
    ...(result.project ? [{ label: 'Project rules', status: result.project.configDrift ? 'needs you' : 'match approval', tone: result.project.configDrift ? 'warn' as const : 'good' as const }] : []),
    ...serviceRows,
  ]);
  if (!result.project?.configDrift && !visibleServices.some((service) => service.state === 'changed' || service.state === 'not-installed')) {
    process.stdout.write(`\n${ui.dim('Everything else looks fine.')}\n`);
  }
}

// Implements encrypted account exchange without requiring a project container.
async function runPair(commandArgs: string[]): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: ['--json', '--quiet', '--raw'], repeated: [], values: ['--recipient'] });
  const [subcommand = 'public-key', source] = parsed.positionals;
  if (subcommand === 'public-key' || subcommand === 'identity') {
    const identity = await call('machine.identity') as MachineIdentityPublic;
    const encoded = encodeIdentityCard(identity);
    if (parsed.booleans.has('--json')) printJson({ encoded, identity });
    else if (parsed.booleans.has('--raw')) process.stdout.write(`${encoded}\n`);
    else { printHeading(identity.label, identity.fingerprint); process.stdout.write(`${encoded}\n`); }
    return;
  }
  if (subcommand === 'export') {
    const recipient = parsed.values['--recipient'] ?? source;
    if (!recipient) throw new Error('Usage: signed-in pair export --recipient <signedin1:...>');
    await requireInteractiveApproval('Share portable connections with this recipient?', `signed-in pair export --recipient ${JSON.stringify(recipient)}`);
    const result = await call('pair.export', { approved: true, recipient });
    if (parsed.booleans.has('--json')) printJson(result);
    else process.stdout.write(`${JSON.stringify((result as { envelope: PairingEnvelope }).envelope)}\n`);
    return;
  }
  if (subcommand === 'import') {
    const text = source && source !== '-' ? readFileSync(path.resolve(source), 'utf8') : (await readStdin()).toString('utf8');
    const document = JSON.parse(text) as PairingEnvelope | { envelope: PairingEnvelope };
    const envelope = 'envelope' in document ? document.envelope : document;
    let result: unknown;
    try { result = await call('pair.import', { envelope }); }
    catch (error) {
      if (!(error instanceof SignedInClientError) || error.code !== 'APPROVAL_REQUIRED') throw error;
      await requireInteractiveApproval(`${error.message} Replace them?`, source && source !== '-' ? `signed-in pair import ${JSON.stringify(path.resolve(source))}` : 'signed-in pair import -');
      result = await call('pair.import', { approved: true, envelope });
    }
    if (parsed.booleans.has('--json')) printJson(result);
    else printSuccess(`Imported ${(result as { imported: string[] }).imported.length} connections.`);
    return;
  }
  throw new Error(`Unknown pair command '${subcommand}'`);
}

// Transfers destination-bound ciphertext to one Tailscale peer and offers independent sign-in afterward.
async function runShareAuth(commandArgs: string[]): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: ['--json', '--no-reauth', '--quiet'], repeated: [], values: [] });
  if (parsed.positionals.length > 1) throw new Error(`Unexpected share-auth argument '${parsed.positionals[1]}'`);
  const host = parsed.positionals[0] ?? await chooseTailscaleHost();
  validateSshHost(host);
  const recipient = execFileSync('ssh', [host, 'signed-in', 'pair', 'public-key', '--raw'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }).trim();
  if (!recipient.startsWith('signedin1:')) throw new Error(`${host} did not return a signed-in machine identity`);
  await requireInteractiveApproval(`Share portable connections with ${host}?`, `signed-in share-auth ${host}`);
  const exported = await call('pair.export', { approved: true, recipient }) as { envelope: PairingEnvelope; skipped: Array<{ account: string; providerId: string }> };
  const remoteOutput = await sshImportEnvelope(host, exported.envelope);
  if (parsed.booleans.has('--json')) printJson({ host, remote: parseJsonIfPossible(remoteOutput), skipped: exported.skipped });
  else printSuccess(`Portable connections delivered to ${host} as destination-bound ciphertext.`);
  if (!parsed.booleans.has('--no-reauth') && exported.skipped.length > 0 && process.stdin.isTTY && await confirm(`Open ${host}'s guided login now?`, true)) {
    const targets = exported.skipped.map((item) => `${item.providerId}${item.account === 'default' ? '' : `@${item.account}`}`);
    const child = spawn('ssh', ['-t', host, 'signed-in', 'login', ...targets, '--remote'], { stdio: 'inherit' });
    const exitCode = await waitForExit(child);
    if (exitCode !== 0) throw new Error(`Remote login exited with ${exitCode}`);
  }
}

// Starts the optional MCP transport with project context only when cwd or a flag supplies it.
async function runMcpCommand(commandArgs: string[], projectOverride?: string): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: [], repeated: [], values: ['--project'] });
  if (parsed.positionals.length > 0) throw new Error(`Unexpected MCP argument '${parsed.positionals[0]}'`);
  await runMcpServer(paths, resolveProjectId(selectProjectOverride(parsed, projectOverride)));
}

interface SkillInstallPlan {
  agent: SkillAgentId;
  destination: string;
  label: string;
  scope: SkillInstallScope;
  state: SkillInstallState;
}

interface SkillInstallReceipt extends SkillInstallPlan {
  outcome: 'current' | 'installed' | 'kept' | 'updated';
}

// Installs or inspects the packaged agent guide without starting the credential daemon.
async function runSkillCommand(commandArgs: string[]): Promise<void> {
  const first = commandArgs[0];
  const subcommand = first && !first.startsWith('-') ? first : 'install';
  const args = first && !first.startsWith('-') ? commandArgs.slice(1) : commandArgs;
  if (subcommand === 'install') {
    await runSkillInstall(args);
    return;
  }
  if (subcommand === 'status') {
    runSkillStatus(args);
    return;
  }
  throw new ActionableCliError(`Unknown skill command '${subcommand}'.`, 'signed-in skill --help');
}

// Guides a human through agent and scope selection while keeping scripted installs explicit and deterministic.
async function runSkillInstall(commandArgs: string[], introShown = false): Promise<void> {
  const parsed = parseOptions(commandArgs, {
    booleans: ['--force', '--global', '--json', '--local', '--quiet'],
    repeated: ['--agent'],
    values: ['--root'],
  });
  if (parsed.positionals.length > 0) throw new Error(`Unexpected skill install argument '${parsed.positionals[0]}'`);
  const interactive = interactiveTerminal() && !parsed.booleans.has('--json') && !quietMode;
  const projectRoot = path.resolve(parsed.values['--root'] ?? findSkillProjectRoot(process.cwd()));
  let scope = skillScopeFromFlags(parsed);
  let agents = parseSkillAgentIds(parsed.repeated['--agent'] ?? []);
  if (!scope && !interactive) {
    throw new ActionableCliError('Choose a global or local skill install.', 'signed-in skill install --global --agent codex');
  }
  if (agents.length === 0 && !interactive) {
    throw new ActionableCliError('Choose at least one agent for the skill install.', `signed-in skill install --${scope} --agent codex`);
  }
  if (interactive) {
    if (!introShown) tuiIntro('signed-in');
    tuiNote('Use authenticated vendor CLIs and APIs through signed-in. Never inspect or expose the underlying credentials.', 'What agents learn');
  }
  if (!scope) scope = await chooseSkillScope(projectRoot);
  if (agents.length === 0) agents = await chooseSkillAgents(scope, projectRoot);
  if (agents.length === 0) {
    if (interactive) tuiOutro('Nothing selected.');
    return;
  }
  const source = bundledSkillDirectory();
  const plans = skillInstallPlans(agents, scope, source, projectRoot);
  const conflicts = plans.filter((plan) => plan.state === 'modified');
  if (!interactive && !parsed.booleans.has('--force') && conflicts.length > 0) {
    const flags = agents.map((agent) => `--agent ${agent}`).join(' ');
    throw new ActionableCliError(
      `Existing signed-in ${conflicts.length === 1 ? 'skill was' : 'skills were'} modified; refusing to overwrite without --force.`,
      `signed-in skill install --${scope} ${flags}${scope === 'local' ? ` --root ${JSON.stringify(projectRoot)}` : ''} --force`,
    );
  }
  const receipts: SkillInstallReceipt[] = [];
  for (const plan of plans) {
    if (plan.state === 'current') {
      receipts.push({ ...plan, outcome: 'current' });
      if (interactive) tuiSkipped(`${plan.label} already knows signed-in · ${displaySkillPath(plan.destination, plan.scope === 'local' ? projectRoot : undefined)}`);
      continue;
    }
    if (plan.state === 'modified' && interactive && !parsed.booleans.has('--force')) {
      const update = await tuiConfirm(`Update ${plan.label}'s existing signed-in skill?`, 'Update', 'Keep mine');
      if (!update) {
        receipts.push({ ...plan, outcome: 'kept' });
        tuiSkipped(`${plan.label} kept its existing skill.`);
        continue;
      }
    }
    installSkill(source, plan.destination);
    const outcome = plan.state === 'missing' ? 'installed' : 'updated';
    receipts.push({ ...plan, outcome });
    if (interactive) tuiSuccess(`${plan.label} ${outcome} · ${displaySkillPath(plan.destination, plan.scope === 'local' ? projectRoot : undefined)}`);
  }
  if (parsed.booleans.has('--json')) printJson({ results: receipts, schema: 1 });
  else if (!quietMode && !interactive) printSkillReceipts(receipts, projectRoot);
  else if (interactive) tuiOutro(skillInstallSummary(receipts));
}

// Reports both discovery tiers by default so an operator can see overrides before installing another copy.
function runSkillStatus(commandArgs: string[]): void {
  const parsed = parseOptions(commandArgs, {
    booleans: ['--global', '--json', '--local', '--quiet'],
    repeated: ['--agent'],
    values: ['--root'],
  });
  if (parsed.positionals.length > 0) throw new Error(`Unexpected skill status argument '${parsed.positionals[0]}'`);
  const requestedScope = skillScopeFromFlags(parsed);
  const scopes: SkillInstallScope[] = requestedScope ? [requestedScope] : ['global', 'local'];
  const agents = parseSkillAgentIds(parsed.repeated['--agent'] ?? [], true);
  const source = bundledSkillDirectory();
  const projectRoot = path.resolve(parsed.values['--root'] ?? findSkillProjectRoot(process.cwd()));
  const plans = scopes.flatMap((scope) => skillInstallPlans(agents, scope, source, projectRoot));
  if (parsed.booleans.has('--json')) {
    printJson({ results: plans, schema: 1 });
    return;
  }
  if (quietMode) return;
  printHeading('signed-in skill', `${plans.filter((plan) => plan.state === 'current').length} current`);
  printRows(plans.map((plan) => ({
    detail: displaySkillPath(plan.destination, plan.scope === 'local' ? projectRoot : undefined),
    label: `${plan.label} · ${plan.scope}`,
    status: plan.state === 'missing' ? 'not installed' : plan.state,
    tone: plan.state === 'current' ? 'good' as const : plan.state === 'modified' ? 'warn' as const : 'muted' as const,
  })));
}

// Rejects contradictory scope flags before any path is resolved or written.
function skillScopeFromFlags(parsed: ParsedOptions): SkillInstallScope | undefined {
  const global = parsed.booleans.has('--global');
  const local = parsed.booleans.has('--local');
  if (global && local) throw new Error('Choose --global or --local, not both');
  if (parsed.values['--root'] && global) throw new Error('--root can be used only with --local');
  return global ? 'global' : local || parsed.values['--root'] ? 'local' : undefined;
}

// Keeps the scope prompt human-first while making the machine-wide signed-in use case the Enter default.
async function chooseSkillScope(projectRoot: string): Promise<SkillInstallScope> {
  return tuiSelect('Where should agents learn signed-in?', [
    { hint: 'Available in every project on this machine', label: 'Globally', value: 'global' },
    { hint: displaySkillPath(projectRoot), label: `This project · ${path.basename(projectRoot)}`, value: 'local' },
  ], 'global');
}

// Presents native agent destinations and preselects only clients detected on this machine or project.
async function chooseSkillAgents(scope: SkillInstallScope, projectRoot: string): Promise<SkillAgentId[]> {
  const detected = detectSkillAgents({ root: projectRoot });
  tuiHint('↑↓ move  ·  space toggle  ·  enter install');
  return tuiMultiselect(
    'Which agents should learn signed-in?',
    skillAgents.map((agent) => ({
      hint: `${detected.includes(agent.id) ? 'Detected · ' : ''}${displaySkillPath(skillInstallDestination(agent.id, scope, { root: projectRoot }), scope === 'local' ? projectRoot : undefined)}`,
      label: agent.label,
      value: agent.id,
    })),
    detected,
  );
}

// Accepts friendly aliases and comma-separated automation input before any value reaches path resolution.
function parseSkillAgentIds(values: string[], defaultAll = false): SkillAgentId[] {
  const requested = values.flatMap((value) => value.split(',')).map((value) => value.trim().toLowerCase()).filter(Boolean);
  if (requested.length === 0 && defaultAll) return skillAgents.map((agent) => agent.id);
  if (requested.includes('all')) return skillAgents.map((agent) => agent.id);
  const aliases: Record<string, SkillAgentId> = {
    'claude-code': 'claude',
    'gemini-cli': 'gemini',
    'github-copilot': 'copilot',
    'open-code': 'opencode',
  };
  const supported = new Set(skillAgents.map((agent) => agent.id));
  const agents = requested.map((value) => aliases[value] ?? value).map((value) => {
    if (!supported.has(value as SkillAgentId)) throw new Error(`Unsupported agent '${value}'. Try codex, claude, cursor, copilot, gemini, opencode, or all.`);
    return value as SkillAgentId;
  });
  return [...new Set(agents)];
}

// Freezes each reviewed destination and preflight state before a batch can make partial changes.
function skillInstallPlans(
  agents: SkillAgentId[],
  scope: SkillInstallScope,
  source: string,
  projectRoot: string,
): SkillInstallPlan[] {
  return agents.map((agent) => {
    const destination = skillInstallDestination(agent, scope, { root: projectRoot });
    return { agent, destination, label: skillAgent(agent).label, scope, state: inspectSkillInstall(source, destination) };
  });
}

// Shortens native user paths and makes project destinations readable without losing their exact relative location.
function displaySkillPath(destination: string, projectRoot?: string): string {
  if (projectRoot && destination.startsWith(`${projectRoot}${path.sep}`)) return path.relative(projectRoot, destination);
  const home = process.env.HOME;
  return home && (destination === home || destination.startsWith(`${home}${path.sep}`))
    ? `~${destination.slice(home.length)}`
    : destination;
}

// Summarizes an idempotent multi-agent install without implying modified copies were replaced when kept.
function skillInstallSummary(receipts: SkillInstallReceipt[]): string {
  const changed = receipts.filter((receipt) => ['installed', 'updated'].includes(receipt.outcome)).length;
  const current = receipts.filter((receipt) => receipt.outcome === 'current').length;
  const kept = receipts.filter((receipt) => receipt.outcome === 'kept').length;
  return [changed ? `${changed} ready` : undefined, current ? `${current} already current` : undefined, kept ? `${kept} kept` : undefined]
    .filter(Boolean).join(' · ') || 'Nothing changed';
}

// Gives redirected human installs the same compact receipts as other non-TUI signed-in commands.
function printSkillReceipts(receipts: SkillInstallReceipt[], projectRoot: string): void {
  printHeading('signed-in skill', skillInstallSummary(receipts));
  printRows(receipts.map((receipt) => ({
    detail: displaySkillPath(receipt.destination, receipt.scope === 'local' ? projectRoot : undefined),
    label: receipt.label,
    status: receipt.outcome,
    tone: receipt.outcome === 'kept' ? 'warn' as const : 'good' as const,
  })));
}

// Keeps destructive recovery obvious and interactive without asking the operator to memorize anything.
async function runReset(commandArgs: string[]): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: ['--json', '--quiet'], repeated: [], values: [] });
  if (parsed.positionals.length > 0) throw new Error(`Unexpected reset argument '${parsed.positionals[0]}'`);
  if (!interactiveTerminal()) throw new HumanRequiredError('Reset needs confirmation in an interactive terminal.', 'signed-in reset');
  tuiNote('This removes every signed-in connection, trusted project, machine identity, and audit receipt. Repository config files are not touched.', 'Reset signed-in');
  await requireInteractiveApproval('Remove all local signed-in state?', 'signed-in reset');
  await stopDaemonAndWait();
  eraseLocalSignedInState(paths);
  if (parsed.booleans.has('--json')) printJson({ removed: true });
  else printSuccess('Removed. signed-in login starts over.');
}

// Waits for the exact daemon socket to disappear so explicit stops and optional idle-only handoffs report truthfully.
async function stopDaemonAndWait(ifIdle = false): Promise<boolean> {
  const wasRunning = true;
  try {
    await callDaemon(paths, 'daemon.shutdown', ifIdle ? { ifIdle: true } : {}, { firstFrameTimeoutMs: 1_000 }).result;
  } catch (error) {
    if (error instanceof SignedInClientError && error.code === 'DAEMON_UNAVAILABLE') return false;
    if (!(error instanceof SignedInClientError) || error.code !== 'DAEMON_DISCONNECTED') throw error;
  }
  const deadline = Date.now() + 3_000;
  while (Date.now() < deadline) {
    try {
      await callDaemon(paths, 'ping', {}, { firstFrameTimeoutMs: 250 }).result;
    } catch (error) {
      if (error instanceof SignedInClientError && error.code === 'DAEMON_UNAVAILABLE') return wasRunning;
      throw error;
    }
    await resetDelay(50);
  }
  throw new SignedInClientError('DAEMON_STOP_TIMEOUT', 'The background helper did not stop', {
    remedy: 'signed-in daemon stop',
  });
}

// Provides a bounded cooperative wait while a confirmed reset waits for daemon shutdown.
function resetDelay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

// Controls on-demand daemon lifecycle and optional per-user startup registration.
async function runDaemonCommand(commandArgs: string[]): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: ['--if-idle'], repeated: [], values: [] });
  const subcommand = parsed.positionals[0] ?? 'status';
  if (parsed.positionals.length > 1) throw new Error(`Unexpected daemon argument '${parsed.positionals[1]}'`);
  if (parsed.booleans.has('--if-idle') && subcommand !== 'stop') throw new Error("Option '--if-idle' is only valid with daemon stop");
  if (subcommand === 'start') { await ensureDaemon(paths); const ping = await call('ping') as { pid: number }; printSuccess(`signed-in-daemon is running · pid ${ping.pid}`); return; }
  if (subcommand === 'status') {
    try { const ping = await callDaemon(paths, 'ping').result as { pid: number }; printSuccess(`signed-in-daemon is running · pid ${ping.pid}`); }
    catch { printWarning('signed-in-daemon is not running; the next command will start it automatically.'); }
    return;
  }
  if (subcommand === 'stop') {
    if (await stopDaemonAndWait(parsed.booleans.has('--if-idle'))) printSuccess('signed-in-daemon stopped.');
    else printWarning('signed-in-daemon is not running.');
    return;
  }
  if (subcommand === 'restart') {
    await stopDaemonAndWait();
    await ensureDaemon(paths);
    const ping = await call('ping') as { pid: number };
    printSuccess(`signed-in-daemon restarted · pid ${ping.pid}`);
    return;
  }
  if (subcommand === 'install') { const installed = await installDaemonService(paths); printSuccess(`Installed ${installed.manager} user service at ${installed.file}`); return; }
  if (subcommand === 'uninstall') {
    const uninstalled = await uninstallDaemonService(paths);
    if (uninstalled.removed) printSuccess(`Removed ${uninstalled.manager} user service at ${uninstalled.file}`);
    else printWarning(`No ${uninstalled.manager} user service was installed.`);
    return;
  }
  throw new Error(`Unknown daemon command '${subcommand}'`);
}

// Emits shell hooks that ask the daemon-free hidden completer for current services, aliases, and projects.
async function runCompletion(commandArgs: string[]): Promise<void> {
  const parsed = parseOptions(commandArgs, { booleans: [], repeated: [], values: [] });
  const shell = parsed.positionals[0] ?? 'zsh';
  if (parsed.positionals.length > 1) throw new Error(`Unexpected completion argument '${parsed.positionals[1]}'`);
  if (shell === 'zsh') {
    process.stdout.write(`#compdef signed-in\n_signed_in() { local -a values; values=(\"\${(@f)$(signed-in __complete \"\${words[@]:1}\")}\"); _describe 'signed-in' values }\ncompdef _signed_in signed-in\n# pair: public-key identity export import\n`); return;
  }
  if (shell === 'bash') {
    process.stdout.write(`_signed_in_completion() { COMPREPLY=( $(compgen -W \"$(signed-in __complete \"\${COMP_WORDS[@]:1}\")\" -- \"\${COMP_WORDS[COMP_CWORD]}\") ); }\ncomplete -F _signed_in_completion signed-in\n# pair: public-key identity export import\n`); return;
  }
  if (shell === 'fish') {
    process.stdout.write(`complete -c signed-in -f -a '(signed-in __complete (commandline -opc)[2..-1])'\n# pair: public-key identity export import\n`); return;
  }
  throw new Error('Supported completions: zsh, bash, fish');
}

// Reads only packaged catalog and owner-only state so tab completion never starts or unlocks the daemon.
function runComplete(words: string[]): void {
  const commands = ['alias', 'audit', 'completion', 'connections', 'daemon', 'demo', 'doctor', 'login', 'logout', 'mcp', 'pair', 'ping', 'policy', 'project', 'rename', 'request', 'reset', 'share-auth', 'skill', 'status', 'trust', 'use'];
  const state = loadMachineState(paths.stateFile);
  const current = words.at(-1) ?? '';
  let values = [...commands, ...Object.keys(builtInServices)];
  if (current.includes('@')) {
    const [service] = current.split('@');
    const aliases = state.services?.[service!]?.aliases ?? state.services?.[service!]?.accounts ?? [];
    values = aliases.map((alias) => `${service}@${alias}`);
  } else if (words[0] === 'project') values = ['trust', 'list', 'show', 'forget', ...Object.keys(state.projects)];
  else if (words[0] === 'pair') values = ['public-key', 'identity', 'export', 'import'];
  else if (words[0] === 'daemon') values = ['status', 'start', 'stop', 'restart', 'install', 'uninstall'];
  else if (words[0] === 'skill') values = ['install', 'status'];
  else if (words[0] === 'completion') values = ['zsh', 'bash', 'fish'];
  process.stdout.write(`${values.filter((value) => value.startsWith(current)).join('\n')}\n`);
}

// Restarts and retries one-shot calls only when transport failure proves the daemon never received the request.
async function call(method: string, params: unknown = {}): Promise<unknown> {
  try {
    return await callDaemon(paths, method, params).result;
  } catch (error) {
    if (!daemonUnavailableBeforeRequest(error)) throw error;
    await ensureDaemon(paths);
    return callDaemon(paths, method, params).result;
  }
}

// Turns protected mutations into visible human stops while non-interactive agents receive a stable remedy.
async function requireInteractiveApproval(question: string, remedy: string): Promise<void> {
  if (!process.stdin.isTTY || !process.stderr.isTTY) {
    throw new HumanRequiredError('This action needs confirmation in an interactive terminal.', remedy);
  }
  if (!await tuiConfirm(question, 'Confirm', 'Cancel', false)) throw new CliCancelledError();
}

// Streams already-redacted provider output while reserving stdout for JSON when requested.
async function runStreaming(
  method: string,
  params: unknown,
  attachStdin: boolean,
  json: boolean,
  observeOutput?: (chunk: Buffer) => void,
): Promise<unknown> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const streaming = callDaemon(paths, method, params, {
      onStderr: (chunk) => {
        observeOutput?.(chunk);
        process.stderr.write(chunk);
      },
      onStdout: (chunk) => {
        observeOutput?.(chunk);
        (json ? process.stderr : process.stdout).write(chunk);
      },
    });
    const cleanup = attachStreamingControls(streaming, attachStdin);
    let retry = false;
    try {
      return await streaming.result;
    } catch (error) {
      if (attempt === 0 && daemonUnavailableBeforeRequest(error)) retry = true;
      else throw error;
    } finally {
      cleanup();
    }
    if (retry) await ensureDaemon(paths);
  }
  throw new Error('Streaming request retry was exhausted');
}

// Restricts transparent replay to connection refusal before any request bytes could have reached the daemon.
function daemonUnavailableBeforeRequest(error: unknown): error is SignedInClientError {
  return error instanceof SignedInClientError && error.code === 'DAEMON_UNAVAILABLE';
}

// Advances trusted provider browser handoffs once their complete safe prompt appears in the redacted stream.
function createProviderLoginObserver(providerId: string, remote: boolean): (chunk: Buffer) => void {
  let handled = false;
  let outputTail = '';
  return (chunk) => {
    if (handled) return;
    outputTail = `${outputTail}${chunk.toString('utf8')}`.slice(-4096);
    const destination = findProviderLoginUrl(providerId, outputTail);
    if (!destination || remote) return;
    handled = true;
    void openExternalUrl(destination).catch(() => undefined);
  };
}

// Attaches temporary input and signal handlers so completed commands never keep the process alive.
function attachStreamingControls(streaming: StreamingCall, attachStdin: boolean): () => void {
  const streamWithEnd = streaming as StreamingCall & { endStdin?: () => void };
  let stdinEnded = false;
  const onData = (chunk: Buffer): void => streaming.sendStdin(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  const onEnd = (): void => {
    if (stdinEnded) return;
    stdinEnded = true;
    streamWithEnd.endStdin?.();
  };
  const onSignal = (): void => streaming.cancel();
  if (attachStdin) {
    process.stdin.on('data', onData);
    process.stdin.once('end', onEnd);
    process.stdin.once('close', onEnd);
    process.stdin.resume();
    if (process.stdin.readableEnded) onEnd();
  }
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  return () => {
    process.stdin.off('data', onData);
    if (attachStdin) {
      process.stdin.off('end', onEnd);
      process.stdin.off('close', onEnd);
      process.stdin.pause();
    }
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
  };
}

// Selects project context only from an explicit override or the most specific containing registered root.
function resolveProjectId(override?: string): string | undefined {
  const state = loadMachineState(paths.stateFile);
  const selected = override ?? process.env.SIGNED_IN_PROJECT ?? selectRegisteredProject(state, process.cwd());
  if (selected && !state.projects[selected]) throw new ActionableCliError(`Project '${selected}' is not registered on this machine.`, 'signed-in project list');
  return selected;
}

// Fetches a trusted project only when later status or extension-service rendering needs its metadata.
async function describeProject(projectId: string): Promise<TrustedProject> {
  return call('project.describe', { projectId }) as Promise<TrustedProject>;
}

// Uses the packaged catalog by default and permits a project-local extension only inside its trusted context.
async function serviceConfig(serviceId: string, projectId?: string): Promise<ServiceConfig> {
  if (builtInServices[serviceId]) return builtInServices[serviceId]!;
  if (projectId) {
    const project = await describeProject(projectId);
    if (project.config.providers[serviceId]) return project.config.providers[serviceId]!;
  }
  throw new ActionableCliError(`Unknown service '${serviceId}'.`, 'signed-in status --all');
}

// Loads all service connection rows once through the daemon's credential-blind status method.
async function serviceStatuses(projectId?: string): Promise<ServiceStatus[]> {
  return call('service.status', { ...(projectId ? { projectId } : {}) }) as Promise<ServiceStatus[]>;
}

// Prints full connection identity, routes, and a runnable repair for every unhealthy connection.
function printServiceDetail(service: ServiceStatus, config: ServiceConfig): void {
  printHeading(service.label);
  if (service.description) {
    printParagraph(service.description, { muted: true });
    process.stdout.write('\n');
  }
  if (service.accounts.length === 0) {
    printRows([
      { label: 'State', status: 'not connected', tone: 'muted' },
      { label: 'Connect', status: `signed-in login ${service.id}` },
      { label: 'Help', status: `signed-in help ${service.id}` },
    ]);
    return;
  }
  const multiple = service.accounts.length > 1;
  const connectionRows = service.accounts.flatMap((account) => [{
    detail: uniqueDetails([multiple && account.default ? 'default' : undefined, account.identity, connectionOriginDetail(account), connectionProblem(config, account)]).join(' · ') || undefined,
    label: account.account,
    status: account.state === 'connected' ? 'connected' : 'needs you',
    tone: account.state === 'connected' ? 'good' as const : 'warn' as const,
  }, ...(account.state !== 'connected' && account.remedy ? [{ label: `Fix ${account.account}`, status: account.remedy }] : [])]);
  printRows(connectionRows);
  process.stdout.write('\n');
  const target = `${service.id}${multiple ? '@<alias>' : ''}`;
  const selected = service.projectAccount
    ? service.accounts.find((account) => account.account === service.projectAccount) ?? service.accounts[0]!
    : service.accounts.find((account) => account.default) ?? service.accounts[0]!;
  printRows([
    ...(config.cli ? [{
      label: 'CLI',
      status: selected.nativeReady ? `signed-in ${target} <arguments…>` : `unavailable · ${selected.nativeRemedy ?? `signed-in login ${service.id}@${selected.account}`}`,
      tone: selected.nativeReady ? undefined : 'warn' as const,
    }] : []),
    ...(config.http ? [{
      label: 'API',
      status: selected.httpReady ? `signed-in request ${target} <METHOD> <path>` : `unavailable · ${selected.httpRemedy ?? `signed-in login ${service.id}@${selected.account}`}`,
      tone: selected.httpReady ? undefined : 'warn' as const,
    }] : []),
    ...(config.ping ? [{ label: 'Ping', status: `signed-in ping ${target}` }] : []),
    { label: 'Manage', status: `signed-in connections ${service.id}${multiple ? '@<alias>' : ''}` },
    { label: 'Add', status: `signed-in login ${service.id}` },
    { label: 'Help', status: `signed-in help ${service.id}` },
  ]);
}

// Reduces one service and its project binding to the compact default status row.
function statusRow(service: ServiceStatus): { detail?: string; label: string; status: string; tone: 'good' | 'muted' | 'warn' } {
  if (service.projectConnectionPending) {
    return {
      detail: `${service.projectAccount ? `${service.projectAccount} · ` : ''}not signed in on this machine`,
      label: service.label,
      status: 'needs you',
      tone: 'warn',
    };
  }
  if (service.projectConnectionMissing) {
    return {
      detail: `${service.projectAccount ? `${service.projectAccount} · ` : ''}project connection was removed`,
      label: service.label,
      status: 'needs you',
      tone: 'warn',
    };
  }
  const selected = service.projectAccount
    ? service.accounts.find((account) => account.account === service.projectAccount)
    : service.accounts.find((account) => account.default) ?? service.accounts[0];
  const multiple = service.accounts.length > 1;
  const otherAccounts = service.accounts.filter((account) => account.connectionId !== selected?.connectionId).map((account) => account.account);
  const additionalAccounts = otherAccounts.length > 3
    ? `also ${otherAccounts.slice(0, 3).join(', ')} +${otherAccounts.length - 3}`
    : otherAccounts.length > 0 ? `also ${otherAccounts.join(', ')}` : undefined;
  if (!selected) {
    return {
      detail: service.description,
      label: service.label,
      status: 'not connected',
      tone: 'muted',
    };
  }
  return {
    detail: uniqueDetails([
      selected.default ? 'default' : undefined,
      selected.account === 'primary' && selected.aliasSource === 'fallback' && !multiple ? undefined : selected.account,
      selected.identity ? conciseIdentity(service.id, selected.identity) : undefined,
      additionalAccounts,
      selected.state === 'connected' ? undefined : connectionProblem(builtInServices[service.id], selected),
    ]).join(' · ') || undefined,
    label: service.label,
    status: selected.state === 'connected' ? 'connected' : 'needs you',
    tone: selected.state === 'connected' ? 'good' : 'warn',
  };
}

// Names the most likely human action target without introducing @alias until a connection actually exists.
function loginTarget(service: ServiceStatus): string {
  const selected = service.projectAccount
    ? service.accounts.find((account) => account.account === service.projectAccount)
    : service.accounts.find((account) => account.default) ?? service.accounts[0];
  return `${service.id}${selected ? `@${selected.account}` : service.projectAccount ? `@${service.projectAccount}` : ''}`;
}

// Converts structured connection states into the shortest useful human explanation.
function connectionProblem(config: ServiceConfig | undefined, account: ProviderStatus): string | undefined {
  if (account.state === 'connected') return undefined;
  if (account.state === 'needs-cli') return config?.cli ? `${config.cli.command} is not installed` : 'vendor command is not installed';
  if (account.state === 'needs-trust') return config?.cli ? `${config.cli.command} changed since approval` : 'vendor command changed since approval';
  if (account.state === 'needs-fields') {
    const invalid = account.invalidFields?.map((field) => config?.credentials?.find((candidate) => candidate.id === field)?.label ?? field) ?? [];
    if (invalid.length > 0) return `invalid ${invalid.join(', ')}`;
    const labels = account.missingFields.map((field) => config?.credentials?.find((candidate) => candidate.id === field)?.label ?? field);
    return `missing ${labels.join(', ')}`;
  }
  return 'signed out by the provider';
}

// Removes repeated status fragments while preserving their first, most recognizable spelling.
function uniqueDetails(values: Array<string | false | undefined>): string[] {
  const seen = new Set<string>();
  return values.filter((value): value is string => {
    if (!value) return false;
    const key = value.trim().toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// Shortens provider identity evidence for overview rows while leaving the full value in detail and JSON views.
function conciseIdentity(serviceId: string, identity: string): string {
  const compact = identity.trim().replace(/\s+/gu, ' ');
  const awsAccount = compact.match(/arn:aws:[^:]*::(\d{6,}):/u)?.[1];
  if (awsAccount) return awsAccount;
  const readable = serviceId === 'github' && /^[A-Za-z0-9-]+$/u.test(compact) ? `@${compact}` : compact;
  return readable.length > 40 ? `${readable.slice(0, 39)}…` : readable;
}

// Marks copied and paired authority separately from the alias without cluttering ordinary provider-led logins.
function connectionOriginDetail(connection: ProviderStatus): string | undefined {
  if (connection.origin?.kind === 'adopted' && connection.origin.source) return `from ${connection.origin.source}`;
  if (connection.origin?.kind === 'paired') return 'from another machine';
  return undefined;
}

// Judges readiness against a project-bound connection when one is named, otherwise the machine default.
function projectServiceReady(service: ServiceStatus): boolean {
  if (service.state) return service.state === 'connected';
  if (service.projectConnectionMissing) return false;
  if (service.projectAccount) return Boolean(service.accounts.find((account) => account.account === service.projectAccount)?.ready);
  return serviceReady(service);
}

// Judges a service ready when its selected default connection is ready.
function serviceReady(service: ServiceStatus): boolean {
  if (service.state) return service.state === 'connected';
  return Boolean((service.accounts.find((account) => account.default) ?? service.accounts[0])?.ready);
}

// Builds the zero-connection catalog view locally so a harmless first glance creates no daemon or keychain state.
function pristineServiceStatuses(): ServiceStatus[] {
  return Object.entries(builtInServices).sort(([left], [right]) => left.localeCompare(right)).map(([id, service]) => ({
    accounts: [],
    ...(service.description ? { description: service.description } : {}),
    ...(service.docsUrl ? { docsUrl: service.docsUrl } : {}),
    id,
    label: service.label,
    remedy: `signed-in login ${id}`,
    required: false,
    signIn: service.signIn,
    state: 'not-connected',
  }));
}

// Avoids mistaking a missing completion mirror for a pristine machine when encrypted records still exist.
function machineAppearsPristine(): boolean {
  if (existsSync(paths.stateFile)) return false;
  if (!existsSync(paths.vaultDir)) return true;
  return !readdirSync(paths.vaultDir).some((entry) => entry.endsWith('.vault'));
}

// Enables guided prompts only when both the human input and dedicated TUI output support terminal controls.
function interactiveTerminal(): boolean {
  return Boolean(process.stdin.isTTY && process.stderr.isTTY);
}

interface ServiceTarget { account?: string; service: string }

// Parses the uniform service@alias token only in a signed-in-owned service position.
function parseServiceTarget(value: string): ServiceTarget {
  const separator = value.indexOf('@');
  const service = separator < 0 ? value : value.slice(0, separator);
  const account = separator < 0 ? undefined : value.slice(separator + 1);
  if (!/^[a-z0-9][a-z0-9-]{0,62}$/u.test(service)) throw new Error(`Invalid service '${service}'`);
  if (separator >= 0 && (!account || !isSafeAccountName(account))) {
    throw new Error(`Invalid alias '${account ?? ''}' — use lowercase letters, digits, and hyphens, up to 32 characters; reserved: ${[...reservedAccountNames].join(', ')}.`);
  }
  return { ...(account ? { account } : {}), service };
}

// Formats a target compactly while keeping the default connection implicit.
function formatTarget(target: ServiceTarget): string {
  return `${target.service}${target.account && target.account !== 'default' ? `@${target.account}` : ''}`;
}

// Deduplicates login targets while preserving the human's left-to-right order.
function uniqueTargets(targets: ServiceTarget[]): ServiceTarget[] {
  const seen = new Set<string>();
  return targets.filter((target) => {
    const key = `${target.service}@${target.account ?? 'default'}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// Resolves project shorthand for human rendering without duplicating daemon alias logic.
function projectBinding(binding: ProjectServiceBinding): {
  account?: string;
  checks: NonNullable<Exclude<ProjectServiceBinding, boolean | string>['checks']>;
  expectedIdentity?: string;
  required: boolean;
  target?: string;
} {
  if (binding === true) return { checks: [], required: true };
  if (typeof binding === 'string') return { account: binding, checks: [], required: true };
  const alias = binding.alias ?? binding.account;
  return {
    ...(alias ? { account: alias } : {}),
    checks: binding.checks ?? [],
    ...(binding.expectedIdentity ? { expectedIdentity: binding.expectedIdentity } : {}),
    required: binding.required === true,
    ...(binding.target ? { target: binding.target } : {}),
  };
}

// Checks PATH without starting a provider or trusting its bytes.
function serviceCliAvailable(serviceId: string): boolean {
  const command = builtInServices[serviceId]?.cli?.command;
  return command ? commandAvailable(command) : false;
}

interface ParsedOptions {
  booleans: Set<string>;
  positionals: string[];
  repeated: Record<string, string[]>;
  values: Record<string, string | undefined>;
}

// Parses built-in options strictly while preserving every token after -- as provider input.
function parseOptions(input: string[], specification: { booleans: string[]; repeated: string[]; values: string[] }): ParsedOptions {
  const booleans = new Set<string>();
  const positionals: string[] = [];
  const repeated = Object.fromEntries(specification.repeated.map((name) => [name, [] as string[]]));
  const values = Object.fromEntries(specification.values.map((name) => [name, undefined as string | undefined]));
  let passthrough = false;
  for (let index = 0; index < input.length; index += 1) {
    const argument = input[index]!;
    if (argument === '--') { passthrough = true; continue; }
    if (!passthrough && specification.booleans.includes(argument)) { booleans.add(argument); continue; }
    if (!passthrough && [...specification.values, ...specification.repeated].includes(argument)) {
      const next = input[index + 1];
      if (next === undefined) throw new Error(`${argument} needs a value`);
      index += 1;
      if (specification.repeated.includes(argument)) repeated[argument]!.push(next);
      else {
        if (values[argument] !== undefined) throw new Error(`${argument} can be supplied only once`);
        values[argument] = next;
      }
      continue;
    }
    if (!passthrough && argument !== '-' && argument.startsWith('-')) throw new Error(`Unknown option '${argument}'`);
    positionals.push(argument);
  }
  return { booleans, positionals, repeated, values };
}

// Reserves root options only before the command so provider flags remain byte-for-byte passthrough.
function extractLeadingOptions(input: string[]): { args: string[]; projectOverride?: string; rootFlags: Set<string> } {
  const args = [...input];
  let projectOverride: string | undefined;
  const rootFlags = new Set<string>();
  while (args[0]?.startsWith('-')) {
    const option = args.shift()!;
    if (option === '--project') { projectOverride = args.shift(); if (!projectOverride) throw new Error('--project needs a value'); continue; }
    if (['--help', '-h', '--json', '--no-color', '--quiet', '--version'].includes(option)) { rootFlags.add(option); continue; }
    throw new Error(`Unknown global option '${option}'`);
  }
  return { args, rootFlags, ...(projectOverride ? { projectOverride } : {}) };
}

// Lets project selection sit anywhere inside a signed-in-owned command without consuming provider flags.
function selectProjectOverride(parsed: ParsedOptions, leadingOverride?: string): string | undefined {
  return parsed.values['--project'] ?? leadingOverride;
}

// Detects built-in help only before passthrough begins so provider --help remains provider input.
function hasHelpFlag(input: string[]): boolean {
  return hasOwnedFlag(input, '--help') || hasOwnedFlag(input, '-h');
}

// Finds a flag only on signed-in's side of the -- boundary.
function hasOwnedFlag(input: string[], flag: string): boolean {
  const boundary = input.indexOf('--');
  return (boundary < 0 ? input : input.slice(0, boundary)).includes(flag);
}

// Reads one signed-in-owned option value without consuming similarly named provider arguments after passthrough.
function ownedOptionValue(input: string[], option: string): string | undefined {
  const boundary = input.indexOf('--');
  const owned = boundary < 0 ? input : input.slice(0, boundary);
  const index = owned.indexOf(option);
  return index >= 0 ? owned[index + 1] : undefined;
}

// Parses safe request headers while preventing caller-supplied authentication overrides.
function parseHeaders(values: string[]): Record<string, string> {
  const headers: Record<string, string> = {};
  const denied = new Set(['authorization', 'cookie', 'proxy-authorization', 'x-api-key', 'x-auth-token']);
  for (const value of values) {
    const separator = value.indexOf(':');
    if (separator < 1) throw new Error(`Invalid header '${value}'`);
    const name = value.slice(0, separator).trim();
    if (denied.has(name.toLowerCase())) throw new Error(`signed-in owns the '${name}' authentication header`);
    headers[name] = value.slice(separator + 1).trim();
  }
  return headers;
}

// Reads piped request bodies and pairing envelopes without shell interpretation.
function readStdin(): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on('data', (chunk: Buffer) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks)));
    process.stdin.on('error', reject);
    process.stdin.resume();
  });
}

// Asks Tailscale for online peers and presents a compact numbered chooser.
async function chooseTailscaleHost(): Promise<string> {
  const raw = execFileSync('tailscale', ['status', '--json'], { encoding: 'utf8' });
  const status = JSON.parse(raw) as { Peer?: Record<string, { DNSName?: string; HostName?: string; Online?: boolean }> };
  const hosts = Object.values(status.Peer ?? {}).filter((peer) => peer.Online)
    .map((peer) => peer.DNSName?.replace(/\.$/u, '') ?? peer.HostName).filter((host): host is string => Boolean(host));
  if (hosts.length === 0) throw new Error('No online Tailscale peers found');
  printRows(hosts.map((host, index) => ({ label: `${index + 1}`, status: host })));
  const selection = Number(await promptText('Share with machine', '1'));
  if (!Number.isInteger(selection) || !hosts[selection - 1]) throw new Error('Invalid machine selection');
  return hosts[selection - 1]!;
}

// Restricts SSH host syntax before it becomes a remote command argument.
function validateSshHost(host: string): void {
  if (!/^[A-Za-z0-9._:@-]+$/u.test(host) || host.startsWith('-')) throw new Error(`Unsafe SSH host '${host}'`);
}

// Sends a short-lived ciphertext envelope to a remote signed-in process over stdin.
function sshImportEnvelope(host: string, envelope: PairingEnvelope): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = execFile('ssh', [host, 'signed-in', 'pair', 'import', '--json'], { encoding: 'utf8' }, (error, stdout) => error ? reject(error) : resolve(stdout));
    child.stdin?.end(JSON.stringify(envelope));
  });
}

// Waits for an inherited SSH terminal without altering its behavior.
function waitForExit(child: ReturnType<typeof spawn>): Promise<number> {
  return new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code) => resolve(code ?? 1)); });
}

// Encodes the public identity card format shared with the daemon pairing module.
function encodeIdentityCard(identity: MachineIdentityPublic): string {
  return `signedin1:${Buffer.from(JSON.stringify(identity), 'utf8').toString('base64url')}`;
}

// Parses remote JSON when available while preserving diagnostics from older clients.
function parseJsonIfPossible(value: string): unknown {
  try { return JSON.parse(value) as unknown; } catch { return value.trim(); }
}

// Normalizes daemon and local failures into stable human and JSON fields.
function renderError(error: unknown): { code: string; message: string; remedy?: string; [key: string]: unknown } {
  if (error instanceof HumanRequiredError) return { code: error.code, message: error.message, remedy: error.remedy };
  if (error instanceof ActionableCliError) return { code: 'SIGNED_IN_ERROR', message: error.message, remedy: error.remedy };
  if (error instanceof SignedInClientError) {
    const details = typeof error.details === 'object' && error.details !== null ? error.details as Record<string, unknown> : {};
    return { code: error.code, message: error.message, ...details, ...(typeof details.remedy === 'string' ? { remedy: details.remedy } : {}) };
  }
  return { code: 'SIGNED_IN_ERROR', message: error instanceof Error ? error.message : String(error) };
}

// Normalizes terminal interrupts from readline into the same calm cancellation outcome as a declined confirmation.
function isUserAbort(error: unknown): boolean {
  return error instanceof Error && (error.name === 'AbortError' || error.message === 'Aborted with Ctrl+C');
}

// Maps human-required and policy outcomes to the documented automation exit contract.
function exitCodeForError(error: unknown): number {
  if (error instanceof HumanRequiredError) return 75;
  if (error instanceof SignedInClientError) {
    if (['AUTH_REQUIRED', 'HUMAN_REQUIRED'].includes(error.code)) return 75;
    if (error.code === 'POLICY_DENIED') return 77;
  }
  return 1;
}

// Uses compact receipt markers that remain readable without terminal color.
function formatAuditStatus(status: string): string {
  if (status === 'completed') return ui.good('✓');
  if (status === 'failed') return ui.danger('×');
  return ui.dim('·');
}

// Prints the complete surface while keeping login and direct service use visually primary.
function printHelp(): void {
  printBrand();
  process.stdout.write(`${ui.bold('Usage')}\n  signed-in                       connection readout and next actions\n  signed-in login                 connect a service\n  signed-in ping [service|--all]  test authenticated access\n  signed-in connections           repair or remove a connection\n  signed-in <service> …           run a vendor CLI\n  signed-in request <service> <METHOD> <path>\n                                  call a vendor API\n  signed-in status [service]      connection detail\n  signed-in doctor                check this machine\n  signed-in demo                  preview fictional connections\n\n${ui.bold('Examples')}\n  signed-in ping\n  signed-in aws s3 ls\n  signed-in github@work pr list\n  signed-in request polar GET /v1/products\n\n${ui.bold('More help')}\n  signed-in help agent            agents and scripts\n  signed-in help skill            install the agent guide\n  signed-in help connections      defaults, names, disconnecting\n  signed-in help machines         sharing across machines\n  signed-in help projects         per-project rules\n  signed-in help troubleshooting  repairs, daemon, reset\n`);
}

// Resolves command, service, and agent topics without starting or unlocking the daemon.
function printCommandHelp(commandName?: string): void {
  if (!commandName || commandName === '--help' || commandName === '-h') { printHelp(); return; }
  if (commandName === 'agent' || commandName === 'agents') {
    printHelpPage('Agent guide', agentHelp);
    return;
  }
  const group = helpGroups[commandName];
  if (group) {
    printHelpPage(commandName, group);
    return;
  }
  const command = commandHelp[commandName];
  if (command) {
    printHelpPage(commandName, command);
    return;
  }
  const service = builtInServices[commandName];
  if (service) {
    printServiceHelp(commandName, service);
    return;
  }
  throw new ActionableCliError(`Unknown help topic '${commandName}'.`, 'signed-in --help');
}

// Gives every help topic the same scannable contract for humans and model context windows.
function printHelpPage(title: string, page: HelpPage): void {
  printBrand();
  process.stdout.write(`${ui.bold(title)}\n${page.summary}\n\n${ui.bold('Usage')}\n${page.usage.map((line) => `  ${line}`).join('\n')}\n`);
  if (page.examples?.length) process.stdout.write(`\n${ui.bold('Examples')}\n${page.examples.map((line) => `  ${line}`).join('\n')}\n`);
  if (page.notes?.length) process.stdout.write(`\n${ui.bold('Notes')}\n${page.notes.map((line) => `  ${line}`).join('\n')}\n`);
}

// Describes signed-in's access routes while leaving provider-native flags to the provider itself.
function printServiceHelp(serviceId: string, service: ServiceConfig): void {
  const usage = [`signed-in login ${serviceId}[@alias]`];
  if (service.ping) usage.push(`signed-in ping ${serviceId}[@alias]`);
  if (service.cli) usage.push(`signed-in ${serviceId}[@alias] <${service.cli.command} arguments…>`);
  if (service.http) usage.push(`signed-in request ${serviceId}[@alias] <METHOD> <path> [request options…]`);
  const examples = [
    `signed-in status ${serviceId}`,
    ...(service.cli?.adapter === 'gws-gmail' ? [
      `signed-in ${serviceId} gmail users messages list --params '{"userId":"me","q":"in:inbox","maxResults":10}'`,
      `signed-in ${serviceId} gmail users messages get --params '{"userId":"me","id":"MESSAGE_ID","format":"full"}'`,
    ] : []),
    ...(service.cli ? [`signed-in ${serviceId} --help`] : []),
    service.cli
      ? `signed-in policy explain ${serviceId} --json -- <${service.cli.command} arguments…>`
      : `signed-in policy explain ${serviceId} --http GET /path --json`,
  ];
  const access = [service.cli ? 'native CLI' : undefined, service.http ? 'authenticated HTTP' : undefined].filter(Boolean).join(' and ');
  printHelpPage(service.label, {
    examples,
    notes: [
      `Access: ${access || 'guided sign-in only'}.`,
      'Add @alias only when status shows more than one connection.',
      ...(service.cli?.adapter === 'gws-gmail' ? [
        'Gmail reads only; sending, deleting, settings, other Workspace services, and auth export are blocked.',
        'First configure an OAuth desktop client with gws auth setup, then run signed-in login gws and choose your Gmail account.',
        'Login privately copies only ~/.config/gws/client_secret.json; existing gws user credentials and Google Cloud login are not imported or changed.',
        'Parameters must be inline JSON. Put flags after the method; file input/output and helper commands are not supported.',
      ] : []),
      `Provider documentation: ${service.docsUrl ?? 'not configured'}`,
    ],
    summary: service.description ?? `Authenticated ${service.label} access through signed-in.`,
    usage,
  });
}

// Reads the packaged version so source and globally installed entry points agree.
function readPackageVersion(): string {
  const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version?: unknown };
  if (typeof manifest.version !== 'string') throw new Error('signed-in package version is unavailable');
  return manifest.version;
}
