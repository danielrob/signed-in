import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { commandAvailable } from './cli-install.js';

export type SkillAgentId = 'claude' | 'codex' | 'copilot' | 'cursor' | 'gemini' | 'opencode';
export type SkillInstallScope = 'global' | 'local';
export type SkillInstallState = 'current' | 'missing' | 'modified';

export interface SkillAgentDefinition {
  command: string;
  id: SkillAgentId;
  label: string;
  localDirectory: string;
}

export interface SkillInstallContext {
  cwd?: string;
  environment?: NodeJS.ProcessEnv;
  home?: string;
  root?: string;
}

export const skillAgents: readonly SkillAgentDefinition[] = [
  { command: 'codex', id: 'codex', label: 'Codex', localDirectory: '.agents/skills' },
  { command: 'claude', id: 'claude', label: 'Claude Code', localDirectory: '.claude/skills' },
  { command: 'cursor', id: 'cursor', label: 'Cursor', localDirectory: '.cursor/skills' },
  { command: 'copilot', id: 'copilot', label: 'GitHub Copilot', localDirectory: '.github/skills' },
  { command: 'gemini', id: 'gemini', label: 'Gemini CLI', localDirectory: '.gemini/skills' },
  { command: 'opencode', id: 'opencode', label: 'OpenCode', localDirectory: '.opencode/skills' },
];

// Resolves the immutable skill payload beside either the source module or its compiled distribution.
export function bundledSkillDirectory(): string {
  return fileURLToPath(new URL('../skill/signed-in', import.meta.url));
}

// Finds a repository boundary without invoking Git or evaluating any project-owned configuration.
export function findSkillProjectRoot(startDirectory: string): string {
  const original = path.resolve(startDirectory);
  let current = original;
  while (true) {
    if (existsSync(path.join(current, '.git'))) return current;
    const parent = path.dirname(current);
    if (parent === current) return original;
    current = parent;
  }
}

// Maps each supported agent to its documented user or project discovery path.
export function skillInstallDestination(
  agentId: SkillAgentId,
  scope: SkillInstallScope,
  context: SkillInstallContext = {},
): string {
  const definition = skillAgent(agentId);
  if (scope === 'local') {
    const root = path.resolve(context.root ?? findSkillProjectRoot(context.cwd ?? process.cwd()));
    return path.join(root, definition.localDirectory, 'signed-in');
  }
  const environment = context.environment ?? process.env;
  const home = context.home ?? homedir();
  if (agentId === 'codex') return path.join(environment.CODEX_HOME ?? path.join(home, '.codex'), 'skills', 'signed-in');
  if (agentId === 'opencode') return path.join(environment.XDG_CONFIG_HOME ?? path.join(home, '.config'), 'opencode', 'skills', 'signed-in');
  return path.join(home, `.${agentId === 'copilot' ? 'copilot' : agentId}`, 'skills', 'signed-in');
}

// Detects likely installed agent clients without starting them or trusting their configuration.
export function detectSkillAgents(
  context: SkillInstallContext = {},
  available: (command: string) => boolean = commandAvailable,
): SkillAgentId[] {
  const environment = context.environment ?? process.env;
  const home = context.home ?? homedir();
  const root = path.resolve(context.root ?? findSkillProjectRoot(context.cwd ?? process.cwd()));
  return skillAgents.filter((agent) => {
    const globalDestination = skillInstallDestination(agent.id, 'global', { environment, home });
    const localDestination = skillInstallDestination(agent.id, 'local', { root });
    return available(agent.command)
      || existsSync(path.dirname(path.dirname(globalDestination)))
      || existsSync(path.dirname(path.dirname(localDestination)));
  }).map((agent) => agent.id);
}

// Compares only packaged files so operator-added notes or resources do not make an installation stale.
export function inspectSkillInstall(source: string, destination: string): SkillInstallState {
  if (!existsSync(destination)) return 'missing';
  if (!statSync(destination).isDirectory()) return 'modified';
  return skillFiles(source).every((relativePath) => {
    const installed = path.join(destination, relativePath);
    return existsSync(installed) && statSync(installed).isFile()
      && readFileSync(installed).equals(readFileSync(path.join(source, relativePath)));
  }) ? 'current' : 'modified';
}

// Copies the reviewed payload in place while preserving unrelated operator-added files in that skill directory.
export function installSkill(source: string, destination: string): void {
  if (!existsSync(path.join(source, 'SKILL.md'))) throw new Error(`Packaged signed-in skill is missing from ${source}`);
  if (existsSync(destination) && !statSync(destination).isDirectory()) throw new Error(`Skill destination is not a directory: ${destination}`);
  for (const relativePath of skillFiles(source)) {
    const target = path.join(destination, relativePath);
    mkdirSync(path.dirname(target), { recursive: true });
    copyFileSync(path.join(source, relativePath), target);
  }
}

// Resolves one reviewed definition or fails before an unrecognized agent can influence a filesystem path.
export function skillAgent(agentId: SkillAgentId): SkillAgentDefinition {
  const definition = skillAgents.find((agent) => agent.id === agentId);
  if (!definition) throw new Error(`Unsupported agent '${agentId}'`);
  return definition;
}

// Enumerates regular payload files recursively and rejects links or special files from the install surface.
function skillFiles(source: string, relativeDirectory = ''): string[] {
  const directory = path.join(source, relativeDirectory);
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDirectory, entry.name);
    if (entry.isDirectory()) return skillFiles(source, relativePath);
    if (entry.isFile()) return [relativePath];
    throw new Error(`Packaged signed-in skill contains an unsupported file: ${relativePath}`);
  });
}
