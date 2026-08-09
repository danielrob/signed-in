import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  bundledSkillDirectory,
  findSkillProjectRoot,
  inspectSkillInstall,
  installSkill,
  skillInstallDestination,
  type SkillAgentId,
} from '../packages/signed-in/src/skill-install.js';

test('packaged signed-in skill is valid and free of scaffold instructions', () => {
  const source = bundledSkillDirectory();
  const skill = readFileSync(path.join(source, 'SKILL.md'), 'utf8');
  assert.match(skill, /^---\nname: signed-in\ndescription: .+\n---/u);
  assert.match(skill, /signed-in help agent/u);
  assert.doesNotMatch(skill, /TODO/u);
  assert.match(skill, /Do not send `Authorization`/u);
  assert.equal(existsSync(path.join(source, 'agents', 'openai.yaml')), true);
});

test('agent destinations use native global and project discovery paths', () => {
  const home = path.join(tmpdir(), 'signed-in-home');
  const root = path.join(tmpdir(), 'signed-in-project');
  const environment = {
    CODEX_HOME: path.join(home, 'custom-codex'),
    XDG_CONFIG_HOME: path.join(home, 'custom-config'),
  };
  const expectedGlobal: Record<SkillAgentId, string> = {
    claude: path.join(home, '.claude', 'skills', 'signed-in'),
    codex: path.join(home, 'custom-codex', 'skills', 'signed-in'),
    copilot: path.join(home, '.copilot', 'skills', 'signed-in'),
    cursor: path.join(home, '.cursor', 'skills', 'signed-in'),
    gemini: path.join(home, '.gemini', 'skills', 'signed-in'),
    opencode: path.join(home, 'custom-config', 'opencode', 'skills', 'signed-in'),
  };
  const expectedLocal: Record<SkillAgentId, string> = {
    claude: path.join(root, '.claude', 'skills', 'signed-in'),
    codex: path.join(root, '.agents', 'skills', 'signed-in'),
    copilot: path.join(root, '.github', 'skills', 'signed-in'),
    cursor: path.join(root, '.cursor', 'skills', 'signed-in'),
    gemini: path.join(root, '.gemini', 'skills', 'signed-in'),
    opencode: path.join(root, '.opencode', 'skills', 'signed-in'),
  };
  for (const agent of Object.keys(expectedGlobal) as SkillAgentId[]) {
    assert.equal(skillInstallDestination(agent, 'global', { environment, home }), expectedGlobal[agent]);
    assert.equal(skillInstallDestination(agent, 'local', { root }), expectedLocal[agent]);
  }
});

test('skill installation is idempotent and preserves operator-added resources', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-skill-copy-'));
  const source = path.join(root, 'source');
  const destination = path.join(root, 'destination');
  mkdirSync(path.join(source, 'agents'), { recursive: true });
  writeFileSync(path.join(source, 'SKILL.md'), 'first\n');
  writeFileSync(path.join(source, 'agents', 'openai.yaml'), 'interface: {}\n');
  assert.equal(inspectSkillInstall(source, destination), 'missing');
  installSkill(source, destination);
  assert.equal(inspectSkillInstall(source, destination), 'current');
  writeFileSync(path.join(destination, 'SKILL.md'), 'operator edit\n');
  writeFileSync(path.join(destination, 'notes.md'), 'keep me\n');
  assert.equal(inspectSkillInstall(source, destination), 'modified');
  installSkill(source, destination);
  assert.equal(inspectSkillInstall(source, destination), 'current');
  assert.equal(readFileSync(path.join(destination, 'notes.md'), 'utf8'), 'keep me\n');
});

test('local skill roots follow a nested shell to its repository boundary', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'signed-in-skill-root-'));
  const nested = path.join(root, 'packages', 'app');
  mkdirSync(path.join(root, '.git'));
  mkdirSync(nested, { recursive: true });
  assert.equal(findSkillProjectRoot(nested), root);
});
