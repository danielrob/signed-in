import assert from 'node:assert/strict';
import test from 'node:test';

import {
  installCli,
  resolveCliInstallPlan,
  type CliInstallRunner,
} from '../packages/signed-in/src/cli-install.js';
import { builtInServices } from '../packages/signed-in/src/catalog.js';

// Proves the installer catalog spans native and Node CLIs while remaining fixed to reviewed service/package pairs.
test('CLI installers resolve to trusted platform-aware argv', () => {
  const convex = resolveCliInstallPlan('convex', { available: (command) => command === 'npm', platform: 'darwin' });
  assert.ok(convex);
  assert.deepEqual(convex.args, ['install', '--global', 'convex']);
  assert.equal(convex.displayCommand, 'npm install --global convex');

  const macAws = resolveCliInstallPlan('aws', { available: (command) => command === 'brew', platform: 'darwin' });
  assert.deepEqual(macAws, { args: ['install', 'awscli'], command: 'brew', displayCommand: 'brew install awscli' });

  const windowsGithub = resolveCliInstallPlan('github', { available: (command) => command === 'winget', platform: 'win32' });
  assert.ok(windowsGithub);
  assert.deepEqual(windowsGithub.args.slice(0, 4), ['install', '--exact', '--id', 'GitHub.cli']);

  const manualSentry = resolveCliInstallPlan('sentry', { available: () => true, platform: 'linux' });
  assert.ok(manualSentry);
  assert.deepEqual(manualSentry.args, ['install', '--global', '@sentry/cli']);

  const knownButAmbiguous = resolveCliInstallPlan('polar', { available: () => true, platform: 'darwin' });
  assert.equal(knownButAmbiguous, undefined);

  assert.equal(resolveCliInstallPlan('project-provider', { available: () => true, platform: 'darwin' }), undefined);
  assert.equal(resolveCliInstallPlan('../../convex', { available: () => true, platform: 'darwin' }), undefined);
  assert.equal(resolveCliInstallPlan('convex', { available: () => false, platform: 'darwin' }), undefined);
});

// Makes adding a future CLI-backed vendor an explicit installer-or-documented-exception decision instead of another one-off omission.
test('every built-in CLI service has a macOS installer except Polar’s privileged upstream flow', () => {
  const cliServices = Object.entries(builtInServices)
    .filter(([, service]) => Boolean(service.cli))
    .map(([serviceId]) => serviceId)
    .sort();
  const installable = cliServices.filter((serviceId) =>
    Boolean(resolveCliInstallPlan(serviceId, { available: () => true, platform: 'darwin' })));
  const guideOnly = cliServices.filter((serviceId) => !installable.includes(serviceId));
  assert.deepEqual(installable, ['aws', 'cloudflare', 'convex', 'gcp', 'github', 'netlify', 'openai', 'sentry', 'stripe']);
  assert.deepEqual(guideOnly, ['polar']);
});

// Ensures the executor receives a copied argv vector so neither UI nor runner can mutate the sealed install recipe.
test('CLI installation executes the resolved argv without a command string shell', async () => {
  const plan = resolveCliInstallPlan('convex', { available: () => true, platform: 'darwin' });
  assert.ok(plan);
  const expectedArgs = [...plan.args];
  let receivedCommand = '';
  const runner: CliInstallRunner = async (command, args) => {
    receivedCommand = command;
    assert.notEqual(args, plan.args);
    assert.deepEqual(args, expectedArgs);
    args.push('unexpected');
    return { stderr: '', stdout: '' };
  };
  await installCli(plan, runner);
  assert.match(receivedCommand, /^npm(?:\.cmd)?$/u);
  assert.deepEqual(plan.args, expectedArgs);
});

// Keeps failed package installs understandable without dumping their full noisy transcript into the login guide.
test('CLI installation reports only the useful tail of a package-manager failure', async () => {
  const plan = resolveCliInstallPlan('convex', { available: () => true, platform: 'darwin' });
  assert.ok(plan);
  await assert.rejects(
    installCli(plan, async () => {
      throw Object.assign(new Error('npm exited 1'), { stderr: 'verbose setup\npermission denied\n' });
    }),
    (error: unknown) => error instanceof Error
      && error.message === 'npm install --global convex failed · permission denied'
      && !error.message.includes('verbose setup'),
  );
});
