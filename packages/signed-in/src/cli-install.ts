import { execFile, execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

export interface CliInstallPlan {
  args: string[];
  command: string;
  displayCommand: string;
}

export type CliInstallRunner = (command: string, args: string[]) => Promise<{ stderr: string; stdout: string }>;

interface CliInstallRecipe {
  args: string[];
  command: string;
  platforms: NodeJS.Platform[];
}

interface CliInstallResolutionOptions {
  available?: (command: string) => boolean;
  platform?: NodeJS.Platform;
}

const allPlatforms: NodeJS.Platform[] = ['aix', 'darwin', 'freebsd', 'linux', 'openbsd', 'sunos', 'win32'];
const unixPlatforms: NodeJS.Platform[] = ['darwin', 'linux'];
const wingetConsent = ['--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity'];

const recipesByService: Readonly<Record<string, readonly CliInstallRecipe[]>> = {
  aws: [
    { args: ['install', 'awscli'], command: 'brew', platforms: unixPlatforms },
    { args: ['/i', 'https://awscli.amazonaws.com/AWSCLIV2-User.msi', '/qn', '/norestart'], command: 'msiexec.exe', platforms: ['win32'] },
  ],
  cloudflare: [
    { args: ['install', '--global', 'wrangler@latest'], command: 'npm', platforms: allPlatforms },
  ],
  convex: [
    { args: ['install', '--global', 'convex'], command: 'npm', platforms: allPlatforms },
  ],
  gcp: [
    { args: ['install', '--cask', 'gcloud-cli'], command: 'brew', platforms: ['darwin'] },
    { args: ['install', '--exact', '--id', 'Google.CloudSDK', ...wingetConsent], command: 'winget', platforms: ['win32'] },
  ],
  github: [
    { args: ['install', 'gh'], command: 'brew', platforms: unixPlatforms },
    { args: ['install', '--exact', '--id', 'GitHub.cli', ...wingetConsent], command: 'winget', platforms: ['win32'] },
  ],
  gws: [
    { args: ['install', 'googleworkspace-cli'], command: 'brew', platforms: unixPlatforms },
    { args: ['install', '--global', '@googleworkspace/cli'], command: 'npm', platforms: allPlatforms },
  ],
  netlify: [
    { args: ['install', '--global', 'netlify-cli'], command: 'npm', platforms: allPlatforms },
  ],
  openai: [
    { args: ['install', 'openai/tools/openai'], command: 'brew', platforms: unixPlatforms },
  ],
  sentry: [
    { args: ['install', '--global', '@sentry/cli'], command: 'npm', platforms: allPlatforms },
  ],
  shopify: [
    { args: ['install', '--global', '@shopify/cli@latest'], command: 'npm', platforms: allPlatforms },
  ],
  stripe: [
    { args: ['install', 'stripe/stripe-cli/stripe'], command: 'brew', platforms: unixPlatforms },
    { args: ['install', 'stripe'], command: 'scoop', platforms: ['win32'] },
  ],
};

// Selects the first reviewed recipe this operating system can actually run without letting provider config supply executable input.
export function resolveCliInstallPlan(
  serviceId: string,
  options: CliInstallResolutionOptions = {},
): CliInstallPlan | undefined {
  const available = options.available ?? commandAvailable;
  const platform = options.platform ?? process.platform;
  const recipe = recipesByService[serviceId]?.find((candidate) =>
    candidate.platforms.includes(platform) && available(candidate.command));
  if (!recipe) return undefined;
  const command = platform === 'win32' && recipe.command === 'npm' ? 'npm.cmd' : recipe.command;
  return { args: [...recipe.args], command, displayCommand: `${recipe.command} ${recipe.args.join(' ')}` };
}

// Runs only a previously resolved fixed argv plan and keeps package-manager noise out of the guided terminal on success.
export async function installCli(plan: CliInstallPlan, runner: CliInstallRunner = runInstallCommand): Promise<void> {
  try {
    await runner(plan.command, [...plan.args]);
  } catch (error) {
    throw new Error(installFailureMessage(plan, error), { cause: error });
  }
}

// Checks PATH without invoking a provider or passing user-controlled arguments through a shell.
export function commandAvailable(command: string): boolean {
  try {
    if (path.isAbsolute(command)) return existsSync(command);
    execFileSync(process.platform === 'win32' ? 'where' : 'which', [command], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

// Captures a bounded install transcript so ordinary npm chatter disappears while failures retain one useful local diagnosis.
function runInstallCommand(command: string, args: string[]): Promise<{ stderr: string; stdout: string }> {
  return new Promise((resolve, reject) => {
    execFile(command, args, {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
      shell: false,
      windowsHide: true,
    }, (error, stdout, stderr) => {
      if (error) {
        reject(Object.assign(error, { stderr, stdout }));
        return;
      }
      resolve({ stderr, stdout });
    });
  });
}

// Turns verbose package-manager failures into a short actionable line without echoing an entire process transcript into the TUI.
function installFailureMessage(plan: CliInstallPlan, error: unknown): string {
  const record = typeof error === 'object' && error !== null ? error as { message?: unknown; stderr?: unknown; stdout?: unknown } : undefined;
  const transcript = [record?.stderr, record?.stdout]
    .filter((value): value is string => typeof value === 'string')
    .flatMap((value) => value.split(/\r?\n/u))
    .map((line) => line.replace(/\u001B\[[0-?]*[ -/]*[@-~]/gu, '').trim())
    .filter(Boolean);
  const detail = transcript.at(-1) ?? (typeof record?.message === 'string' ? record.message : String(error));
  const concise = detail.length > 240 ? `${detail.slice(0, 237)}…` : detail;
  return `${plan.displayCommand} failed · ${concise}`;
}
