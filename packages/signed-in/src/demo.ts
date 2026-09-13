import process from 'node:process';

import { builtInServices } from './catalog.js';
import { tuiIntro, tuiOutro, tuiSelectOrDefault } from './tui.js';
import { printHeading, printJson, printRows } from './ui.js';

const connections: Array<{ service: string; aliases: string[]; identity?: string }> = [
  { service: 'aws', aliases: ['production', 'staging', 'sandbox'] },
  { service: 'clerk', aliases: ['web-prod', 'web-dev', 'mobile'] },
  { service: 'cloudflare', aliases: ['acme1', 'acme2', 'personal'] },
  { service: 'convex', aliases: ['main-app', 'preview'] },
  { service: 'datocms', aliases: ['marketing', 'docs'] },
  { service: 'gcp', aliases: ['analytics', 'ml-lab'] },
  { service: 'github', aliases: ['personal', 'acme1', 'acme2'], identity: '@acme-dev' },
  { service: 'netlify', aliases: ['portfolio', 'acme-site', 'client-site'] },
  { service: 'openai', aliases: ['product', 'research', 'personal'] },
  { service: 'polar', aliases: ['acme-saas', 'side-project'] },
  { service: 'resend', aliases: ['transactional', 'newsletters'] },
  { service: 'sentry', aliases: ['web', 'api', 'mobile'] },
  { service: 'shopify', aliases: ['flagship-store', 'outlet', 'development'] },
];

// Renders documentation fixtures through the normal UI without importing the daemon, vault, or account discovery.
export async function renderDemoScreen(options: { json?: boolean; quiet?: boolean } = {}): Promise<void> {
  if (options.quiet) return;
  const accountCount = connections.reduce((count, connection) => count + connection.aliases.length, 0);
  if (options.json) {
    printJson({ demo: true, serviceCount: connections.length, connectionCount: accountCount, services: connections });
    return;
  }
  const interactive = Boolean(process.stdin.isTTY && process.stdout.isTTY && process.stderr.isTTY);
  if (interactive) process.stdout.write('\u001b[2J\u001b[H');
  printHeading('signed-in', `${connections.length} services connected · ${accountCount} connections`);
  printRows(connections.map(statusRow));
  process.stdout.write('\n');
  if (!interactive) return;
  tuiIntro('signed-in');
  await tuiSelectOrDefault('What would you like to do?', [
    { label: 'Connect another service', value: 'login' },
    { label: 'Manage connections', value: 'connections' },
    { label: 'Test all connections', value: 'test' },
    { hint: 'Teach Codex, Claude Code +3 to use signed-in', label: 'Install the agent skill', value: 'skill' },
    { label: 'Done', value: 'done' },
  ], 'skill', 'done');
  tuiOutro('Demo finished.');
}

// Formats only fictional aliases and identities while taking provider names and status styling from the product.
function statusRow(connection: typeof connections[number]): Parameters<typeof printRows>[0][number] {
  const [primary, ...others] = connection.aliases;
  return {
    detail: ['default', primary, connection.identity, others.length ? `also ${others.join(', ')}` : undefined]
      .filter(Boolean).join(' · '),
    label: builtInServices[connection.service]!.label,
    status: 'connected',
    tone: 'good',
  };
}
