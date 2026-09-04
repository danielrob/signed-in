import { execFile } from 'node:child_process';
import process from 'node:process';

/**
 * Opens trusted setup documentation without a shell and remains alive until the launcher reports
 * success, so an awaited CLI action cannot terminate as unsettled top-level work.
 */
export function openExternalUrl(value: string): Promise<void> {
  const destination = new URL(value);
  if (!['http:', 'https:'].includes(destination.protocol)) throw new Error(`Cannot open ${destination.protocol} links`);
  const invocation = process.platform === 'darwin'
    ? { args: [destination.href], command: 'open' }
    : process.platform === 'win32'
      ? { args: ['/d', '/s', '/c', 'start', '', destination.href], command: 'cmd.exe' }
      : { args: [destination.href], command: 'xdg-open' };
  return new Promise((resolve, reject) => {
    execFile(invocation.command, invocation.args, { windowsHide: true }, (error) => error ? reject(error) : resolve());
  });
}

// Extracts only provider-owned login URLs whose exact origin and shape signed-in has explicitly trusted.
export function findProviderLoginUrl(providerId: string, output: string): string | undefined {
  if (providerId === 'convex') return output.match(/https:\/\/auth\.convex\.dev\/device\?user_code=[A-Z0-9-]+/u)?.[0];
  if (providerId === 'github') return output.match(/https:\/\/github\.com\/login\/device/u)?.[0];
  if (providerId === 'gws') {
    // GWS waits for a localhost callback; only a complete Google-owned OAuth URL is safe to open.
    return output.match(/https:\/\/accounts\.google\.com\/o\/oauth2\/(?:v2\/)?auth\?[^\s]+\r?\n/u)?.[0].trim();
  }
  return undefined;
}
