import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { callDaemon, SignedInClientError } from './client.js';
import { signedInBuild, type SignedInPaths } from './paths.js';

const launchAgentLabel = 'signed-in.daemon';

export interface DaemonInstallResult {
  file: string;
  manager: 'launchd' | 'systemd';
}

export interface DaemonUninstallResult extends DaemonInstallResult {
  removed: boolean;
}

// Installs a user-scoped startup service while handing any live on-demand daemon over before the manager starts.
export async function installDaemonService(paths: SignedInPaths): Promise<DaemonInstallResult> {
  const daemonEntry = locateInstalledDaemonEntry();
  if (process.platform === 'darwin') return installLaunchAgent(daemonEntry, paths);
  if (process.platform === 'linux') return installSystemdUserService(daemonEntry, paths);
  throw new Error('Persistent daemon installation is currently supported on macOS and Linux; Windows auto-starts on first use');
}

// Removes the optional startup registration and stops its process without touching encrypted authority or audit state.
export async function uninstallDaemonService(paths: SignedInPaths): Promise<DaemonUninstallResult> {
  if (process.platform === 'darwin') {
    const file = path.join(homedir(), 'Library', 'LaunchAgents', `${launchAgentLabel}.plist`);
    const domain = `gui/${typeof process.getuid === 'function' ? process.getuid() : ''}`;
    try { execFileSync('launchctl', ['bootout', `${domain}/${launchAgentLabel}`], { stdio: 'ignore' }); } catch { /* An absent or unloaded registration is already uninstalled. */ }
    await stopLiveDaemon(paths);
    const removed = existsSync(file);
    if (removed) unlinkSync(file);
    return { file, manager: 'launchd', removed };
  }
  if (process.platform === 'linux') {
    const configRoot = process.env.XDG_CONFIG_HOME ?? path.join(homedir(), '.config');
    const file = path.join(configRoot, 'systemd', 'user', 'signed-in.service');
    try { execFileSync('systemctl', ['--user', 'disable', '--now', 'signed-in.service'], { stdio: 'ignore' }); } catch { /* An absent or unavailable user manager leaves no running registration to remove. */ }
    await stopLiveDaemon(paths);
    const removed = existsSync(file);
    if (removed) unlinkSync(file);
    try { execFileSync('systemctl', ['--user', 'daemon-reload'], { stdio: 'ignore' }); } catch { /* Headless sessions may not expose the user manager after the file is gone. */ }
    return { file, manager: 'systemd', removed };
  }
  throw new Error('Windows has no persistent signed-in service to uninstall; it starts on demand');
}

/** Keeps signed-in available after macOS restarts without depending on an interactive shell. */
async function installLaunchAgent(daemonEntry: string, paths: SignedInPaths): Promise<DaemonInstallResult> {
  const file = path.join(homedir(), 'Library', 'LaunchAgents', `${launchAgentLabel}.plist`);
  const environment = daemonEnvironment(paths);
  const environmentXml = Object.entries(environment).map(([name, value]) =>
    `    <key>${escapeXml(name)}</key><string>${escapeXml(value)}</string>`).join('\n');
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${launchAgentLabel}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${escapeXml(process.execPath)}</string>
    <string>${escapeXml(daemonEntry)}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
${environmentXml}
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>${escapeXml(paths.daemonLogFile)}</string>
  <key>StandardErrorPath</key><string>${escapeXml(paths.daemonLogFile)}</string>
</dict>
</plist>
`;
  const hadPreviousDefinition = existsSync(file);
  const rollback = installFileAtomically(file, plist);
  const domain = `gui/${typeof process.getuid === 'function' ? process.getuid() : ''}`;
  try {
    try { execFileSync('launchctl', ['bootout', `${domain}/${launchAgentLabel}`], { stdio: 'ignore' }); } catch { /* A first install has no loaded job. */ }
    await stopLiveDaemon(paths);
    execFileSync('launchctl', ['bootstrap', domain, file], { stdio: 'ignore' });
    execFileSync('launchctl', ['kickstart', `${domain}/${launchAgentLabel}`], { stdio: 'ignore' });
    await verifyManagedDaemon(paths);
    return { file, manager: 'launchd' };
  } catch (error) {
    let rollbackError: unknown;
    try {
      try { execFileSync('launchctl', ['bootout', `${domain}/${launchAgentLabel}`], { stdio: 'ignore' }); } catch { /* A failed candidate may never have loaded. */ }
      rollback();
      if (hadPreviousDefinition) {
        execFileSync('launchctl', ['bootstrap', domain, file], { stdio: 'ignore' });
        execFileSync('launchctl', ['kickstart', `${domain}/${launchAgentLabel}`], { stdio: 'ignore' });
      }
    } catch (recoveryError) { rollbackError = recoveryError; }
    throw installError('launchd', file, error, rollbackError);
  }
}

// Creates and enables a user systemd service with the same PATH and state roots visible to the installing client.
async function installSystemdUserService(daemonEntry: string, paths: SignedInPaths): Promise<DaemonInstallResult> {
  const configRoot = process.env.XDG_CONFIG_HOME ?? path.join(homedir(), '.config');
  const file = path.join(configRoot, 'systemd', 'user', 'signed-in.service');
  const environmentLines = Object.entries(daemonEnvironment(paths))
    .map(([name, value]) => `Environment=${escapeSystemd(`${name}=${value}`)}`).join('\n');
  const unit = `[Unit]
Description=signed-in credential gateway
After=network-online.target

[Service]
Type=simple
ExecStart=${escapeSystemd(process.execPath)} ${escapeSystemd(daemonEntry)}
${environmentLines}
Restart=on-failure
RestartSec=2
UMask=0077

[Install]
WantedBy=default.target
`;
  const hadPreviousDefinition = existsSync(file);
  const rollback = installFileAtomically(file, unit);
  try {
    try { execFileSync('systemctl', ['--user', 'stop', 'signed-in.service'], { stdio: 'ignore' }); } catch { /* A first install has no loaded unit. */ }
    await stopLiveDaemon(paths);
    execFileSync('systemctl', ['--user', 'daemon-reload'], { stdio: 'ignore' });
    execFileSync('systemctl', ['--user', 'enable', '--now', 'signed-in.service'], { stdio: 'ignore' });
    await verifyManagedDaemon(paths);
    return { file, manager: 'systemd' };
  } catch (error) {
    let rollbackError: unknown;
    try {
      try { execFileSync('systemctl', ['--user', 'disable', '--now', 'signed-in.service'], { stdio: 'ignore' }); } catch { /* A failed candidate may never have loaded. */ }
      rollback();
      execFileSync('systemctl', ['--user', 'daemon-reload'], { stdio: 'ignore' });
      if (hadPreviousDefinition) execFileSync('systemctl', ['--user', 'enable', '--now', 'signed-in.service'], { stdio: 'ignore' });
    } catch (recoveryError) { rollbackError = recoveryError; }
    throw installError('systemd', file, error, rollbackError);
  }
}

// Stops an on-demand daemon and waits for the socket to disappear so KeepAlive cannot race the old owner.
async function stopLiveDaemon(paths: SignedInPaths): Promise<void> {
  try {
    await callDaemon(paths, 'daemon.shutdown', {}, { firstFrameTimeoutMs: 1_000 }).result;
  } catch (error) {
    if (!(error instanceof SignedInClientError) || !['DAEMON_DISCONNECTED', 'DAEMON_UNAVAILABLE'].includes(error.code)) throw error;
  }
  const deadline = Date.now() + 3_000;
  while (Date.now() < deadline) {
    try {
      await callDaemon(paths, 'ping', {}, { firstFrameTimeoutMs: 250 }).result;
    } catch (error) {
      if (error instanceof SignedInClientError && error.code === 'DAEMON_UNAVAILABLE') return;
      throw error;
    }
    await delay(50);
  }
  throw new SignedInClientError('DAEMON_STOP_TIMEOUT', 'The existing signed-in daemon did not stop before service installation');
}

// Verifies that the service manager launched the exact build just installed instead of reporting configuration alone as success.
async function verifyManagedDaemon(paths: SignedInPaths): Promise<void> {
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    try {
      const ping = await callDaemon(paths, 'ping', {}, { firstFrameTimeoutMs: 500 }).result;
      if (typeof ping === 'object' && ping !== null && (ping as { build?: unknown }).build === signedInBuild) return;
    } catch {
      // The manager may still be between exec and socket bind; the bounded retry preserves its real failure below.
    }
    await delay(100);
  }
  throw new SignedInClientError('DAEMON_INSTALL_START_FAILED', 'The installed daemon service did not start the expected build', {
    logFile: paths.daemonLogFile,
  });
}

// Writes service definitions through a private same-directory temporary file and returns an exact rollback action.
function installFileAtomically(file: string, contents: string): () => void {
  mkdirSync(path.dirname(file), { mode: 0o700, recursive: true });
  const previous = existsSync(file) ? readFileSync(file) : undefined;
  const temporary = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${randomUUID()}.tmp`);
  try {
    writeFileSync(temporary, contents, { mode: 0o600 });
    renameSync(temporary, file);
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
  return () => {
    if (previous) installFileAtomically(file, previous.toString('utf8'));
    else if (existsSync(file)) unlinkSync(file);
  };
}

// Preserves the interactive client's executable discovery and exact private storage roots across login-manager startup.
function daemonEnvironment(paths: SignedInPaths): Record<string, string> {
  return {
    PATH: process.env.PATH ?? '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
    SIGNED_IN_CONFIG_HOME: paths.configDir,
    SIGNED_IN_DAEMONIZED: '1',
    SIGNED_IN_DATA_HOME: paths.dataDir,
    SIGNED_IN_RUNTIME_DIR: paths.runtimeDir,
  };
}

// Locates only the compiled daemon because startup managers cannot inherit a transient tsx loader reliably.
function locateInstalledDaemonEntry(): string {
  const directory = path.dirname(fileURLToPath(import.meta.url));
  const daemonEntry = path.join(directory, 'daemon-entry.js');
  if (!existsSync(daemonEntry)) throw new Error('Build signed-in before installing its persistent daemon service');
  return daemonEntry;
}

// Escapes user-controlled path punctuation before embedding it in an XML service file.
function escapeXml(value: string): string {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
}

// Quotes systemd arguments and escapes specifier punctuation before ExecStart or Environment tokenization.
function escapeSystemd(value: string): string {
  return `"${value.replaceAll('%', '%%').replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}

// Wraps manager failures with stable non-secret diagnostics while preserving the original cause text for local repair.
function installError(manager: DaemonInstallResult['manager'], file: string, error: unknown, rollbackError?: unknown): SignedInClientError {
  return new SignedInClientError('DAEMON_INSTALL_FAILED', `The ${manager} signed-in service could not be installed`, {
    file,
    reason: error instanceof Error ? error.message : String(error),
    ...(rollbackError ? { rollback: rollbackError instanceof Error ? rollbackError.message : String(rollbackError) } : {}),
  });
}

// Provides a bounded cooperative wait during service-manager lifecycle transitions.
function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
