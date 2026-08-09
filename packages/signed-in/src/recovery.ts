import { existsSync, unlinkSync } from 'node:fs';

import type { SignedInPaths } from './paths.js';
import { EncryptedVault, type SecretStore } from './secrets.js';

// Erases the exact local state surfaces without first decrypting records, keeping reset usable after vault corruption.
export function eraseLocalSignedInState(
  paths: SignedInPaths,
  store: SecretStore = new EncryptedVault(paths.vaultDir),
): void {
  store.reset();
  for (const file of [paths.auditFile, paths.stateFile, paths.daemonLogFile]) {
    if (existsSync(file)) unlinkSync(file);
  }
}
