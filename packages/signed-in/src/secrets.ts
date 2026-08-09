import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { Entry } from '@napi-rs/keyring';

const keyringService = 'signed-in';
const keyringAccount = 'vault-master-v1';

interface EncryptedRecord {
  algorithm: 'aes-256-gcm';
  authTag: string;
  ciphertext: string;
  iv: string;
  version: 1;
}

export interface SecretStore {
  delete(key: string): void;
  get<T>(key: string): T | undefined;
  has(key: string): boolean;
  reset(): void;
  set<T>(key: string, value: T): void;
}

// Stores only one random wrapping key in the OS keychain and keeps every expandable payload encrypted on disk.
export class EncryptedVault implements SecretStore {
  readonly #keyringEntry: Entry;
  readonly #vaultDir: string;
  #masterKey?: Buffer;

  // Binds the vault to one private data directory while allowing an injectable keychain identity in tests.
  constructor(vaultDir: string, service = keyringService, account = keyringAccount) {
    this.#vaultDir = vaultDir;
    this.#keyringEntry = new Entry(service, account);
  }

  // Decrypts a record only inside the daemon and authenticates its logical key as associated data.
  get<T>(key: string): T | undefined {
    const recordPath = this.#recordPath(key);
    if (!existsSync(recordPath)) return undefined;
    const record = JSON.parse(readFileSync(recordPath, 'utf8')) as EncryptedRecord;
    if (record.version !== 1 || record.algorithm !== 'aes-256-gcm') {
      throw new Error(`Unsupported encrypted vault record: ${path.basename(recordPath)}`);
    }
    const decipher = createDecipheriv('aes-256-gcm', this.#loadMasterKey(), Buffer.from(record.iv, 'base64'));
    decipher.setAAD(Buffer.from(key, 'utf8'));
    decipher.setAuthTag(Buffer.from(record.authTag, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(record.ciphertext, 'base64')),
      decipher.final(),
    ]);
    try {
      return JSON.parse(plaintext.toString('utf8')) as T;
    } finally {
      plaintext.fill(0);
    }
  }

  // Encrypts complete credential or session records before they cross the daemon's memory boundary.
  set<T>(key: string, value: T): void {
    const plaintext = Buffer.from(JSON.stringify(value), 'utf8');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.#loadMasterKey(), iv);
    cipher.setAAD(Buffer.from(key, 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const record: EncryptedRecord = {
      algorithm: 'aes-256-gcm',
      authTag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      version: 1,
    };
    const recordPath = this.#recordPath(key);
    const temporaryPath = `${recordPath}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
    try {
      writeFileSync(temporaryPath, `${JSON.stringify(record)}\n`, { mode: 0o600 });
      renameSync(temporaryPath, recordPath);
    } finally {
      plaintext.fill(0);
      ciphertext.fill(0);
      if (existsSync(temporaryPath)) unlinkSync(temporaryPath);
    }
  }

  // Removes a sealed record without ever decoding it into the caller.
  delete(key: string): void {
    const recordPath = this.#recordPath(key);
    if (existsSync(recordPath)) unlinkSync(recordPath);
  }

  // Answers readiness checks without forcing callers to handle decryption failures as absence.
  has(key: string): boolean {
    return existsSync(this.#recordPath(key));
  }

  // Erases every encrypted record and the wrapping key only after interactive reset confirmation.
  reset(): void {
    for (const entry of readdirSync(this.#vaultDir, { withFileTypes: true })) {
      if (entry.isFile()) unlinkSync(path.join(this.#vaultDir, entry.name));
    }
    if (this.#keyringEntry.getPassword()) this.#keyringEntry.deletePassword();
    this.#masterKey?.fill(0);
    this.#masterKey = undefined;
  }

  // Resolves an opaque filename so provider and project names never become path traversal input.
  #recordPath(key: string): string {
    const digest = createHash('sha256').update(key).digest('hex');
    return path.join(this.#vaultDir, `${digest}.vault`);
  }

  // Creates the wrapping key exactly once and never falls back to a plaintext local key.
  #loadMasterKey(): Buffer {
    if (this.#masterKey) return this.#masterKey;
    const existing = this.#keyringEntry.getPassword();
    if (existing) {
      const decoded = Buffer.from(existing, 'base64');
      if (decoded.length !== 32) throw new Error('signed-in keychain entry has an invalid master key');
      this.#masterKey = decoded;
      return decoded;
    }
    const generated = randomBytes(32);
    this.#keyringEntry.setPassword(generated.toString('base64'));
    this.#masterKey = generated;
    return generated;
  }
}

// Provides a non-persistent store so policy, pairing, and service tests never touch a developer keychain.
export class MemorySecretStore implements SecretStore {
  readonly #records = new Map<string, string>();

  // Returns a fresh JSON value to prevent tests from mutating the store by reference.
  get<T>(key: string): T | undefined {
    const serialized = this.#records.get(key);
    return serialized === undefined ? undefined : JSON.parse(serialized) as T;
  }

  // Mirrors encrypted-vault serialization semantics for realistic tests.
  set<T>(key: string, value: T): void {
    this.#records.set(key, JSON.stringify(value));
  }

  // Supports logout and replacement behavior without filesystem side effects.
  delete(key: string): void {
    this.#records.delete(key);
  }

  // Lets status checks avoid unnecessarily loading secret material.
  has(key: string): boolean {
    return this.#records.has(key);
  }

  // Mirrors a complete vault reset so recovery behavior can be verified without touching a real keychain.
  reset(): void {
    this.#records.clear();
  }
}

// Preserves the v1 key shape solely so daemon-side migration can re-key existing credentials safely.
export function credentialStoreKey(projectId: string, providerId: string): string {
  return `project/${projectId}/provider/${providerId}/credentials`;
}

// Preserves the v1 session key shape until every registered project has migrated to machine connections.
export function sessionStoreKey(projectId: string, providerId: string): string {
  return `project/${projectId}/provider/${providerId}/session`;
}

// Preserves alias-keyed v1 credentials solely for lossless connection migration.
export function accountCredentialStoreKey(serviceId: string, account: string): string {
  return `service/${serviceId}/account/${account}/credentials`;
}

// Preserves alias-keyed v1 sessions solely for lossless connection migration.
export function accountSessionStoreKey(serviceId: string, account: string): string {
  return `service/${serviceId}/account/${account}/session`;
}

// Makes credential storage independent from the human alias used to route to a connection.
export function connectionCredentialStoreKey(serviceId: string, connectionId: string): string {
  return `service/${serviceId}/connection/${connectionId}/credentials`;
}

// Keeps refreshable sessions stable when a human renames their connection alias.
export function connectionSessionStoreKey(serviceId: string, connectionId: string): string {
  return `service/${serviceId}/connection/${connectionId}/session`;
}

// Makes connection enumeration possible without making encrypted record filenames or secret values discoverable.
export function machineAccountsStoreKey(): string {
  return 'machine/accounts';
}

// Makes an interrupted alias-to-connection migration resumable without retaining plaintext state.
export function connectionMigrationStoreKey(): string {
  return 'machine/connections-migration-v2';
}

// Pins a provider executable once per machine rather than once per project snapshot.
export function binaryPinStoreKey(serviceId: string): string {
  return `machine/service/${serviceId}/binary`;
}

// Journals v1 re-keying before source deletion so interrupted migrations resume without guessing.
export function migrationStoreKey(): string {
  return 'machine/migration/v1-to-v2';
}

// Seals reviewed declarations where repo edits cannot change runtime behavior.
export function trustedProjectStoreKey(projectId: string): string {
  return `project/${projectId}/trusted-config`;
}

// Gives pairing keys their own lifecycle independent of any vendor credential.
export function machineIdentityStoreKey(): string {
  return 'machine/identity/private';
}
