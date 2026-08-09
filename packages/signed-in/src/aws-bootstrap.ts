import { normalizeAlias } from './aliases.js';
import type { CredentialRecord } from './types.js';

const administratorPolicyArn = 'arn:aws:iam::aws:policy/AdministratorAccess';
const principalUserName = 'signed-in';

interface AwsAccessKey {
  AccessKeyId?: string;
  SecretAccessKey?: string;
  Status?: string;
  UserName?: string;
}

interface AwsIdentity {
  Account?: string;
  Arn?: string;
  UserId?: string;
}

export interface AwsBootstrapResult {
  alias: string;
  credentials: CredentialRecord;
  identity: string;
  userName: string;
}

/**
 * Converts AWS's expiring browser proof into one connection credential that signed-in may share.
 * The injected runner is daemon-private, so neither IAM responses nor the one-time secret cross IPC.
 */
export async function bootstrapAwsCredentials(options: {
  browserCredentials: CredentialRecord;
  previousCredentials?: CredentialRecord;
  run: (args: string[], credentials: CredentialRecord) => Promise<unknown>;
  wait?: (milliseconds: number) => Promise<void>;
}): Promise<AwsBootstrapResult> {
  const browserIdentity = parseIdentity(await options.run(identityArgs(), options.browserCredentials));
  const accountId = requireAccountId(browserIdentity);
  const alias = await resolveAwsAccountAlias(options.run, options.browserCredentials, accountId);
  const target = awsConnectionTarget(accountId);
  if (options.previousCredentials && await credentialsResolveToTarget(options.run, options.previousCredentials, target.arn)) {
    return buildResult(accountId, alias, target.userName, target.arn, options.previousCredentials);
  }

  await ensureAwsUser(options.run, options.browserCredentials, target.userName);
  await options.run([
    'iam', 'attach-user-policy', '--user-name', target.userName, '--policy-arn', administratorPolicyArn,
  ], options.browserCredentials);

  const keys = parseAccessKeyList(await options.run([
    'iam', 'list-access-keys', '--user-name', target.userName, '--output', 'json', '--no-cli-pager',
  ], options.browserCredentials));
  const inactiveKeys = keys.filter((key) => key.Status === 'Inactive' && key.AccessKeyId);
  for (const key of inactiveKeys) {
    await options.run([
      'iam', 'delete-access-key', '--user-name', target.userName, '--access-key-id', key.AccessKeyId!,
    ], options.browserCredentials);
  }
  const occupiedKeys = keys.filter((key) => !inactiveKeys.includes(key));
  if (occupiedKeys.length >= 2) {
    throw new Error(
      `AWS user ${target.userName} already has two active access keys. Share an existing signed-in connection from another machine or remove a stale key deliberately.`,
    );
  }

  const created = parseCreatedAccessKey(await options.run([
    'iam', 'create-access-key', '--user-name', target.userName, '--output', 'json', '--no-cli-pager',
  ], options.browserCredentials), target.userName);
  const credentials: CredentialRecord = {
    fields: { accessKeyId: created.AccessKeyId, secretAccessKey: created.SecretAccessKey },
    updatedAt: new Date().toISOString(),
  };
  await verifyAwsCredentials(options.run, options.wait ?? wait, credentials, target.arn);
  return buildResult(accountId, alias, target.userName, target.arn, credentials);
}

/** Keeps AWS identity requests deterministic and prevents the CLI from opening a pager. */
function identityArgs(): string[] {
  return ['sts', 'get-caller-identity', '--output', 'json', '--no-cli-pager'];
}

/** Prevents malformed or non-account AWS responses from becoming IAM names or aliases. */
function requireAccountId(identity: AwsIdentity): string {
  if (!identity.Account || !/^\d{12}$/u.test(identity.Account)) throw new Error('AWS browser login did not resolve a 12-digit account ID');
  return identity.Account;
}

/** Binds one AWS account connection to the generic principal that can be shared between machines. */
function awsConnectionTarget(accountId: string): { arn: string; userName: string } {
  return { arn: `arn:aws:iam::${accountId}:user/${principalUserName}`, userName: principalUserName };
}

/** Derives a human route from provider-owned metadata without teaching core about any account. */
async function resolveAwsAccountAlias(
  run: (args: string[], credentials: CredentialRecord) => Promise<unknown>,
  credentials: CredentialRecord,
  accountId: string,
): Promise<string> {
  try {
    const result = await run(['iam', 'list-account-aliases', '--output', 'json', '--no-cli-pager'], credentials);
    const aliases = typeof result === 'object' && result !== null
      ? (result as { AccountAliases?: unknown }).AccountAliases
      : undefined;
    if (Array.isArray(aliases)) {
      const alias = aliases.find((value): value is string => typeof value === 'string' && Boolean(normalizeAlias(value)));
      if (alias) return normalizeAlias(alias)!;
    }
  } catch {
    // Account aliases are optional metadata and must never block durable credential bootstrap.
  }
  return `account-${accountId.slice(-6)}`;
}

/** Reuses an already sealed permanent key instead of consuming another IAM key slot on reconnect. */
async function credentialsResolveToTarget(
  run: (args: string[], credentials: CredentialRecord) => Promise<unknown>,
  credentials: CredentialRecord,
  targetArn: string,
): Promise<boolean> {
  if (!credentials.fields.accessKeyId || !credentials.fields.secretAccessKey || credentials.fields.sessionToken) return false;
  try {
    return parseIdentity(await run(identityArgs(), credentials)).Arn === targetArn;
  } catch {
    return false;
  }
}

/** Creates the generic connection principal only when the AWS account does not already contain it. */
async function ensureAwsUser(
  run: (args: string[], credentials: CredentialRecord) => Promise<unknown>,
  credentials: CredentialRecord,
  userName: string,
): Promise<void> {
  try {
    await run(['iam', 'get-user', '--user-name', userName, '--output', 'json', '--no-cli-pager'], credentials);
  } catch {
    await run(['iam', 'create-user', '--user-name', userName, '--output', 'json', '--no-cli-pager'], credentials);
  }
}

/** Treats AWS's key-list response as untrusted provider data before rotation decisions. */
function parseAccessKeyList(value: unknown): AwsAccessKey[] {
  if (typeof value !== 'object' || value === null || !Array.isArray((value as { AccessKeyMetadata?: unknown }).AccessKeyMetadata)) {
    throw new Error('AWS returned an invalid access-key list');
  }
  return (value as { AccessKeyMetadata: AwsAccessKey[] }).AccessKeyMetadata;
}

/** Rejects incomplete one-time key responses before their only secret copy can be discarded. */
function parseCreatedAccessKey(value: unknown, userName: string): { AccessKeyId: string; SecretAccessKey: string } {
  const key = typeof value === 'object' && value !== null ? (value as { AccessKey?: AwsAccessKey }).AccessKey : undefined;
  if (!key?.AccessKeyId || !key.SecretAccessKey || (key.UserName && key.UserName !== userName)) {
    throw new Error(`AWS did not return a complete access key for ${userName}`);
  }
  return { AccessKeyId: key.AccessKeyId, SecretAccessKey: key.SecretAccessKey };
}

/** Normalizes the safe caller identity fields used for account and user verification. */
function parseIdentity(value: unknown): AwsIdentity {
  if (typeof value !== 'object' || value === null) throw new Error('AWS returned an invalid caller identity');
  const identity = value as AwsIdentity;
  return {
    ...(typeof identity.Account === 'string' ? { Account: identity.Account } : {}),
    ...(typeof identity.Arn === 'string' ? { Arn: identity.Arn } : {}),
    ...(typeof identity.UserId === 'string' ? { UserId: identity.UserId } : {}),
  };
}

/** Gives a newly created IAM key a bounded propagation window before login is declared failed. */
async function verifyAwsCredentials(
  run: (args: string[], credentials: CredentialRecord) => Promise<unknown>,
  waitFor: (milliseconds: number) => Promise<void>,
  credentials: CredentialRecord,
  targetArn: string,
): Promise<void> {
  for (let attempt = 1; attempt <= 6; attempt += 1) {
    if (await credentialsResolveToTarget(run, credentials, targetArn)) return;
    if (attempt < 6) await waitFor(2_000);
  }
  throw new Error(`AWS created the access key, but it did not resolve to ${targetArn}`);
}

/** Produces the non-secret identity shown in status alongside the encrypted credential record. */
function buildResult(accountId: string, alias: string, userName: string, arn: string, credentials: CredentialRecord): AwsBootstrapResult {
  return { alias, credentials, identity: `${alias} · ${accountId} · ${arn}`, userName };
}

/** Avoids blocking the daemon while AWS propagates a newly created access key. */
function wait(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
