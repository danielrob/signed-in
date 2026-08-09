const personalEmailDomains = new Set([
  'fastmail.com',
  'gmail.com',
  'googlemail.com',
  'hey.com',
  'hotmail.com',
  'icloud.com',
  'live.com',
  'me.com',
  'outlook.com',
  'pm.me',
  'proton.me',
  'protonmail.com',
  'yahoo.com',
]);

const countrySecondLevelSuffixes = new Set(['ac', 'co', 'com', 'edu', 'gov', 'net', 'org']);
const reservedDerivedAliases = new Set(['all', 'default', 'list', 'new', 'none']);

/*
 * Connection aliases keep login-first onboarding identifiable without making a mutable label the
 * authority boundary. The daemon owns allocation; the CLI reuses normalization for prompt feedback.
 */

export type AliasSource = 'domain' | 'fallback' | 'identity' | 'operator';

/** Describes the visible alias and how confidently signed-in was able to choose it. */
export interface DerivedAlias {
  alias: string;
  source: AliasSource;
}

/**
 * Gives a connection a useful human route from provider identity while keeping collisions explicit.
 */
export function deriveConnectionAlias(identity: string | undefined, fallback: string, taken: Iterable<string>): DerivedAlias {
  const occupied = new Set([...taken].map((alias) => alias.toLowerCase()));
  const domain = identity ? identityDomain(identity) : undefined;
  if (domain) {
    const base = personalEmailDomains.has(domain) ? 'personal' : registrableDomainLabel(domain);
    if (base) return { alias: allocateAlias(base, occupied), source: 'domain' };
  }
  const identityAlias = identity ? normalizeAlias(identityAliasCandidate(identity)) : undefined;
  if (identityAlias) return { alias: allocateAlias(identityAlias, occupied), source: 'identity' };
  return { alias: allocateAlias(normalizeAlias(fallback) ?? 'primary', occupied), source: 'fallback' };
}

/**
 * Validates operator vocabulary once so aliases remain safe in commands, configs, and completion.
 */
export function normalizeAlias(value: string): string | undefined {
  const normalized = value.normalize('NFKD').toLowerCase()
    .replace(/[\u0300-\u036f]/gu, '')
    .replace(/[^a-z0-9]+/gu, '-')
    .replace(/^-+|-+$/gu, '')
    .slice(0, 32)
    .replace(/-+$/u, '');
  return /^[a-z0-9][a-z0-9-]{0,31}$/u.test(normalized) ? normalized : undefined;
}

/**
 * Preserves a meaningful base alias and adds the smallest readable suffix when it already exists.
 */
export function allocateAlias(base: string, taken: Iterable<string>): string {
  const occupied = new Set([...taken].map((alias) => alias.toLowerCase()));
  for (const alias of reservedDerivedAliases) occupied.add(alias);
  if (!occupied.has(base)) return base;
  let suffix = 2;
  while (true) {
    const ending = `-${suffix}`;
    const candidate = `${base.slice(0, 32 - ending.length)}${ending}`;
    if (!occupied.has(candidate)) return candidate;
    suffix += 1;
  }
}

/**
 * Finds email, URL, or hostname evidence without mistaking arbitrary provider labels for domains.
 */
function identityDomain(identity: string): string | undefined {
  const email = identity.match(/(?:^|\s|<)[^\s@<>]+@([a-z0-9.-]+\.[a-z]{2,})(?:>|\s|$)/iu)?.[1];
  if (email) return normalizeHostname(email);
  try {
    const url = new URL(identity.includes('://') ? identity : `https://${identity}`);
    if (url.hostname.includes('.')) return normalizeHostname(url.hostname);
  } catch {
    return undefined;
  }
  return undefined;
}

/**
 * Reduces common country-code suffixes such as co.nz and com.au to the organisation label.
 */
function registrableDomainLabel(hostname: string): string | undefined {
  const labels = hostname.split('.').filter(Boolean);
  if (labels.length < 2) return undefined;
  const countrySuffix = labels.at(-1)?.length === 2 && countrySecondLevelSuffixes.has(labels.at(-2) ?? '');
  return normalizeAlias(labels.at(countrySuffix ? -3 : -2) ?? '');
}

/**
 * Keeps provider usernames readable while preventing long numeric account identifiers from looking accidental.
 */
function identityAliasCandidate(identity: string): string {
  const compact = identity.trim().replace(/\s+/gu, '-');
  if (/^\d{6,}$/u.test(compact)) return `account-${compact.slice(-6)}`;
  return compact;
}

/**
 * Canonicalizes only DNS-safe identity evidence before the personal-domain and suffix rules run.
 */
function normalizeHostname(hostname: string): string {
  return hostname.toLowerCase().replace(/^www\./u, '').replace(/\.$/u, '');
}
