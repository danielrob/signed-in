import type {
  SignedInProjectConfig,
  Operation,
  OperationClass,
  PolicyDecision,
  PolicyEffect,
  PolicyRule,
  ProviderConfig,
} from './types.js';

const credentialPathPattern = /(?:^|[/_-])(?:api[-_]?keys?|access[-_]?keys?|auth(?:entication)?|credentials?|oauth|private[-_]?keys?|refresh[-_]?tokens?|service[-_]?account[-_]?keys?|tokens?)(?:$|[/_-])/iu;
const destructiveWords = new Set(['cancel', 'delete', 'destroy', 'disable', 'drop', 'logout', 'purge', 'remove', 'revoke', 'terminate']);
const mutatingWords = new Set(['add', 'apply', 'configure', 'create', 'deploy', 'edit', 'enable', 'import', 'invite', 'link', 'login', 'merge', 'promote', 'publish', 'push', 'release', 'rollback', 'set', 'update', 'upload']);
const forbiddenSecretFlags = /^(?:--?)(?:access[-_]?key|api[-_]?key|auth[-_]?token|client[-_]?secret|credential|password|private[-_]?key|secret[-_]?key|token)(?:=|$)/iu;

const hardDenyPatterns: string[][] = [
  ['auth', 'token'],
  ['configure', 'export-credentials'],
  ['create-access-key'],
  ['create-service-account-key'],
  ['service-accounts', 'keys', 'create'],
  ['api-keys', 'create'],
  ['credentials', 'create'],
  ['tokens', 'create'],
];

// Applies hard credential controls first, then the most restrictive matching trusted project rule.
export function evaluatePolicy(config: SignedInProjectConfig, operation: Operation): PolicyDecision {
  const provider = operation.providerId ? config.providers[operation.providerId] : undefined;
  const classification = classifyOperation(operation, provider);
  const hardDenial = evaluateHardDenial(operation, classification, provider);
  if (hardDenial) return hardDenial;

  const matchingRules = (config.policies ?? []).filter((rule) => matchesRule(rule, operation, classification));
  if (matchingRules.length > 0) {
    const winningEffect = mostRestrictive(matchingRules.map((rule) => rule.effect));
    const winners = matchingRules.filter((rule) => rule.effect === winningEffect);
    return {
      classification,
      effect: winningEffect,
      matchedRules: winners.map((rule) => rule.id),
      reason: winners.map((rule) => rule.reason).join('; '),
    };
  }

  return defaultDecision(classification);
}

// Explains operations consistently for both enforcement and `policy explain` UX.
export function classifyOperation(operation: Operation, provider?: ProviderConfig): OperationClass {
  if (operation.interface === 'control') return classifyControlOperation(operation.path ?? '');
  if (operation.interface === 'http') return classifyHttpOperation(operation.method ?? 'GET', operation.path ?? '/');
  return classifyNativeOperation(operation.args ?? [], provider);
}

// Treats credential administration as categorically unavailable through the agent-facing gateway.
function evaluateHardDenial(
  operation: Operation,
  classification: OperationClass,
  provider?: ProviderConfig,
): PolicyDecision | undefined {
  if (classification === 'credential-control' && operation.interface !== 'control') {
    return {
      classification,
      effect: 'deny',
      matchedRules: ['signed-in:credential-boundary'],
      reason: 'Credential creation, extraction, and replacement are outside the agent capability boundary.',
    };
  }
  if (operation.interface === 'native') {
    const args = operation.args ?? [];
    if (args.some((argument) => forbiddenSecretFlags.test(argument))) {
      return {
        classification: 'credential-control',
        effect: 'deny',
        matchedRules: ['signed-in:secret-argument'],
        reason: 'Secrets may not be supplied to provider CLIs through command-line arguments.',
      };
    }
    const deniedPatterns = [...hardDenyPatterns, ...(provider?.policy?.denyCliPatterns ?? [])];
    if (deniedPatterns.some((pattern) => containsSequence(args, pattern))) {
      return {
        classification: 'credential-control',
        effect: 'deny',
        matchedRules: ['signed-in:credential-command'],
        reason: 'This provider command can reveal or mint authentication material.',
      };
    }
  }
  return undefined;
}

// Separates human-only vault controls from harmless status and explanation calls.
function classifyControlOperation(action: string): OperationClass {
  if (/^(?:credential\.|pair\.(?:export|import)|project\.trust|vault\.)/u.test(action)) return 'credential-control';
  if (/^(?:daemon\.shutdown|provider\.logout)/u.test(action)) return 'destructive';
  if (/^(?:machine\.|project\.|provider\.login)/u.test(action)) return 'mutation';
  return 'read';
}

// Uses both method and route semantics because credential endpoints are dangerous even when read-only.
function classifyHttpOperation(method: string, requestPath: string): OperationClass {
  const upperMethod = method.toUpperCase();
  const pathname = safePathname(requestPath);
  if (credentialPathPattern.test(pathname)) return 'credential-control';
  if (upperMethod === 'DELETE') return 'destructive';
  if (['GET', 'HEAD', 'OPTIONS'].includes(upperMethod)) return 'read';
  return 'mutation';
}

// Maps provider verbs and trusted overrides to a conservative native command class.
function classifyNativeOperation(args: string[], provider?: ProviderConfig): OperationClass {
  if (hardDenyPatterns.some((pattern) => containsSequence(args, pattern))) return 'credential-control';
  if ((provider?.policy?.denyCliPatterns ?? []).some((pattern) => containsSequence(args, pattern))) {
    return 'credential-control';
  }
  if ((provider?.policy?.destructiveCliPatterns ?? []).some((pattern) => containsSequence(args, pattern))) {
    return 'destructive';
  }
  if ((provider?.policy?.mutatingCliPatterns ?? []).some((pattern) => containsSequence(args, pattern))) {
    return 'mutation';
  }
  const normalized = args.map(normalizeWord);
  const semanticWords = normalized.flatMap((word) => [word, ...word.split(/[-.:/]/u)]);
  if (semanticWords.some((word) => destructiveWords.has(word))) return 'destructive';
  if (semanticWords.some((word) => mutatingWords.has(word))) return 'mutation';
  return 'read';
}

// Makes trusted policy rules composable across provider, environment, route, and command scopes.
function matchesRule(rule: PolicyRule, operation: Operation, classification: OperationClass): boolean {
  if (rule.interfaces && !rule.interfaces.includes(operation.interface)) return false;
  if (rule.providers && (!operation.providerId || !rule.providers.includes(operation.providerId))) return false;
  if (rule.environments && (!operation.environment || !rule.environments.includes(operation.environment))) return false;
  if (rule.operationClasses && !rule.operationClasses.includes(classification)) return false;
  if (rule.methods && (!operation.method || !rule.methods.includes(operation.method.toUpperCase()))) return false;
  if (rule.pathPattern && !globMatches(operation.path ?? '', rule.pathPattern)) return false;
  if (rule.commandPattern && !containsSequence(operation.args ?? [], rule.commandPattern)) return false;
  return true;
}

// Defaults to frictionless reads, auditable writes, and deliberate confirmation for destructive work.
function defaultDecision(classification: OperationClass): PolicyDecision {
  if (classification === 'credential-control') {
    return {
      classification,
      effect: 'deny',
      matchedRules: ['signed-in:default-credential-deny'],
      reason: 'Credential-control operations are denied by default.',
    };
  }
  if (classification === 'destructive') {
    return {
      classification,
      effect: 'confirm',
      matchedRules: ['signed-in:default-destructive-confirm'],
      reason: 'Destructive operations require an explicit confirmation.',
    };
  }
  return {
    classification,
    effect: 'allow',
    matchedRules: ['signed-in:default-allow'],
    reason: classification === 'read' ? 'Read operations are allowed.' : 'Ordinary mutations are allowed.',
  };
}

// Resolves overlapping policies in the direction that can never broaden access accidentally.
function mostRestrictive(effects: PolicyEffect[]): PolicyEffect {
  if (effects.includes('deny')) return 'deny';
  if (effects.includes('confirm')) return 'confirm';
  return 'allow';
}

// Matches command tokens contiguously while ignoring cosmetic punctuation and case.
function containsSequence(args: string[], pattern: string[]): boolean {
  const normalizedArgs = args.map(normalizeWord);
  const normalizedPattern = pattern.map(normalizeWord);
  return normalizedArgs.some((_, index) => normalizedPattern.every((word, offset) => normalizedArgs[index + offset] === word));
}

// Normalizes CLI spellings such as `--create-access-key` without changing semantic words.
function normalizeWord(value: string): string {
  return value.toLowerCase().replace(/^--?/u, '').replace(/_/gu, '-').split('=')[0] ?? '';
}

// Converts the small trusted wildcard language into an anchored regular expression.
function globMatches(value: string, pattern: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/gu, '\\$&').replace(/\*/gu, '.*');
  return new RegExp(`^${escaped}$`, 'u').test(value);
}

// Extracts a pathname without letting malformed input crash policy evaluation.
function safePathname(value: string): string {
  try {
    const pathname = new URL(value, 'https://signed-in.invalid').pathname;
    try {
      return decodeURIComponent(pathname);
    } catch {
      return pathname;
    }
  } catch {
    return value;
  }
}
