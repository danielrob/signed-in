const sensitiveKeyPattern = /(access.?key|api.?key|authorization|client.?secret|credential|password|private.?key|refresh.?token|secret|session.?token|token)/iu;

const heuristicTokenPatterns = [
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/gu,
  /\bgh[oprsu]_[A-Za-z0-9]{20,}\b/gu,
  /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/gu,
  /\bsk-[A-Za-z0-9_-]{20,}\b/gu,
  /\bAKIA[A-Z0-9]{16}\b/gu,
  /\b(?:eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/gu,
];

const secretAssignmentPattern = /((?:["']?(?:access.?key|api.?key|authorization|client.?secret|credential|password|private.?key|refresh.?token|secret|session.?token|token)["']?\s*[:=]\s*["']?))([^\s,"'<>]{4,})/giu;
const secretXmlPattern = /(<(?:AccessKeyId|SecretAccessKey|SessionToken|Token|Password|PrivateKey)>)([^<]{4,})(<\/[^>]+>)/giu;
const privateKeyBlockPattern = /-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----/gu;
const githubDevicePromptPattern = /(?:Open this URL to continue in your web browser: https:\/\/github\.com\/login\/device|Press Enter to open https:\/\/github\.com\/login\/device in your browser\.\.\.)\s*$/u;

// Redacts exact secrets across arbitrary stream chunk boundaries before a byte reaches the caller.
export class StreamRedactor {
  readonly #secrets: string[];
  readonly #tailLength: number;
  #buffer = '';

  // Sorts longer secrets first so overlapping values cannot leave a revealing suffix.
  constructor(secrets: Iterable<string>) {
    this.#secrets = [...new Set([...secrets].filter((secret) => secret.length >= 4))]
      .sort((left, right) => right.length - left.length);
    this.#tailLength = Math.max(0, ...this.#secrets.map((secret) => secret.length - 1), 96);
  }

  // Retains a small suffix until the next chunk so split tokens are replaced as one value.
  push(chunk: string): string {
    this.#buffer += chunk;
    if (this.#buffer.length <= this.#tailLength) return '';
    const safeLength = this.#buffer.length - this.#tailLength;
    const masked = maskTextPreservingLength(this.#buffer, this.#secrets);
    const output = masked.slice(0, safeLength);
    this.#buffer = masked.slice(safeLength);
    return output;
  }

  // Releases prompts, or opted-in complete login lines, so redaction buffering cannot deadlock a browser flow.
  flushPrompt(completeLoginLines = false): string {
    if (!/[:?>]\s*$/u.test(this.#buffer) && !githubDevicePromptPattern.test(this.#buffer)
      && !(completeLoginLines && /\r?\n\s*$/u.test(this.#buffer))) return '';
    const redacted = redactText(this.#buffer, this.#secrets);
    if (redacted !== this.#buffer) return '';
    this.#buffer = '';
    return redacted;
  }

  // Flushes the final suffix once no future chunk can complete a secret prefix.
  finish(): string {
    const output = redactText(this.#buffer, this.#secrets);
    this.#buffer = '';
    return output;
  }
}

// Applies exact-value and high-confidence format redaction to non-streaming output.
export function redactText(value: string, secrets: Iterable<string> = []): string {
  let redacted = value;
  for (const secret of secrets) {
    if (secret.length < 4) continue;
    redacted = redacted.split(secret).join('[REDACTED]');
  }
  for (const pattern of heuristicTokenPatterns) redacted = redacted.replace(pattern, '[REDACTED]');
  redacted = redacted.replace(secretAssignmentPattern, '$1[REDACTED]');
  redacted = redacted.replace(secretXmlPattern, '$1[REDACTED]$3');
  redacted = redacted.replace(privateKeyBlockPattern, '[REDACTED PRIVATE KEY]');
  return redacted;
}

// Removes secret-shaped JSON fields recursively while preserving enough structure for agents to use responses.
export function redactStructured(value: unknown, secrets: Iterable<string> = []): unknown {
  if (Array.isArray(value)) return value.map((item) => redactStructured(item, secrets));
  if (isRecord(value)) {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [
      key,
      sensitiveKeyPattern.test(key) ? '[REDACTED]' : redactStructured(item, secrets),
    ]));
  }
  if (typeof value === 'string') return redactText(value, secrets);
  return value;
}

// Collects likely tokens from session files so native output can redact values the provider owns internally.
export function collectSensitiveStrings(value: unknown, keyHint = ''): string[] {
  if (Array.isArray(value)) return value.flatMap((item) => collectSensitiveStrings(item, keyHint));
  if (isRecord(value)) {
    return Object.entries(value).flatMap(([key, item]) => collectSensitiveStrings(item, key));
  }
  if (typeof value === 'string' && (sensitiveKeyPattern.test(keyHint) || looksLikeToken(value))) return [value];
  return [];
}

// Limits heuristic redaction to long, compact values to avoid blanking ordinary prose and identifiers.
function looksLikeToken(value: string): boolean {
  return value.length >= 20 && value.length <= 4096 && !/\s{2,}/u.test(value) && /^[\x21-\x7e]+$/u.test(value);
}

// Masks complete secret matches without changing length so stream boundaries cannot reveal a split suffix.
function maskTextPreservingLength(value: string, secrets: Iterable<string>): string {
  let masked = value;
  for (const secret of secrets) {
    if (secret.length < 4) continue;
    masked = masked.split(secret).join('█'.repeat(secret.length));
  }
  for (const pattern of heuristicTokenPatterns) {
    masked = masked.replace(pattern, (match) => '█'.repeat(match.length));
  }
  masked = masked.replace(secretAssignmentPattern, (match, prefix: string) => `${prefix}${'█'.repeat(match.length - prefix.length)}`);
  masked = masked.replace(secretXmlPattern, (match, prefix: string, secret: string, suffix: string) => `${prefix}${'█'.repeat(secret.length)}${suffix}`);
  return masked;
}

// Narrows recursive JSON traversal without importing a schema library into the trusted core.
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
