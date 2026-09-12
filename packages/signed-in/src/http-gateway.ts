import { authenticateHeaders } from './http-auth.js';
import { redactStructured, redactText } from './redact.js';
import type { HttpGatewayConfig } from './types.js';

export interface GatewayResponse {
  body: string;
  bodyEncoding: 'base64' | 'utf8';
  headers: Record<string, string>;
  status: number;
  url: string;
}

const maximumResponseBytes = 32 * 1024 * 1024;
const maximumRequestBytes = 32 * 1024 * 1024;
const maximumCanonicalRedirects = 3;

// Performs an allowlisted authenticated API request without returning any credential-bearing headers or JSON fields.
export async function performGatewayRequest(options: {
  body: Buffer;
  credentials: Record<string, string>;
  gateway: HttpGatewayConfig;
  headers: Record<string, string>;
  method: string;
  path: string;
  secrets: string[];
  signal?: AbortSignal;
}): Promise<GatewayResponse> {
  if (options.body.length > maximumRequestBytes) {
    throw new Error(`Provider request exceeded ${maximumRequestBytes} bytes`);
  }
  let url = resolveGatewayUrl(options.gateway, options.path);
  const signal = options.signal
    ? AbortSignal.any([options.signal, AbortSignal.timeout(120_000)])
    : AbortSignal.timeout(120_000);
  let response: Response;
  for (let redirectCount = 0; ; redirectCount += 1) {
    const headers = authenticateHeaders(
      options.gateway.auth,
      options.credentials,
      options.method,
      url,
      mergeHeaders(options.gateway.defaultHeaders ?? {}, options.headers),
      options.body,
    );
    response = await fetch(url, {
      body: bodyAllowed(options.method) && options.body.length > 0 ? new Uint8Array(options.body) : undefined,
      headers,
      method: options.method,
      redirect: 'manual',
      signal,
    });
    let redirectUrl: URL | undefined;
    try {
      redirectUrl = canonicalRedirectUrl(options.gateway, options.method, url, response);
    } catch (error) {
      await response.body?.cancel();
      throw error;
    }
    if (!redirectUrl) break;
    if (redirectCount >= maximumCanonicalRedirects) {
      await response.body?.cancel();
      throw new Error(`Provider exceeded ${maximumCanonicalRedirects} canonical redirects`);
    }
    await response.body?.cancel();
    url = redirectUrl;
  }
  const responseBuffer = await readLimitedResponse(response, maximumResponseBytes);
  const contentType = response.headers.get('content-type') ?? '';
  const textual = isTextual(contentType);
  const body = textual
    ? redactResponseText(responseBuffer.toString('utf8'), contentType, options.secrets)
    : responseBuffer.toString('base64');
  return {
    body,
    bodyEncoding: textual ? 'utf8' : 'base64',
    headers: safeResponseHeaders(response.headers, options.secrets),
    status: response.status,
    url: response.url,
  };
}

// Lets caller headers override adapter defaults without emitting duplicate case variants that providers parse ambiguously.
function mergeHeaders(defaults: Record<string, string>, overrides: Record<string, string>): Record<string, string> {
  const merged = { ...defaults };
  for (const [name, value] of Object.entries(overrides)) {
    for (const existing of Object.keys(merged)) {
      if (existing.toLowerCase() === name.toLowerCase()) delete merged[existing];
    }
    merged[name] = value;
  }
  return merged;
}

// Follows only same-endpoint slash normalization so redirects cannot evade path policy or carry authority elsewhere.
function canonicalRedirectUrl(gateway: HttpGatewayConfig, method: string, current: URL, response: Response): URL | undefined {
  if (![301, 302, 307, 308].includes(response.status)) return undefined;
  const location = response.headers.get('location');
  if (!location) return undefined;
  if (![307, 308].includes(response.status) && !['GET', 'HEAD'].includes(method.toUpperCase())) {
    throw new Error(`Provider returned an unsafe ${response.status} redirect for ${method.toUpperCase()}`);
  }
  const redirected = resolveGatewayUrl(gateway, new URL(location, current).href);
  const currentPath = current.pathname === '/' ? '/' : current.pathname.replace(/\/+$/u, '');
  const redirectedPath = redirected.pathname === '/' ? '/' : redirected.pathname.replace(/\/+$/u, '');
  if (redirected.origin !== current.origin || redirectedPath !== currentPath || redirected.search !== current.search) {
    throw new Error('Provider redirected outside the approved canonical endpoint');
  }
  return redirected;
}

// Resolves relative API paths under one base URL and rejects credential smuggling or host changes.
export function resolveGatewayUrl(gateway: HttpGatewayConfig, requestPath: string): URL {
  const base = new URL(gateway.baseUrl);
  const url = new URL(requestPath, base.href.endsWith('/') ? base : new URL(`${base.href}/`));
  const allowedHosts = [base.hostname, ...(gateway.allowHosts ?? [])];
  if (!allowedHosts.some((pattern) => hostMatches(url.hostname, pattern))) {
    throw new Error(`Provider request host '${url.hostname}' is not allowlisted`);
  }
  if (url.username || url.password) throw new Error('Provider URLs may not contain credentials');
  if (url.protocol !== 'https:' && url.hostname !== '127.0.0.1' && url.hostname !== 'localhost') {
    throw new Error('Provider requests must use HTTPS');
  }
  return url;
}

// Avoids passing a body for methods where fetch rejects it or intermediaries handle it inconsistently.
function bodyAllowed(method: string): boolean {
  return !['GET', 'HEAD'].includes(method.toUpperCase());
}

// Reads responses with a fixed ceiling so an API cannot exhaust a long-running broker.
async function readLimitedResponse(response: Response, limit: number): Promise<Buffer> {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) {
      await reader.cancel('signed-in response limit exceeded');
      throw new Error(`Provider response exceeded ${limit} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

// Preserves normal JSON while replacing both known secrets and newly returned token-shaped fields.
function redactResponseText(value: string, contentType: string, secrets: string[]): string {
  if (/json/iu.test(contentType)) {
    try {
      return JSON.stringify(redactStructured(JSON.parse(value), secrets), null, 2);
    } catch {
      return redactText(value, secrets);
    }
  }
  return redactText(value, secrets);
}

// Omits cookies and authentication challenges that can themselves contain reusable session material.
function safeResponseHeaders(headers: Headers, secrets: string[]): Record<string, string> {
  const denied = new Set(['authentication-info', 'proxy-authenticate', 'set-cookie', 'www-authenticate']);
  const safe: Record<string, string> = {};
  headers.forEach((value, name) => {
    if (!denied.has(name.toLowerCase())) safe[name] = redactText(value, secrets);
  });
  return safe;
}

// Classifies text formats narrowly so arbitrary binary output is never decoded and corrupted.
function isTextual(contentType: string): boolean {
  return /^(?:text\/|application\/(?:graphql|json|[^;\s/]+\+json|xml|x-www-form-urlencoded))/iu.test(contentType);
}

// Supports exact and leading-wildcard aliases without admitting sibling domains.
function hostMatches(host: string, pattern: string): boolean {
  const normalizedHost = host.toLowerCase();
  const normalizedPattern = pattern.toLowerCase();
  if (normalizedPattern.startsWith('*.')) {
    const suffix = normalizedPattern.slice(1);
    return normalizedHost.endsWith(suffix) && normalizedHost.length > suffix.length;
  }
  return normalizedHost === normalizedPattern;
}
