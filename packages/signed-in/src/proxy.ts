import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import http, { type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from 'node:http';
import https from 'node:https';
import { type Socket } from 'node:net';
import tls from 'node:tls';

import forge from 'node-forge';

import { authenticateHeaders } from './http-auth.js';
import { redactStructured, redactText } from './redact.js';
import type { HttpGatewayConfig } from './types.js';

export interface CredentialProxyOptions {
  credentials: Record<string, string>;
  gateway: HttpGatewayConfig;
  onRequest?: (request: { method: string; path: string }) => void;
  secrets: string[];
  upstreamCa?: string;
}

export interface CredentialProxy {
  caCertificate: string;
  close: () => Promise<void>;
  url: string;
}

export interface CredentialSocketProxy {
  close: () => Promise<void>;
  socketPath: string;
}

interface CertificateAuthority {
  caCertificate: string;
  caCertificateForge: forge.pki.Certificate;
  caPrivateKey: forge.pki.rsa.PrivateKey;
  expiresAt: number;
  leafPrivateKey: forge.pki.rsa.PrivateKey;
  leafPrivateKeyPem: string;
}

const maximumInspectableResponseBytes = 10 * 1024 * 1024;
const maximumRequestBytes = 256 * 1024 * 1024;
let cachedAuthority: CertificateAuthority | undefined;

// Starts a loopback-only MITM proxy that substitutes real authentication after the child has sent dummy credentials.
export async function startCredentialProxy(options: CredentialProxyOptions): Promise<CredentialProxy> {
  const authority = daemonCertificateAuthority();
  const certificateCache = new Map<string, tls.SecureContext>();
  const innerServer = http.createServer((request, response) => {
    void forwardInterceptedRequest(request, response, options).catch((error) => {
      sendProxyError(response, error, options.secrets);
    });
  });
  const proxyServer = http.createServer((request, response) => {
    void forwardAbsoluteRequest(request, response, options).catch((error) => {
      sendProxyError(response, error, options.secrets);
    });
  });
  proxyServer.on('connect', (request, clientSocket, head) => {
    handleConnect(request, clientSocket as Socket, head, innerServer, authority, certificateCache, options);
  });
  await listen(proxyServer);
  const address = proxyServer.address();
  if (!address || typeof address === 'string') throw new Error('Credential proxy did not receive a TCP address');
  return {
    caCertificate: authority.caCertificate,
    close: async () => closeServer(proxyServer, innerServer),
    url: `http://127.0.0.1:${address.port}`,
  };
}

// Gives compatible native CLIs a private HTTP transport that avoids platform-specific custom-CA behavior.
export async function startCredentialSocketProxy(
  options: CredentialProxyOptions,
  socketPath: string,
): Promise<CredentialSocketProxy> {
  const server = http.createServer((request, response) => {
    void forwardInterceptedRequest(request, response, options).catch((error) => {
      sendProxyError(response, error, options.secrets);
    });
  });
  await listenSocket(server, socketPath);
  return {
    close: async () => closeOne(server),
    socketPath,
  };
}

// Reuses an in-memory daemon-lifetime CA so routine native commands do not pay for RSA generation every time.
function daemonCertificateAuthority(): CertificateAuthority {
  if (!cachedAuthority || cachedAuthority.expiresAt < Date.now() + 60 * 60 * 1000) {
    cachedAuthority = createCertificateAuthority();
  }
  return cachedAuthority;
}

// Intercepts only configured provider hosts and tunnels explicitly allowed auxiliary egress without credentials.
function handleConnect(
  request: IncomingMessage,
  clientSocket: Socket,
  head: Buffer,
  innerServer: http.Server,
  authority: CertificateAuthority,
  certificateCache: Map<string, tls.SecureContext>,
  options: CredentialProxyOptions,
): void {
  const host = parseConnectHost(request.url ?? '');
  if (!host) {
    clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    return;
  }
  if (isAuthenticatedHost(host, options.gateway) || isCredentialFreeEgressHost(host, options.gateway)) {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: SignedIn\r\n\r\n');
    if (head.length > 0) clientSocket.unshift(head);
    const secureContext = certificateCache.get(host) ?? createLeafContext(host, authority);
    certificateCache.set(host, secureContext);
    const tlsSocket = new tls.TLSSocket(clientSocket, { isServer: true, secureContext });
    innerServer.emit('connection', tlsSocket);
    return;
  }
  clientSocket.end('HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nBlocked undeclared egress.\n');
}

// Handles decrypted HTTPS requests using the original Host header as the authenticated destination.
async function forwardInterceptedRequest(
  request: IncomingMessage,
  response: ServerResponse,
  options: CredentialProxyOptions,
): Promise<void> {
  const host = headerValue(request.headers.host);
  if (!host) throw new Error('Provider request did not include a Host header');
  const url = new URL(request.url ?? '/', `https://${host}`);
  if (!isAuthenticatedHost(url.hostname, options.gateway) && !isCredentialFreeEgressHost(url.hostname, options.gateway)) {
    throw new Error(`Blocked provider host: ${url.hostname}`);
  }
  await forwardProviderRequest(request, response, url, options);
}

// Supports clients that send absolute-form HTTP requests instead of CONNECT tunnels.
async function forwardAbsoluteRequest(
  request: IncomingMessage,
  response: ServerResponse,
  options: CredentialProxyOptions,
): Promise<void> {
  const url = new URL(request.url ?? '');
  if (!isAuthenticatedHost(url.hostname, options.gateway) && !isCredentialFreeEgressHost(url.hostname, options.gateway)) {
    throw new Error(`Blocked provider host: ${url.hostname}`);
  }
  await forwardProviderRequest(request, response, url, options);
}

// Applies policy, authentication, safe forwarding, and response redaction as one indivisible gateway operation.
async function forwardProviderRequest(
  request: IncomingMessage,
  response: ServerResponse,
  url: URL,
  options: CredentialProxyOptions,
): Promise<void> {
  const method = request.method ?? 'GET';
  const body = await readRequestBody(request, maximumRequestBytes);
  const authenticated = isAuthenticatedHost(url.hostname, options.gateway);
  if (authenticated) options.onRequest?.({ method, path: `${url.pathname}${url.search}` });
  const headers = authenticated
    ? authenticateHeaders(
        options.gateway.auth,
        options.credentials,
        method,
        url,
        normalizeHeaders(request.headers),
        body,
      )
    : stripEgressAuthentication(normalizeHeaders(request.headers));
  delete headers['proxy-connection'];
  delete headers.connection;
  headers.host = url.host;
  headers['accept-encoding'] = 'identity';
  const upstream = await performUpstreamRequest(url, method, headers, body, options.upstreamCa);
  const safeResponse = sanitizeUpstreamResponse(upstream, options.secrets);
  response.writeHead(upstream.statusCode, safeResponse.headers);
  response.end(safeResponse.body);
}

// Performs the actual provider request with redirects disabled so credentials cannot cross origins.
function performUpstreamRequest(
  url: URL,
  method: string,
  headers: Record<string, string>,
  body: Buffer,
  upstreamCa?: string,
): Promise<{ body: Buffer; headers: IncomingHttpHeaders; statusCode: number }> {
  return new Promise((resolve, reject) => {
    const upstream = https.request(url, { ...(upstreamCa ? { ca: upstreamCa } : {}), headers, method }, (providerResponse) => {
      const chunks: Buffer[] = [];
      let total = 0;
      providerResponse.on('data', (chunk: Buffer) => {
        total += chunk.length;
        if (total > maximumRequestBytes) {
          providerResponse.destroy(new Error('Provider response exceeded the proxy limit'));
          return;
        }
        chunks.push(chunk);
      });
      providerResponse.on('end', () => resolve({
        body: Buffer.concat(chunks),
        headers: providerResponse.headers,
        statusCode: providerResponse.statusCode ?? 502,
      }));
      providerResponse.on('error', reject);
    });
    upstream.on('error', reject);
    if (body.length > 0) upstream.write(body);
    upstream.end();
  });
}

// Redacts newly issued secret-shaped JSON and exact known credentials before a provider CLI can print them.
function sanitizeUpstreamResponse(
  upstream: { body: Buffer; headers: IncomingHttpHeaders },
  secrets: string[],
): { body: Buffer; headers: Record<string, string | string[]> } {
  const headers = normalizeResponseHeaders(upstream.headers);
  const contentType = headerValue(upstream.headers['content-type']) ?? '';
  for (const name of ['authentication-info', 'proxy-authenticate', 'set-cookie', 'www-authenticate']) delete headers[name];
  if (upstream.body.length > maximumInspectableResponseBytes && isInspectableContentType(contentType)) {
    throw new Error('Provider text response exceeded the safe redaction limit');
  }
  let body = upstream.body;
  if (/json/iu.test(contentType)) {
    try {
      body = Buffer.from(JSON.stringify(redactStructured(JSON.parse(body.toString('utf8')), secrets)), 'utf8');
    } catch {
      body = Buffer.from(redactText(body.toString('utf8'), secrets), 'utf8');
    }
  } else if (/^(?:text\/|application\/(?:xml|x-www-form-urlencoded))/iu.test(contentType)) {
    body = Buffer.from(redactText(body.toString('utf8'), secrets), 'utf8');
  }
  for (const name of ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']) {
    delete headers[name];
  }
  const safeHeaders = Object.fromEntries(Object.entries(headers).map(([name, value]) => [
    name,
    Array.isArray(value)
      ? value.map((item) => redactText(item, secrets))
      : redactText(value, secrets),
  ]));
  safeHeaders['content-length'] = String(body.length);
  return { body, headers: safeHeaders };
}

// Identifies formats that must be fully inspected before any bytes can return to a provider CLI.
function isInspectableContentType(contentType: string): boolean {
  return /^(?:text\/|application\/(?:graphql|json|problem\+json|xml|x-www-form-urlencoded))/iu.test(contentType);
}

// Creates an in-memory CA whose public certificate alone is shared with the child process.
function createCertificateAuthority(): CertificateAuthority {
  const caKeys = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
    publicKeyEncoding: { format: 'pem', type: 'spki' },
  });
  const leafKeys = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
    publicKeyEncoding: { format: 'pem', type: 'spki' },
  });
  const caCertificate = forge.pki.createCertificate();
  caCertificate.publicKey = forge.pki.publicKeyFromPem(caKeys.publicKey);
  caCertificate.serialNumber = positiveCertificateSerial();
  caCertificate.validity.notBefore = new Date(Date.now() - 60_000);
  caCertificate.validity.notAfter = new Date(Date.now() + 24 * 60 * 60 * 1000);
  const attributes = [{ name: 'commonName', value: `SignedIn Ephemeral CA ${randomUUID()}` }];
  caCertificate.setSubject(attributes);
  caCertificate.setIssuer(attributes);
  caCertificate.setExtensions([
    { cA: true, critical: true, name: 'basicConstraints' },
    { keyCertSign: true, name: 'keyUsage' },
  ]);
  const caPrivateKey = forge.pki.privateKeyFromPem(caKeys.privateKey) as forge.pki.rsa.PrivateKey;
  caCertificate.sign(caPrivateKey, forge.md.sha256.create());
  return {
    caCertificate: forge.pki.certificateToPem(caCertificate),
    caCertificateForge: caCertificate,
    caPrivateKey,
    expiresAt: caCertificate.validity.notAfter.getTime(),
    leafPrivateKey: forge.pki.privateKeyFromPem(leafKeys.privateKey) as forge.pki.rsa.PrivateKey,
    leafPrivateKeyPem: leafKeys.privateKey,
  };
}

// Issues a short-lived leaf certificate only for the exact provider hostname requested by the child.
function createLeafContext(host: string, authority: CertificateAuthority): tls.SecureContext {
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = forge.pki.setRsaPublicKey(authority.leafPrivateKey.n, authority.leafPrivateKey.e);
  certificate.serialNumber = positiveCertificateSerial();
  certificate.validity.notBefore = new Date(Date.now() - 60_000);
  certificate.validity.notAfter = new Date(Date.now() + 60 * 60 * 1000);
  certificate.setSubject([{ name: 'commonName', value: host }]);
  certificate.setIssuer(authority.caCertificateForge.subject.attributes);
  certificate.setExtensions([
    { cA: false, critical: true, name: 'basicConstraints' },
    { digitalSignature: true, keyEncipherment: true, name: 'keyUsage' },
    { name: 'extKeyUsage', serverAuth: true },
    { altNames: [{ type: 2, value: host }], name: 'subjectAltName' },
  ]);
  certificate.sign(authority.caPrivateKey, forge.md.sha256.create());
  return tls.createSecureContext({
    ca: authority.caCertificate,
    cert: forge.pki.certificateToPem(certificate),
    key: authority.leafPrivateKeyPem,
  });
}

// Clears ASN.1's sign bit so strict X.509 clients such as Go never reject an ephemeral certificate as a negative serial.
function positiveCertificateSerial(): string {
  const serial = randomBytes(16);
  serial[0] = (serial[0] ?? 0) & 0x7f;
  if (serial.every((byte) => byte === 0)) serial[serial.length - 1] = 1;
  return serial.toString('hex');
}

// Reads request bodies with an explicit ceiling so a child cannot exhaust daemon memory accidentally.
function readRequestBody(request: IncomingMessage, limit: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    request.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > limit) {
        reject(new Error(`Provider request exceeded the ${limit}-byte proxy limit`));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

// Restricts credential injection to the configured base host and trusted aliases.
function isAuthenticatedHost(host: string, gateway: HttpGatewayConfig): boolean {
  const allowed = [new URL(gateway.baseUrl).hostname, ...(gateway.allowHosts ?? [])];
  return allowed.some((pattern) => hostMatches(host, pattern));
}

// Recognizes explicitly declared auxiliary destinations that may receive normal data but never authentication.
function isCredentialFreeEgressHost(host: string, gateway: HttpGatewayConfig): boolean {
  return (gateway.egressHosts ?? []).some((pattern) => hostMatches(host, pattern));
}

// Removes every common credential carrier before forwarding to an auxiliary egress origin.
function stripEgressAuthentication(headers: Record<string, string>): Record<string, string> {
  const forbidden = /^(?:authorization|cookie|proxy-authorization|x-amz-security-token|x-api-key|x-auth-token|x-goog-api-key)$/iu;
  return Object.fromEntries(Object.entries(headers).filter(([name]) => !forbidden.test(name)));
}

// Supports exact hosts and one-or-more-label wildcard suffixes without arbitrary regular expressions.
function hostMatches(host: string, pattern: string): boolean {
  const normalizedHost = host.toLowerCase();
  const normalizedPattern = pattern.toLowerCase();
  if (normalizedPattern.startsWith('*.')) {
    const suffix = normalizedPattern.slice(1);
    return normalizedHost.endsWith(suffix) && normalizedHost.length > suffix.length;
  }
  return normalizedHost === normalizedPattern;
}

// Parses a CONNECT authority without letting malformed host text enter certificate generation.
function parseConnectHost(authority: string): string {
  try {
    const parsed = new URL(`https://${authority}`);
    return parsed.hostname;
  } catch {
    return '';
  }
}

// Converts Node's multi-value request headers into a single deterministic upstream form.
function normalizeHeaders(headers: IncomingHttpHeaders): Record<string, string> {
  return Object.fromEntries(Object.entries(headers).flatMap(([name, value]) => {
    if (value === undefined) return [];
    return [[name.toLowerCase(), Array.isArray(value) ? value.join(', ') : value]];
  }));
}

// Preserves safe multi-value response headers while dropping ambiguous undefined entries.
function normalizeResponseHeaders(headers: IncomingHttpHeaders): Record<string, string | string[]> {
  return Object.fromEntries(Object.entries(headers).filter((entry): entry is [string, string | string[]] => entry[1] !== undefined));
}

// Normalizes Node's string-or-array header values for host and content-type checks.
function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

// Turns proxy failures into a stable child-visible response without exposing internal stack traces.
function sendProxyError(response: ServerResponse, error: unknown, secrets: string[]): void {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  const message = redactText(error instanceof Error ? error.message : String(error), secrets);
  response.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
  response.end(`signed-in gateway blocked the request: ${message}\n`);
}

// Waits for a loopback listener without exposing a partially initialized proxy to callers.
function listen(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
}

// Waits for an owner-private Unix listener before a CLI is allowed to read its generated config.
function listenSocket(server: http.Server, socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.off('error', reject);
      resolve();
    });
  });
}

// Closes both listener layers so the command-specific proxy port cannot outlive its child process.
async function closeServer(proxyServer: http.Server, innerServer: http.Server): Promise<void> {
  await Promise.all([closeOne(proxyServer), closeOne(innerServer)]);
}

// Handles already-closed inner HTTP servers without hanging command cleanup.
function closeOne(server: http.Server): Promise<void> {
  if (!server.listening) return Promise.resolve();
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
