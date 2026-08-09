import { createHash, createHmac } from 'node:crypto';

import type { AwsSigV4AuthConfig } from './types.js';

export interface AwsCredentialFields {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

const authorizationPattern = /^AWS4-HMAC-SHA256\s+Credential=[^/]+\/(\d{8})\/([^/]+)\/([^/]+)\/aws4_request,/u;

// Re-signs a dummy-authenticated AWS CLI request without exposing the real key material to the child.
export function resignAwsRequest(
  method: string,
  requestUrl: URL,
  headers: Record<string, string>,
  body: Buffer,
  credentials: AwsCredentialFields,
  fallbackScope?: { region: string; service: string },
): Record<string, string> {
  const existingAuthorization = getHeader(headers, 'authorization');
  const match = existingAuthorization ? authorizationPattern.exec(existingAuthorization) : undefined;
  const now = new Date();
  const dateStamp = match?.[1] ?? now.toISOString().slice(0, 10).replaceAll('-', '');
  const region = match?.[2] ?? fallbackScope?.region;
  const service = match?.[3] ?? fallbackScope?.service;
  if (!dateStamp || !region || !service) {
    throw new Error('AWS request needs a SigV4 scope; supply x-signed-in-aws-region and x-signed-in-aws-service');
  }
  const amzDate = getHeader(headers, 'x-amz-date') ?? now.toISOString().replace(/[:-]|\.\d{3}/gu, '');
  const payloadHash = getHeader(headers, 'x-amz-content-sha256') ?? sha256(body);
  const signedHeaders = selectSignedHeaders(headers, credentials.sessionToken !== undefined);
  const canonicalHeaders = signedHeaders
    .map((name) => `${name}:${normalizeHeaderValue(name === 'host' ? requestUrl.host : getHeader(headers, name) ?? '')}\n`)
    .join('');
  const signedHeaderNames = signedHeaders.join(';');
  const canonicalRequest = [
    method.toUpperCase(),
    canonicalUri(requestUrl.pathname, service),
    canonicalQuery(requestUrl),
    canonicalHeaders,
    signedHeaderNames,
    payloadHash,
  ].join('\n');
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256(Buffer.from(canonicalRequest, 'utf8')),
  ].join('\n');
  const signingKey = deriveSigningKey(credentials.secretAccessKey, dateStamp, region, service);
  const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex');
  const nextHeaders = { ...headers };
  setHeader(nextHeaders, 'host', requestUrl.host);
  setHeader(nextHeaders, 'x-amz-date', amzDate);
  if (credentials.sessionToken) setHeader(nextHeaders, 'x-amz-security-token', credentials.sessionToken);
  else deleteHeader(nextHeaders, 'x-amz-security-token');
  setHeader(
    nextHeaders,
    'authorization',
    `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaderNames}, Signature=${signature}`,
  );
  return nextHeaders;
}

// Converts a trusted auth declaration and stored field map into strongly named signing credentials.
export function resolveAwsCredentials(
  auth: AwsSigV4AuthConfig,
  fields: Record<string, string>,
): AwsCredentialFields {
  const accessKeyId = fields[auth.accessKeyField];
  const secretAccessKey = fields[auth.secretKeyField];
  const sessionToken = auth.sessionTokenField ? fields[auth.sessionTokenField] : undefined;
  if (!accessKeyId || !secretAccessKey) throw new Error('AWS credentials are incomplete');
  return { accessKeyId, secretAccessKey, ...(sessionToken ? { sessionToken } : {}) };
}

// Produces AWS's four-stage derived key without retaining extra copies beyond this request.
function deriveSigningKey(secret: string, date: string, region: string, service: string): Buffer {
  const dateKey = createHmac('sha256', `AWS4${secret}`).update(date).digest();
  const regionKey = createHmac('sha256', dateKey).update(region).digest();
  const serviceKey = createHmac('sha256', regionKey).update(service).digest();
  return createHmac('sha256', serviceKey).update('aws4_request').digest();
}

// Signs a conservative deterministic set of headers supported by every normal AWS API operation.
function selectSignedHeaders(headers: Record<string, string>, includeSessionToken: boolean): string[] {
  const names = new Set(['host', 'x-amz-date']);
  for (const name of Object.keys(headers).map((header) => header.toLowerCase())) {
    if (name === 'content-type' || name === 'content-md5' || name === 'x-amz-content-sha256') names.add(name);
  }
  if (includeSessionToken) names.add('x-amz-security-token');
  return [...names].sort();
}

// Preserves S3 object paths while applying AWS-compatible segment escaping elsewhere.
function canonicalUri(pathname: string, service: string): string {
  const source = pathname || '/';
  if (service === 's3') return normalizePercentEncoding(source);
  return source.split('/').map((segment) => encodeRfc3986(safeDecode(segment))).join('/') || '/';
}

// Sorts encoded duplicate query parameters exactly as required by SigV4.
function canonicalQuery(url: URL): string {
  const pairs: Array<[string, string]> = [];
  url.searchParams.forEach((value, key) => pairs.push([encodeRfc3986(key), encodeRfc3986(value)]));
  return pairs
    .sort(([leftKey, leftValue], [rightKey, rightValue]) => leftKey.localeCompare(rightKey) || leftValue.localeCompare(rightValue))
    .map(([key, value]) => `${key}=${value}`)
    .join('&');
}

// Uses uppercase RFC 3986 escapes instead of the looser form encoding used by URLSearchParams.
function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/gu, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

// Avoids double-encoding an already canonical path segment when URL parsing preserved escapes.
function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

// Normalizes percent escape casing without changing slash or repeated-slash semantics for S3.
function normalizePercentEncoding(value: string): string {
  return value.replace(/%[0-9a-f]{2}/giu, (escape) => escape.toUpperCase());
}

// Collapses HTTP whitespace in the same way AWS canonical header construction does.
function normalizeHeaderValue(value: string): string {
  return value.trim().replace(/\s+/gu, ' ');
}

// Computes lowercase SHA-256 hex for payloads and canonical requests.
function sha256(value: Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

// Finds header values case-insensitively because Node preserves caller casing.
function getHeader(headers: Record<string, string>, name: string): string | undefined {
  const key = Object.keys(headers).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
  return key ? headers[key] : undefined;
}

// Replaces a header without leaving a differently-cased duplicate behind.
function setHeader(headers: Record<string, string>, name: string, value: string): void {
  deleteHeader(headers, name);
  headers[name] = value;
}

// Removes every casing of a sensitive header before forwarding.
function deleteHeader(headers: Record<string, string>, name: string): void {
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === name.toLowerCase()) delete headers[key];
  }
}
