import { createPrivateKey, sign } from 'node:crypto';

import type { AppleConnectJwtAuthConfig, HttpAuthConfig } from './types.js';
import { resignAwsRequest, resolveAwsCredentials } from './aws-sigv4.js';

// Injects provider authentication only after a request has crossed into daemon-owned memory.
export function authenticateHeaders(
  auth: HttpAuthConfig,
  fields: Record<string, string>,
  method: string,
  url: URL,
  inputHeaders: Record<string, string>,
  body: Buffer,
): Record<string, string> {
  const headers = stripCallerAuthentication(inputHeaders);
  if (auth.type === 'none') return headers;
  if (auth.type === 'bearer') {
    setHeader(headers, 'authorization', `Bearer ${requireField(fields, auth.field)}`);
    return headers;
  }
  if (auth.type === 'header') {
    setHeader(headers, auth.header, `${auth.prefix ?? ''}${requireField(fields, auth.field)}`);
    return headers;
  }
  if (auth.type === 'basic') {
    const password = auth.password === 'empty'
      ? ''
      : requireField(fields, requireBasicPasswordField(auth.passwordField));
    const encoded = Buffer.from(
      `${requireField(fields, auth.usernameField)}:${password}`,
      'utf8',
    ).toString('base64');
    setHeader(headers, 'authorization', `Basic ${encoded}`);
    return headers;
  }
  if (auth.type === 'apple-connect-jwt') {
    setHeader(headers, 'authorization', `Bearer ${createAppleConnectJwt(auth, fields)}`);
    return headers;
  }
  const existingAuthorization = getHeader(inputHeaders, 'authorization');
  const region = getHeader(inputHeaders, 'x-signed-in-aws-region') ?? auth.defaultRegion;
  const service = getHeader(inputHeaders, 'x-signed-in-aws-service') ?? auth.defaultService;
  return resignAwsRequest(
    method,
    url,
    { ...headers, ...(existingAuthorization ? { authorization: existingAuthorization } : {}) },
    body,
    resolveAwsCredentials(auth, fields),
    region && service ? { region, service } : undefined,
  );
}

// Creates believable placeholders so provider CLIs follow their normal authenticated code paths without real secrets.
export function dummyCredentialEnvironment(
  auth: HttpAuthConfig,
  credentialFields: Array<{ env?: string; id: string }>,
  nonce: string,
): Record<string, string> {
  const fieldValues = new Map<string, string>();
  if (auth.type === 'aws-sigv4') {
    fieldValues.set(auth.accessKeyField, `AKIA${nonce.replace(/[^A-Z0-9]/giu, '').toUpperCase().padEnd(16, 'A').slice(0, 16)}`);
    fieldValues.set(auth.secretKeyField, `signed-in-dummy-secret-${nonce}`);
    if (auth.sessionTokenField) fieldValues.set(auth.sessionTokenField, `signed-in-dummy-session-${nonce}`);
  } else if (auth.type === 'bearer' || auth.type === 'header') {
    fieldValues.set(auth.field, `signed_in_dummy_${nonce}`);
  } else if (auth.type === 'basic') {
    fieldValues.set(auth.usernameField, 'signed-in');
    if (auth.passwordField) fieldValues.set(auth.passwordField, `signed_in_dummy_${nonce}`);
  }
  return Object.fromEntries(credentialFields.flatMap((field) => {
    const value = fieldValues.get(field.id);
    return field.env && value ? [[field.env, value]] : [];
  }));
}

// Rejects an incomplete Basic-auth declaration before it can construct an ambiguous header.
function requireBasicPasswordField(field: string | undefined): string {
  if (!field) throw new Error('Basic authentication needs passwordField or password: empty');
  return field;
}

// Creates Apple's required short-lived ES256 token just in time so no reusable JWT is stored or exposed.
function createAppleConnectJwt(auth: AppleConnectJwtAuthConfig, fields: Record<string, string>): string {
  const issuedAt = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({
    alg: 'ES256',
    kid: requireField(fields, auth.keyIdField),
    typ: 'JWT',
  }), 'utf8').toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    aud: 'appstoreconnect-v1',
    exp: issuedAt + 19 * 60,
    iat: issuedAt,
    iss: requireField(fields, auth.issuerField),
  }), 'utf8').toString('base64url');
  const signingInput = `${header}.${payload}`;
  const signature = sign('sha256', Buffer.from(signingInput, 'utf8'), {
    dsaEncoding: 'ieee-p1363',
    key: createPrivateKey(requireField(fields, auth.privateKeyField)),
  });
  return `${signingInput}.${signature.toString('base64url')}`;
}

// Removes every caller-provided authentication spelling so it cannot override or leak through broker policy.
export function stripCallerAuthentication(headers: Record<string, string>): Record<string, string> {
  const forbidden = new Set([
    'authorization',
    'cookie',
    'proxy-authorization',
    'x-api-key',
    'x-auth-token',
    'x-goog-api-key',
    'x-signed-in-aws-region',
    'x-signed-in-aws-service',
  ]);
  return Object.fromEntries(Object.entries(headers).filter(([name]) => !forbidden.has(name.toLowerCase())));
}

// Reads headers case-insensitively before internal signing hints and dummy authentication are stripped.
function getHeader(headers: Record<string, string>, name: string): string | undefined {
  const key = Object.keys(headers).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
  return key ? headers[key] : undefined;
}

// Gives missing credentials a provider-field name without ever interpolating its value.
function requireField(fields: Record<string, string>, field: string): string {
  const value = fields[field];
  if (!value) throw new Error(`Missing credential field '${field}'`);
  return value;
}

// Replaces a header case-insensitively to prevent ambiguous duplicate authentication.
function setHeader(headers: Record<string, string>, name: string, value: string): void {
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === name.toLowerCase()) delete headers[key];
  }
  headers[name] = value;
}
