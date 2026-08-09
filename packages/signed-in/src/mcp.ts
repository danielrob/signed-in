import process from 'node:process';

import { callDaemon, SignedInClientError } from './client.js';
import type { SignedInPaths } from './paths.js';

interface JsonRpcRequest {
  id?: number | string;
  method: string;
  params?: Record<string, unknown>;
}

// Exposes signed-in's existing daemon policy boundary as optional MCP tools without making MCP the credential architecture.
export async function runMcpServer(paths: SignedInPaths, projectId?: string): Promise<void> {
  process.stdin.setEncoding('utf8');
  let buffer = '';
  for await (const chunk of process.stdin) {
    buffer += chunk;
    while (buffer.includes('\n')) {
      const newline = buffer.indexOf('\n');
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (!line) continue;
      let decoded: unknown;
      try { decoded = JSON.parse(line) as unknown; }
      catch {
        writeRpc({ error: { code: -32700, message: 'Parse error' }, id: null, jsonrpc: '2.0' });
        continue;
      }
      if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded) || typeof (decoded as { method?: unknown }).method !== 'string') {
        writeRpc({ error: { code: -32600, message: 'Invalid Request' }, id: requestId(decoded), jsonrpc: '2.0' });
        continue;
      }
      const request = decoded as JsonRpcRequest;
      if (request.id === undefined) continue;
      try {
        const result = await handleMcpRequest(paths, projectId, request);
        writeRpc({ id: request.id, jsonrpc: '2.0', result });
      } catch (error) {
        writeRpc({
          error: { code: -32000, message: error instanceof Error ? error.message : String(error) },
          id: request.id,
          jsonrpc: '2.0',
        });
      }
    }
  }
}

// Implements only initialization and three capability-shaped tools backed by the same daemon methods as the CLI.
async function handleMcpRequest(paths: SignedInPaths, projectId: string | undefined, request: JsonRpcRequest): Promise<unknown> {
  if (request.method === 'initialize') {
    return {
      capabilities: { tools: { listChanged: false } },
      protocolVersion: '2025-11-25',
      serverInfo: { name: 'signed-in', version: '0.1.0' },
    };
  }
  if (request.method === 'ping') return {};
  if (request.method === 'tools/list') return { tools: mcpTools() };
  if (request.method === 'tools/call') {
    const name = requireString(request.params?.name, 'tool name');
    const input = requireRecord(request.params?.arguments ?? {}, 'tool arguments');
    try { return await callMcpTool(paths, projectId, name, input); }
    catch (error) { return toolError(error); }
  }
  throw new Error(`Unsupported MCP method '${request.method}'`);
}

// Routes MCP calls to operation-shaped daemon methods and captures only already-redacted native output.
async function callMcpTool(
  paths: SignedInPaths,
  projectId: string | undefined,
  name: string,
  input: Record<string, unknown>,
): Promise<unknown> {
  if (name === 'signed_in_status') {
    const result = await callDaemon(paths, 'service.status', { ...(projectId ? { projectId } : {}) }).result;
    return toolText(JSON.stringify(result, null, 2));
  }
  if (name === 'signed_in_request') {
    const target = parseServiceTarget(requireString(input.provider, 'provider'));
    const result = await callDaemon(paths, 'http.request', {
      ...(target.account ? { account: target.account } : {}),
      body: typeof input.body === 'string' ? Buffer.from(input.body, 'utf8').toString('base64') : '',
      bodyEncoding: 'base64',
      headers: requireOptionalStringRecord(input.headers),
      method: requireString(input.method, 'method'),
      path: requireString(input.path, 'path'),
      ...(projectId ? { projectId } : {}),
      providerId: target.service,
    }).result;
    return toolText(JSON.stringify(result, null, 2));
  }
  if (name === 'signed_in_run') {
    const target = parseServiceTarget(requireString(input.provider, 'provider'));
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    const invocation = callDaemon(paths, 'provider.run', {
      args: requireStringArray(input.args, 'args'),
      cwd: typeof input.cwd === 'string' ? input.cwd : process.cwd(),
      ...(target.account ? { account: target.account } : {}),
      ...(projectId ? { projectId } : {}),
      providerId: target.service,
    }, {
      onStderr: (chunk) => stderr.push(chunk),
      onStdout: (chunk) => stdout.push(chunk),
    });
    const result = await invocation.result;
    return toolText(JSON.stringify({
      result,
      stderr: Buffer.concat(stderr).toString('utf8'),
      stdout: Buffer.concat(stdout).toString('utf8'),
    }, null, 2));
  }
  throw new Error(`Unknown signed-in MCP tool '${name}'`);
}

// Declares a deliberately small MCP surface while the CLI remains the richer primary interface.
function mcpTools(): unknown[] {
  return [
    {
      description: 'List configured providers and whether their CLI/API surfaces are ready. Never returns credentials.',
      inputSchema: { additionalProperties: false, properties: {}, type: 'object' },
      name: 'signed_in_status',
    },
    {
      description: 'Call an allowlisted provider API endpoint with daemon-side authentication and policy.',
      inputSchema: {
        additionalProperties: false,
        properties: {
          body: { type: 'string' },
          headers: { additionalProperties: { type: 'string' }, type: 'object' },
          method: { type: 'string' },
          path: { type: 'string' },
          provider: { type: 'string' },
        },
        required: ['provider', 'method', 'path'],
        type: 'object',
      },
      name: 'signed_in_request',
    },
    {
      description: 'Run one sealed provider CLI with isolated auth, policy, output redaction, and an audit receipt.',
      inputSchema: {
        additionalProperties: false,
        properties: {
          args: { items: { type: 'string' }, type: 'array' },
          cwd: { type: 'string' },
          provider: { type: 'string' },
        },
        required: ['provider', 'args'],
        type: 'object',
      },
      name: 'signed_in_run',
    },
  ];
}

// Formats a normal MCP text response without introducing provider-specific content types.
function toolText(text: string): { content: Array<{ text: string; type: 'text' }> } {
  return { content: [{ text, type: 'text' }] };
}

// Preserves daemon error codes and remedies inside MCP tool failures so agents can recover without guessing.
function toolError(error: unknown): { content: Array<{ text: string; type: 'text' }>; isError: true; structuredContent: { error: Record<string, unknown> } } {
  const details = error instanceof SignedInClientError && typeof error.details === 'object' && error.details !== null
    ? error.details as Record<string, unknown>
    : {};
  const rendered = {
    code: error instanceof SignedInClientError ? error.code : 'SIGNED_IN_ERROR',
    ...details,
    message: error instanceof Error ? error.message : String(error),
  };
  return {
    content: [{ text: JSON.stringify({ error: rendered }, null, 2), type: 'text' }],
    isError: true,
    structuredContent: { error: rendered },
  };
}

// Echoes only a scalar request id for protocol-level errors and otherwise uses JSON-RPC's null id.
function requestId(value: unknown): number | string | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const id = (value as { id?: unknown }).id;
  return typeof id === 'number' || typeof id === 'string' ? id : null;
}

// Writes one newline-framed JSON-RPC message compatible with MCP stdio transports.
function writeRpc(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

// Narrows MCP arguments before they enter daemon parameter construction.
function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

// Rejects missing MCP string inputs with a useful tool error.
function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value === '') throw new Error(`${label} must be a string`);
  return value;
}

// Validates native argv without accepting objects that could stringify unexpectedly.
function requireStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) throw new Error(`${label} must be an array of strings`);
  return value;
}

// Accepts optional safe HTTP header maps while leaving auth headers for the daemon to reject.
function requireOptionalStringRecord(value: unknown): Record<string, string> | undefined {
  if (value === undefined) return undefined;
  const record = requireRecord(value, 'headers');
  if (!Object.values(record).every((item) => typeof item === 'string')) throw new Error('headers must contain only strings');
  return record as Record<string, string>;
}

// Splits the uniform service@alias grammar without interpreting any vendor argument.
function parseServiceTarget(value: string): { account?: string; service: string } {
  const separator = value.indexOf('@');
  if (separator < 0) return { service: value };
  const service = value.slice(0, separator);
  const account = value.slice(separator + 1);
  if (!service || !account) throw new Error('provider must be service or service@alias');
  return { account, service };
}
