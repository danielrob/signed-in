import { randomUUID } from 'node:crypto';
import { appendFileSync, chmodSync } from 'node:fs';

import { redactText } from './redact.js';
import type { AuditReceipt, Operation, PolicyDecision } from './types.js';

// Emits append-only, secret-free receipts that explain every use of delegated authority.
export class AuditLog {
  readonly #auditFile: string;

  // Pins one daemon instance to one private audit stream.
  constructor(auditFile: string) {
    this.#auditFile = auditFile;
  }

  // Records policy intent before a provider receives any request.
  start(operation: Operation, decision: PolicyDecision, secrets: Iterable<string> = []): AuditReceipt {
    const receipt: AuditReceipt = {
      ...(operation.args ? { args: operation.args.map((argument) => redactText(argument, secrets)) } : {}),
      ...(operation.cwd ? { cwd: operation.cwd } : {}),
      ...(operation.method ? { method: operation.method } : {}),
      ...(operation.path ? { path: redactText(operation.path, secrets) } : {}),
      ...(operation.providerId ? { providerId: operation.providerId } : {}),
      classification: decision.classification,
      decision: decision.effect,
      id: randomUUID(),
      interface: operation.interface,
      ...(operation.projectId ? { projectId: operation.projectId } : {}),
      reason: decision.reason,
      startedAt: new Date().toISOString(),
      status: 'started',
    };
    this.#append(receipt);
    return receipt;
  }

  // Completes a receipt with outcome metadata while deliberately omitting request and response bodies.
  complete(
    started: AuditReceipt,
    outcome: { errorCode?: string; exitCode?: number; status: 'completed' | 'failed' },
  ): AuditReceipt {
    const completedAt = new Date().toISOString();
    const receipt: AuditReceipt = {
      ...started,
      ...outcome,
      completedAt,
      durationMs: Date.parse(completedAt) - Date.parse(started.startedAt),
    };
    this.#append(receipt);
    return receipt;
  }

  // Keeps each receipt independently parseable and narrows file permissions after first creation.
  #append(receipt: AuditReceipt): void {
    appendFileSync(this.#auditFile, `${JSON.stringify(receipt)}\n`, { mode: 0o600 });
    chmodSync(this.#auditFile, 0o600);
  }
}
