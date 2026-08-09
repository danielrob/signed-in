import type { CredentialFieldConfig } from './types.js';

// Rejects obvious cross-service credential mistakes without ever including the supplied secret in validation output.
export function credentialValidationMessage(field: CredentialFieldConfig, value: string | undefined): string | undefined {
  if (!value) return 'This field is required.';
  if (!field.prefixes?.length || field.prefixes.some((prefix) => value.startsWith(prefix))) return undefined;
  const expected = field.prefixes.map((prefix) => `${prefix}…`).join(' or ');
  return `${field.label} should start with ${expected}`;
}
