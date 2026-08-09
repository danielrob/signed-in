import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  randomUUID,
  sign,
  verify,
} from 'node:crypto';
import { hostname } from 'node:os';

import type {
  MachineIdentityPrivate,
  MachineIdentityPublic,
  PairingEnvelope,
  PairingPayload,
} from './types.js';

const pairingInfo = Buffer.from('signed-in-pairing-envelope-v1', 'utf8');

// Creates separate non-exportable-in-practice encryption and signing identities for one machine vault.
export function createMachineIdentity(label = hostname()): MachineIdentityPrivate {
  const encryption = generateKeyPairSync('x25519');
  const signing = generateKeyPairSync('ed25519');
  const publicIdentity = buildPublicIdentity({
    encryptionPublicKey: encryption.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    id: randomUUID(),
    label,
    signingPublicKey: signing.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
  });
  return {
    ...publicIdentity,
    encryptionPrivateKey: encryption.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    signingPrivateKey: signing.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
  };
}

// Removes private material before a machine identity crosses IPC or appears in pairing metadata.
export function publicMachineIdentity(identity: MachineIdentityPrivate): MachineIdentityPublic {
  return {
    encryptionPublicKey: identity.encryptionPublicKey,
    fingerprint: identity.fingerprint,
    id: identity.id,
    label: identity.label,
    signingPublicKey: identity.signingPublicKey,
  };
}

// Encrypts portable credentials to the destination and signs the complete envelope for tamper evidence.
export function encryptPairingPayload(
  sender: MachineIdentityPrivate,
  recipient: MachineIdentityPublic,
  payload: PairingPayload,
  lifetimeMs = 10 * 60 * 1000,
): PairingEnvelope {
  validatePublicIdentity(recipient);
  const ephemeral = generateKeyPairSync('x25519');
  const sharedSecret = diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: createPublicKey({
      format: 'der',
      key: Buffer.from(recipient.encryptionPublicKey, 'base64'),
      type: 'spki',
    }),
  });
  const salt = randomBytes(32);
  const iv = randomBytes(12);
  const key = Buffer.from(hkdfSync('sha256', sharedSecret, salt, pairingInfo, 32));
  const senderPublic = publicMachineIdentity(sender);
  const createdAt = new Date();
  const unsigned = {
    createdAt: createdAt.toISOString(),
    ephemeralPublicKey: ephemeral.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    expiresAt: new Date(createdAt.getTime() + lifetimeMs).toISOString(),
    iv: iv.toString('base64'),
    kind: 'signed-in-pairing-envelope' as const,
    recipientFingerprint: recipient.fingerprint,
    salt: salt.toString('base64'),
    sender: senderPublic,
    version: 1 as const,
  };
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(canonicalJson(unsigned), 'utf8'));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(payload), 'utf8')),
    cipher.final(),
  ]);
  const envelopeWithoutSignature = {
    ...unsigned,
    authTag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
  const signature = sign(
    null,
    Buffer.from(canonicalJson(envelopeWithoutSignature), 'utf8'),
    createPrivateKey({ format: 'der', key: Buffer.from(sender.signingPrivateKey, 'base64'), type: 'pkcs8' }),
  );
  key.fill(0);
  sharedSecret.fill(0);
  return { ...envelopeWithoutSignature, signature: signature.toString('base64') };
}

// Verifies sender integrity, destination binding, and expiry before any credential is decrypted.
export function decryptPairingEnvelope(
  recipient: MachineIdentityPrivate,
  envelope: PairingEnvelope,
  now = new Date(),
): PairingPayload {
  if (envelope.kind !== 'signed-in-pairing-envelope' || envelope.version !== 1) {
    throw new Error('Unsupported signed-in pairing envelope');
  }
  validatePublicIdentity(envelope.sender);
  if (envelope.recipientFingerprint !== recipient.fingerprint) {
    throw new Error('Pairing envelope belongs to a different machine');
  }
  if (Date.parse(envelope.expiresAt) < now.getTime()) throw new Error('Pairing envelope has expired');
  if (Date.parse(envelope.createdAt) > now.getTime() + 60_000) throw new Error('Pairing envelope is from the future');
  const { signature, ...signedPayload } = envelope;
  const signatureValid = verify(
    null,
    Buffer.from(canonicalJson(signedPayload), 'utf8'),
    createPublicKey({ format: 'der', key: Buffer.from(envelope.sender.signingPublicKey, 'base64'), type: 'spki' }),
    Buffer.from(signature, 'base64'),
  );
  if (!signatureValid) throw new Error('Pairing envelope signature is invalid');

  const sharedSecret = diffieHellman({
    privateKey: createPrivateKey({
      format: 'der',
      key: Buffer.from(recipient.encryptionPrivateKey, 'base64'),
      type: 'pkcs8',
    }),
    publicKey: createPublicKey({
      format: 'der',
      key: Buffer.from(envelope.ephemeralPublicKey, 'base64'),
      type: 'spki',
    }),
  });
  const key = Buffer.from(hkdfSync(
    'sha256',
    sharedSecret,
    Buffer.from(envelope.salt, 'base64'),
    pairingInfo,
    32,
  ));
  const { authTag: _authTag, ciphertext: _ciphertext, signature: _signature, ...aad } = envelope;
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
  decipher.setAAD(Buffer.from(canonicalJson(aad), 'utf8'));
  decipher.setAuthTag(Buffer.from(envelope.authTag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final(),
  ]);
  key.fill(0);
  sharedSecret.fill(0);
  try {
    return JSON.parse(plaintext.toString('utf8')) as PairingPayload;
  } finally {
    plaintext.fill(0);
  }
}

// Encodes a public machine card compactly for copy/paste and SSH pairing flows.
export function encodePublicIdentity(identity: MachineIdentityPublic): string {
  validatePublicIdentity(identity);
  return `signedin1:${Buffer.from(JSON.stringify(identity), 'utf8').toString('base64url')}`;
}

// Parses only versioned public cards and validates the embedded fingerprint before use.
export function decodePublicIdentity(value: string): MachineIdentityPublic {
  if (!value.startsWith('signedin1:')) throw new Error('Expected a signedin1 public machine identity');
  const parsed = JSON.parse(Buffer.from(value.slice('signedin1:'.length), 'base64url').toString('utf8')) as MachineIdentityPublic;
  validatePublicIdentity(parsed);
  return parsed;
}

// Derives a human-comparable fingerprint from both authority-bearing public keys.
function buildPublicIdentity(input: Omit<MachineIdentityPublic, 'fingerprint'>): MachineIdentityPublic {
  const fingerprint = createHash('sha256')
    .update(input.encryptionPublicKey)
    .update('\0')
    .update(input.signingPublicKey)
    .digest('hex')
    .match(/.{1,4}/gu)
    ?.slice(0, 6)
    .join('-') ?? '';
  return { ...input, fingerprint };
}

// Prevents forged labels or swapped keys from masquerading under a copied fingerprint.
function validatePublicIdentity(identity: MachineIdentityPublic): void {
  const expected = buildPublicIdentity({
    encryptionPublicKey: identity.encryptionPublicKey,
    id: identity.id,
    label: identity.label,
    signingPublicKey: identity.signingPublicKey,
  });
  if (expected.fingerprint !== identity.fingerprint) throw new Error('Machine identity fingerprint is invalid');
}

// Canonicalizes signed structures so all platforms verify identical bytes.
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object' && value !== null) {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
