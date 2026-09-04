# Machine pairing

Each machine has two durable signed-in device keys:

- X25519 for destination-bound encryption;
- Ed25519 for signed source metadata.

Private keys are vault records. The public card includes the machine ID, label, keys, and a
human-comparable fingerprint.

## Manual flow

On the destination:

```sh
signed-in pair public-key --raw
```

On the source:

```sh
signed-in pair export --recipient 'signedin1:...' > pair-bundle.json
```

Back on the destination:

```sh
signed-in pair import pair-bundle.json
```

An export uses an ephemeral X25519 key, HKDF-SHA-256, AES-256-GCM, and an Ed25519 signature. It is
bound to the destination fingerprint and expires after ten minutes. The output contains ciphertext,
public metadata, nonce material, and signatures only.

Export requires visible confirmation on the source machine. A conflict requires visible confirmation
on the destination; a non-conflicting, recipient-bound envelope can import unattended so
`share-auth` works over SSH. Aliases are retained while the destination creates its own immutable
connection IDs, so `service@alias` keeps the same human meaning without pretending the two machines
share local identity.

## Local network flow

```sh
signed-in share-auth example-machine
```

Without a host argument, signed-in lists online Tailscale peers. It obtains the remote public card
over SSH, sends only the encrypted envelope to remote stdin, and reports independent connections that
must be signed in on the destination. It can then open the remote guided login in an interactive SSH
TTY.

Tailscale and SSH authenticate the transport; signed-in encryption remains end-to-end even if transport
logs or buffers are retained.

## What moves

Only fields whose provider uses `credentialMode: shared` and whose field is explicitly marked
`portable: true` enter the payload. Provider sessions are never copied by the normal pairing path.

Google Cloud, Gmail through GWS, GitHub, Cloudflare, Netlify, Polar, and Convex use independent machine authority. AWS,
Clerk, Resend, OpenAI, Sentry, Better Stack, and similar providers copy fields only where the adapter
deliberately defines the connection as shared.

Portability is an explicit connection property, not a security ranking. Shared keys trade narrower
revocation for simpler trusted-machine operation; opaque browser and OAuth sessions remain local.
