# Security model

## Protected outcomes

signed-in is designed to prevent a helpful but careless or determined agent from obtaining reusable
provider credentials through normal shell and filesystem behavior.

The intended properties are:

- real credentials do not enter the invoking agent process;
- real credentials do not appear in command arguments;
- real credentials do not remain in ordinary provider dotfiles;
- real credentials do not appear in normal stdout, stderr, API responses, or audit logs;
- agents cannot ask signed-in to reveal credentials;
- agents cannot use the ordinary gateway to mint replacement credentials;
- trusted commands, hosts, connection bindings, and policies cannot change through an unreviewed repo
  edit;
- non-interactive signed-in CLI and MCP calls cannot silently confirm protected operations;
- shared credentials cross machines only as authenticated, recipient-bound ciphertext;
- provider-managed machine identities are reauthenticated independently.

## Explicit boundary

signed-in is not a hostile-code sandbox for every process running as the same OS user. The following
remain outside its protection:

- OS, kernel, administrator, or physical compromise;
- attaching a debugger to `signed-in-daemon` or reading its process memory;
- replacing or instrumenting the signed-in daemon binary itself;
- deleting or rewriting signed-in's owner-readable files as the same OS user;
- calling the owner-only daemon protocol directly and forging an approval marker as the same OS user;
- defeating the OS keychain implementation;
- a malicious provider CLI or dependency that is intentionally trusted, especially for
  `session`/`environment` adapters;
- an agent intentionally abusing already-authorized provider operations to damage external state.

Policy, executable pinning, proxy delivery, confirmations, and receipts substantially reduce
accidental and cooperative bypasses, but they are not a separate OS-user security boundary. Run
untrusted or prompt-compromised agents under another user, container, sandbox, or host.

## Interactive guardrails

signed-in has no separate approval password, phrase, PIN, or recovery secret. Reconnecting an
existing connection is confirmed by deliberately selecting it inside the human login workflow.
Changing a service default, renaming or removing a connection, changing trust, exporting authority,
resetting local state, or satisfying a policy decision marked `confirm` requires a visible terminal
confirmation. Protected commands fail with exit 75 and a runnable remedy when no interactive terminal
is present. Routine reads and allowed mutations remain permanently unattended.

These prompts prevent accidents and cooperative automation, not a same-user process deliberately
calling the daemon protocol. That limitation matches the explicit boundary above; stronger hostile
separation requires another OS user, container, sandbox, or host.

Explicit project aliases are resolved to immutable connection IDs at trust time. Renaming an alias
does not alter the sealed target, and deleting then recreating the same alias cannot redirect it.
If the alias is not connected on this machine, the reviewed project is sealed in a pending state and
fails closed while the human completes normal login. Trust then resolves the new immutable ID. A
removed sealed connection likewise fails closed until its source binding is reviewed and trusted
again.

## Credential categories

signed-in separates three kinds of authority:

1. **Operator credentials** control vendor accounts and belong in signed-in.
2. **Runtime application secrets** are inputs consumed by deployed applications and remain in the
   project's configuration system or deployment platform's secret store.
3. **Machine identity** belongs to signed-in pairing and is never a provider credential.

Examples: a Resend account API key belongs in signed-in; a webhook-signing secret or inbound delivery
token belongs in the application's secret manager. A Clerk secret key used for both management and
runtime should ideally be split into separate provider keys before migrating provider-management
authority.

## Hard controls

The daemon denies known credential output and minting forms, including token-print commands, AWS
credential export, IAM access-key creation, GCP service-account key creation, GitHub/Cloudflare auth
token output, Convex deploy-key creation, and HTTP paths containing token, credential, OAuth, private
key, or access-key resources.

AWS has one narrow control-plane exception: after a human completes browser login, the daemon may use
that temporary proof internally to create or reuse signed-in's generic IAM user and seal its
one-time access-key response. This operation is not reachable through native passthrough, HTTP, MCP,
or ordinary agent-facing commands.

Responses receive two redaction passes:

- exact known secret replacement, including chunk-boundary-safe native streams;
- structural removal of newly returned secret-shaped JSON fields and high-confidence token formats.

## Provider CLI caveat

Proxy delivery is the strongest native mode: project hooks inherit only dummy credentials. If a CLI
does not honor proxy settings, its request fails with the dummy rather than falling back to the real
secret.

Session delivery necessarily gives the trusted provider CLI a decrypted OAuth session for its child
lifetime. The directory is random, owner-only, preferably memory-backed, and removed immediately.
This mode is used only when the CLI's protocol depends on provider-issued secondary credentials that
cannot be substituted at the network edge.

## Platform roots of trust

- macOS: Keychain through `@napi-rs/keyring`.
- Windows: Credential Manager through `@napi-rs/keyring`.
- Linux: Secret Service through `@napi-rs/keyring`; headless systems need an unlocked user Secret
  Service and D-Bus session before installing the persistent user service.

There is deliberately no plaintext master-key fallback.

## Response to compromise

1. Stop `signed-in-daemon`.
2. Revoke the affected machine's independent provider sessions and keys.
3. Rotate unavoidable shared static credentials.
4. If the installed signed-in binary remains trusted, run `signed-in reset` and confirm the removal
   in its terminal prompt. Otherwise remove the OS keychain item `signed-in / vault-master-v1`
   and the signed-in data directory manually.
5. Re-run per-machine login, then re-trust any optional project bindings.
6. Inspect the secret-free audit receipts and provider-side access logs.
