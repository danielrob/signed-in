# Provider adapters

## Adapter contract

The packaged service catalog or a trusted extension adapter may define:

- credential fields and their provider environment names;
- hidden, visible, or file-backed credential prompts for multiline key material;
- a native CLI executable, fixed prefix argv, and delivery mode;
- an isolated login argv and optional remote-login argv;
- private token resolvers from command text, command JSON, AWS process JSON, or captured JSON files;
- one fixed HTTPS base origin, additional authenticated hosts, and credential-free auxiliary egress;
- Bearer, custom-header, Basic, App Store Connect JWT, AWS SigV4, or no HTTP auth;
- provider-specific native classification patterns;
- independent or shared machine-credential behavior.

The first successful interactive login pins that service's resolved executable locally. A changed
binary must be reviewed with `signed-in trust <service>`. Project trust also verifies the binaries it
will use. General-purpose interpreters and package runners are rejected as provider commands.
Placeholders in fixed prefix arguments are limited to `{cwd}` and `{workspaceRoot}`.

## Built-in matrix

| Provider | Login / source | Native | HTTP | Authority model | Isolation |
| --- | --- | --- | --- | --- | --- |
| AWS | `aws login`, then shared IAM key bootstrap | `aws` | SigV4 hosts | shared | proxy |
| Google Cloud | `gcloud auth login`, private access-token resolver | `gcloud` | Google APIs | independent | proxy |
| Convex | `convex login` user token | Convex CLI | — | independent | ephemeral session |
| Clerk | hidden backend secret key | — | Backend API | shared fallback | brokered HTTP |
| Netlify | `netlify login`, captured token extraction | `netlify` | REST API | independent | proxy |
| Polar | `polar login`; separate organization token for full REST | current limited CLI | REST API | independent | session + brokered HTTP |
| Cloudflare | Wrangler OAuth, private refreshed-token resolver | `wrangler` | v4 API | independent | proxy |
| GitHub | `gh auth login` with repository and workflow authority, private token resolver | `gh` | REST/GraphQL | independent | proxy |
| Resend | hidden account API key | — | REST API | shared fallback | brokered HTTP |
| OpenAI | hidden project API key | `openai` when installed | REST API | shared fallback | proxy |
| Sentry | hidden auth token | `sentry-cli` | REST API | shared fallback | proxy |
| Better Stack | hidden API token | — | Uptime/Telemetry APIs | shared fallback | brokered HTTP |
| PostHog | hidden personal API key | — | REST API | shared fallback | brokered HTTP |
| Shopify | `shopify auth login` | Shopify CLI | — | independent | ephemeral session |
| Stripe | hidden secret key | `stripe` | REST API | shared fallback | proxy |
| App Store Connect | issuer, key ID, `.p8` | — | fresh ES256 JWT per call | shared fallback | brokered HTTP |
| Meta | hidden system-user token | — | Graph API | shared fallback | brokered HTTP |
| npm | hidden granular token | — | registry API | shared fallback | brokered HTTP |

### Polar

Polar's current CLI owns OAuth login/logout and a small set of listen/migrate/update workflows. It
does not model the management API. signed-in retains that native surface but makes the complete
documented REST API available through `signed-in request polar ...`. An organization access token is
used for the REST gateway because the CLI's refreshable token store does not expose a supported
management-token interface.

### Convex

Convex login stores a full-account user token and the CLI can mint secondary deployment authority as
part of ordinary commands. signed-in therefore captures the whole CLI session rather than pretending a
simple Bearer proxy covers all Convex protocols. Deploy-key creation remains denied as credential
minting. Projects may independently deny deployment publication through their trusted policy.

### AWS

`aws login` runs against a deterministic `signed-in` profile inside a private home. Its temporary
console credentials are used once, during that human-started login, to create or reuse a dedicated
`signed-in` IAM user and access key. The principal receives full account access to match the
operator-authority contract. No account ID, operator username, or machine name is built into the
adapter. AWS's account alias is used as the connection alias when available; otherwise a suffix of
the account ID is used.

An existing key is reused only when its secret is already sealed in the current connection and STS
proves that it belongs to the generic principal. Listed remote keys are never borrowed because AWS
cannot return their secrets. Two active keys are never rotated automatically because either may be
in use on another machine; authenticated `share-auth` is the preferred path.

Only the durable key enters the encrypted vault; the browser session is discarded after bootstrap.
Its portable fields may cross machines only inside a recipient-bound signed pairing envelope.
Normal AWS commands receive dummy values and are re-signed inside the daemon. The agent-facing policy
continues to deny STS credential minting, IAM key creation, and common secret-value reads—the key
creation exception exists only inside an explicit human login.

### Netlify

Native deployment and REST management are available by default. A trusted project can deny deploy
commands when publication is owned by a separate release harness.

### Shopify

`signed-in login shopify` installs the official Shopify CLI when it is missing, then opens Shopify's
browser login only after the user chooses the sign-in action. It retains the resulting CLI state in an
isolated encrypted session and does not ask the user to create or paste an Admin API token. Run Shopify
commands through `signed-in shopify ...` so they use that sealed session instead of whichever account
happens to be active in the global CLI. This account login does not itself grant access to a merchant's
Admin API.

Shopify's Dev MCP server supplies unauthenticated documentation, schemas, and validation; it is
separate from merchant authority. For direct Admin API work, Shopify's CLI Connector app is the
supported agent-oriented path. It deliberately adds a second, per-store authorization boundary. A
human can grant only the scopes needed for the task without copying a token:

```sh
signed-in shopify store auth --store example.myshopify.com --scopes read_products,read_orders
```

signed-in requires this command to be run and confirmed in an interactive terminal. Shopify then
opens its own Admin consent page, where the merchant reviews the Connector app, scopes, and API terms.
No local app source is created: this route is for direct CLI/agent store operations. Shopify stores
the resulting user-bound online access token inside the same isolated session, and subsequent
`store execute` and `store bulk` commands reuse it.

Projects can bind the exact store as their provider target:

```json
{
  "services": {
    "shopify": {
      "alias": "acme",
      "target": "example.myshopify.com"
    }
  }
}
```

Ambient Shopify scope, store, password, and mutation flags are removed before the isolated CLI starts;
the trusted project target is applied afterward. GraphQL mutations remain disabled by Shopify unless
`--allow-mutations` is supplied, and signed-in classifies that flag as a mutating operation. For a
deployed integration rather than direct operator work, scaffold a Shopify app and manage its scopes
and installation in app configuration instead of relying on the CLI Connector app.

## Adding a service

1. Prefer a provider browser/device session that can yield renewable authority without exporting it.
2. Prefer `proxy` native delivery with a short-lived private resolver or static field.
3. Declare the narrowest authenticated hosts and no auxiliary egress unless the CLI demonstrably
   needs it.
4. Add credential-output/mint patterns to provider policy.
5. Use `session` only when the provider CLI must consume opaque or secondary credentials.
6. Use `environment` only as a documented compatibility exception.
7. Mark a field `portable: true` only when sharing that connection across trusted machines is an
   intentional adapter property; omission fails closed.
8. Add policy, redaction, status, pairing, and request tests before publishing the catalog change.

The built-in catalog is the normal route for broadly useful services. A project may seal an extension
adapter for a private or transitional integration, but that must not make basic login dependent on a
project.

For a private API, define a manual credential, fixed HTTPS origin, header injection, and harmless
`/me`-style ping in `providers`, then bind it in `services`. Project checks can prove the particular
read surfaces an agent needs without exposing their bodies. See the
[custom HTTP example](../examples/custom-http/signed-in.config.json).

## Optional Pipedream adapter

Pipedream Connect can be added as a long-tail OAuth adapter, but it should not become signed-in's root of
trust. Its API proxy centralizes provider credentials and introduces a reusable Pipedream project
secret. A future adapter should let the local daemon hold that root, constrain upstream origins, and
apply the same policy and redaction path.
