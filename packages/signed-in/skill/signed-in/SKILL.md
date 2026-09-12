---
name: signed-in
description: Use authenticated vendor CLIs and APIs through the local signed-in gateway without accessing credentials. Use whenever a task needs AWS, GCP, GitHub, Netlify, Convex, Clerk, Polar, Cloudflare, or another configured service; when checking sign-in state; or when a provider command or API call would otherwise need tokens, profiles, or browser authentication.
---

# signed-in

Route vendor access through the installed `signed-in` command. Let its private daemon supply
authentication; never search for, request, print, or copy the underlying credentials.

## Start here

1. Run `signed-in help agent` for the current operating contract.
2. Run `signed-in status [service] --json` to discover configured services, aliases, and remedies.
3. Run `signed-in ping [service[@alias] | --all] --json` when an authentication proof is useful. Inside a
   trusted project, this automatically checks its intended identity, provider target, and declared
   read capabilities too.
4. Outside a project, the same command simply tests the selected standalone connection.
5. Use the project-selected connection inside a trusted project. Otherwise use the default alias
   unless status shows multiple connections or the task names one explicitly.

When asked to test all saved connections, run `signed-in ping --all --json`. This checks every alias,
not only each service's selected default, and returns one aggregate result without provider bodies.

## Perform provider work

- Native CLI: `signed-in <service>[@alias] <vendor arguments...>`
- HTTP API: `signed-in request <service>[@alias] <METHOD> <path> [options]`
- Provider-specific routes and examples: `signed-in help <service>`
- Policy preview: `signed-in policy explain <service> --json -- <vendor arguments...>`

Examples:

```sh
signed-in github pr list
signed-in aws sts get-caller-identity
signed-in request clerk GET '/v1/users?limit=1' --json
signed-in ping polar --json
```

Do not send `Authorization`, `Cookie`, or API-key headers. Do not call an underlying provider CLI
directly to evade signed-in routing, alias selection, policy, redaction, or audit behavior.

## Shopify authority

- Shopify's Dev MCP supplies documentation and validation; it does not provide merchant Admin API
  authentication. Use `signed-in shopify ...` for authenticated store commands.
- `signed-in login shopify` establishes only the Shopify account session. Per-store Admin authority
  comes from `signed-in shopify store auth --store <domain> --scopes <minimum-scopes>`.
- Store authorization changes persistent authority and must be chosen in an interactive terminal.
  Never automate the Shopify Admin consent page or treat approval in chat as terminal confirmation.
- After the human grants access, use `store execute` for reads. Let signed-in and Shopify present their
  own confirmation boundaries for scope changes, protected data, and mutations.

## Handle stops

- Follow the exact remedy printed by signed-in when authentication needs a person.
- Treat exit 75 as human-required, exit 77 as a policy denial that must not be bypassed, and exit 78
  as a human decline.
- In a non-interactive agent session, report the runnable login remedy rather than attempting to
  recover credentials from environment variables, provider profiles, keychains, vault files, daemon
  internals, shell history, or process state.
- Let signed-in present any confirmation for destructive provider operations. Never manufacture or
  imply approval on the operator's behalf.

If `signed-in` is unavailable, report that the machine needs the signed-in CLI installed. Do not fall
back to raw tokens or ambient provider authentication.
