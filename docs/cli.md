# CLI reference

## First sign-in

```sh
signed-in login
```

No project is required. On a new machine, signed-in presents every supported service in one checkbox
list. Use the arrow keys to move, Space to toggle, and Enter to continue. When nothing is checked,
Enter selects the highlighted service before continuing, so choosing one service never requires a
separate Space keystroke. Authentication mechanics are not separate sections: each selected service
gets one focused step with the appropriate actions.
For example, AWS can continue into its provider sign-in while Clerk offers API-key entry,
instructions, or a skip for now.

Name services directly to bypass the checklist:

```sh
signed-in login clerk
signed-in login polar
```

Each sign-in creates an immutable connection with a visible alias. Email identities derive the alias
from their domain: Gmail and similar personal providers become `personal`; `@acme.com` becomes
`acme`; `@studio.co.nz` becomes `studio`. Other provider identities become readable aliases, and
services without safe identity evidence ask what the connection is for. Collisions receive `-2`,
`-3`, and so on.

Human-chosen and renamed aliases are prompted with the recommended `<project>-<environment>` pattern,
for example `acme-production`. The pattern is guidance rather than validation: identity-derived
aliases such as `personal` remain useful, and existing aliases continue to work unchanged.

The first connection becomes the service default, but `default` is only a pointer and is never its
stored name. Use the same `service@alias` spelling everywhere:

```sh
signed-in login github@work
signed-in login github@personal
signed-in use github@work
signed-in github@personal auth status
```

Selecting an already connected service offers either another connection or reconnection of a named
alias. Choosing reconnection is the confirmation for that human login workflow. Changing a default,
renaming an alias, removing a connection, changing trust, sharing authority, or approving a
destructive provider operation uses a visible terminal confirmation. There is no signed-in approval
password, phrase, or PIN. Browser/device sessions run in isolated homes. Fallback credentials are
entered through a hidden terminal prompt, never a CLI option. Multiline keys use a visible file-path
prompt and are forwarded only during that explicit human workflow.

After a successful batch, Enter runs one safe authenticated test for every new connection. A pass
returns to the same summary with Done selected; a rejected credential, unavailable provider, or
misconfigured probe is identified without exposing the response and enters the focused repair path.
If any service needs attention, Enter retries only that failed subset; connecting more services
remains available in the same summary. An explicit command such as `signed-in login aws` starts
directly with AWS and ends at the same calm summary. Machine-readable and non-interactive invocations
never prompt or run an implicit test.

If any command discovers that its selected connection is not signed in, an interactive terminal
offers to enter that service's normal sign-in flow immediately. Declining leaves the exact command
to run later. JSON, quiet, redirected, and other non-interactive calls retain the structured
`AUTH_REQUIRED` error, login remedy, and exit status 75 without prompting.

AWS browser login is a bootstrap rather than the stored authority. signed-in converts it into a
durable access key on the generic `signed-in` IAM principal, verifies the resulting identity,
encrypts it in the vault, and discards the browser session. The credential belongs to the connection
and may be copied to another trusted machine through authenticated pairing. AWS account aliases
become connection aliases when available; otherwise the account ID provides a recognizable fallback.

Useful authentication commands:

```sh
signed-in login [service[@alias]…] [--all] [--remote|--local]
signed-in ping [service[@alias]] [--json]
signed-in status [service] [--all]
signed-in connections [service[@alias]]
signed-in use <service>@<alias>
signed-in alias <service>@<alias> <new-alias>
signed-in logout <service>[@alias]
```

## Authenticated operations

```sh
signed-in ping [service[@alias]] [--json]
signed-in <service>[@alias] [vendor CLI arguments...]
signed-in request <service>[@alias] <METHOD> <path>
```

`ping` performs each provider's safest identity-style read: a `/me` or `whoami` equivalent where
one exists, otherwise a minimal authenticated list or status call. A named service checks that
connection; no service checks every connected service concurrently. The result reports only the
interface, HTTP status or CLI exit code, and duration. Provider bodies and native output are
discarded inside the daemon. Exit status is non-zero when any probe fails.

## Agent skill installer

```sh
signed-in skill install
signed-in skill install --global --agent codex --agent claude
signed-in skill install --local --agent all [--root <directory>]
signed-in skill status [--global|--local] [--agent <name>]…
```

The interactive installer selects global or repository-local scope, detects installed clients, and
shows every exact destination before copying the packaged `signed-in` operating guide. Supported
targets are Codex, Claude Code, Cursor, GitHub Copilot, Gemini CLI, and OpenCode. Scripted installs
must provide a scope and at least one `--agent`; `--agent all` selects every supported client.

Installation is idempotent. A current copy is left untouched. A modified copy requires interactive
confirmation or `--force`, and extra operator-added files inside the skill directory are preserved.
This command is daemon-free and can be used before any service login.

Provider arguments pass as argv to the pinned executable; no shell parses them. A destructive
classification prompts locally. Credential-control commands are denied before the provider starts.

HTTP options:

```text
--data <text>       UTF-8 request body
--data-file <path>  request body from a file
--stdin             request body from stdin
-H, --header        non-authentication request header; repeatable
--include           print safe response status and headers
--json              wrap the redacted gateway response and receipt as JSON
```

signed-in owns `Authorization`, cookies, proxy authorization, and common API-key headers. Direct AWS
requests default to the catalog's STS scope; other services use non-secret internal hints, for
example `-H 'x-signed-in-aws-service: s3'`. signed-in removes those hints before signing and
forwarding.

## Optional projects

Machine connections exist independently of repositories. A project is a later, optional map from
services to aliases plus policy that can only narrow machine authority. Explicit aliases resolve to
immutable connection IDs when the project is trusted; renaming an alias therefore cannot redirect
or break the sealed project. A `true` binding deliberately follows the service's machine default.

The config is deliberately just a readable map of the aliases shown by `signed-in status`:

```json
{
  "schemaVersion": 2,
  "project": { "id": "acme-app", "name": "Acme App" },
  "providers": {},
  "services": {
    "aws": "acme",
    "github": "acme",
    "resend": { "alias": "acme", "required": true }
  }
}
```

This source stays understandable after an alias is renamed: the already trusted snapshot continues
using its sealed connection, while `signed-in project show` calls out the old configured alias so an
agent can update the file before the next trust review.

```sh
signed-in project trust [--config <path>] [--root <project-root>]
signed-in project list
signed-in project show [id]
signed-in project forget <id>
```

`project trust` discovers `signed-in.config.json` upward from the current directory when `--config`
is omitted. It shows the bindings before asking for approval, seals the reviewed snapshot, and pins
provider executables. It does not copy credentials into the project. A repository edit cannot alter
the sealed runtime policy until a human trusts it again.

Inside a trusted root, commands automatically use that project's connection bindings. An explicit
override can appear before or after a built-in command:

```sh
signed-in --project acme-app status
signed-in status --project acme-app
```

`SIGNED_IN_PROJECT` is a non-secret equivalent for automated shells.

## Inspection

```sh
signed-in
signed-in ping [service[@alias]] [--json]
signed-in status [--all] [--json]
signed-in doctor [--json]
signed-in project list [--json]
signed-in audit [--limit 50] [--json]
signed-in policy explain <service> -- <native args>
signed-in policy explain <service> --http <METHOD> <path>
```

At an interactive terminal, bare `signed-in` always shows the current connection readout before one
small next-action menu: connect or repair a service, manage existing connections, install the agent
skill, or finish. Services with more than one connection show their default alias followed by the
additional aliases; `signed-in status clerk` expands one service, while `signed-in connections
clerk@work` opens management directly for that alias. Enter starts login when no service is connected
or a connection needs attention, recommends the skill when a detected agent does not yet have it,
and otherwise selects Done. When stdin is redirected or no terminal is available, it remains a
prompt-free status view and exits successfully even on a new machine. `--all` turns explicit status
into the complete service browser.

## Machine pairing

```sh
signed-in pair public-key --raw
signed-in pair export --recipient 'signedin1:...' > bundle.json
signed-in pair import bundle.json
signed-in share-auth example-machine
```

See [Machine pairing](./pairing.md).

## Daemon

```sh
signed-in daemon status
signed-in daemon start
signed-in daemon stop
signed-in daemon restart
signed-in daemon install
signed-in daemon uninstall
```

Normal commands auto-start the private daemon. `daemon install` is optional; it adds a user
LaunchAgent on macOS or user systemd service on Linux so signed-in is warm immediately after a
restart. Authentication state always lives in the encrypted vault and survives daemon or machine
restarts.

`daemon uninstall` removes that optional startup registration and stops the helper without removing
connections. To remove signed-in completely, first run `signed-in reset`, then
`signed-in daemon uninstall`, then `npm uninstall --global signed-in`. Skip reset when uninstalling
the executable temporarily and retaining encrypted connections for a later reinstall.

## Recovery

```sh
signed-in reset
```

Reset presents a destructive confirmation in an interactive terminal and never accepts a phrase or
non-interactive bypass. It removes machine connections, project bindings, audit receipts, device
identity, encrypted records, and the OS-keychain wrapping key. Repository config files are untouched.

## Discoverability and automation

```sh
signed-in --help
signed-in help agent
signed-in help aws
signed-in login --help
signed-in aws --help
signed-in --version
signed-in completion zsh
```

`signed-in help agent` is the compact operating contract for automated callers. `signed-in help
<service>` describes that service's login, native CLI, HTTP, status, policy, alias, and documentation
routes without starting the daemon. Every built-in command supports `--help`; `signed-in <service>
--help` deliberately forwards to the underlying provider CLI instead. Unknown signed-in-owned flags
fail instead of being silently ignored; tokens after `--` and provider-CLI arguments remain
passthrough input. Warnings, prompts, progress, cancellations, and errors use stderr, while stdout
carries the command result.

Exit status is `0` for success, `75` when human authentication or approval is required, `77` for
policy denial, `78` when a human declines, `1` for another signed-in error, or the provider CLI's own
status for native passthrough. JSON errors include a stable code, message, and runnable remedy when a
person is needed.

## Optional MCP transport

```sh
signed-in mcp
```

The stdio server exposes `signed_in_status`, `signed_in_request`, and `signed_in_run`. It uses the
same daemon, connection resolution, policy, redaction, and audit path. Operations requiring interactive
confirmation fail closed through MCP and return to the direct CLI for the human step.
