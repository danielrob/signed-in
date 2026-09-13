# Contributing

Thank you for helping improve signed-in. Authentication software benefits from small, reviewable
changes and explicit security reasoning.

## Development setup

Requirements: Node.js 22 or newer and pnpm 10.

```sh
pnpm install --frozen-lockfile
pnpm check
```

Run the source CLI without installing it:

```sh
pnpm dev -- --help
```

Exercise the real global installation path:

```sh
pnpm dev:install
signed-in --version
```

Render the home screen with fictional personal, team, project, and environment connections for documentation screenshots:

```sh
signed-in demo
# Or run directly from source:
pnpm -s demo:screen
```

This clears the terminal and uses the normal UI with fixed demo data. It does not read saved accounts,
start the daemon, or contact providers. Capture the screen while the menu is open; Enter or Ctrl+C exits.
Keep local screenshots under the ignored `artifacts/` directory until an image is selected for documentation.

Use isolated signed-in state during tests. Tests must never read or alter an operator's real keychain,
vault, provider profiles, or agent skill directories.

## Pull requests

- Keep changes focused and use a conventional commit title.
- Explain security-boundary changes explicitly in the pull request.
- Add regression coverage for behavior changes.
- Run `pnpm check` before requesting review.
- Do not commit credentials, provider sessions, generated archives, daemon state, or local logs.
- Do not weaken policy, executable pinning, response redaction, host allowlists, or interactive gates
  merely to make a provider command succeed.

## Adding a provider

Provider adapters are executable security policy. A new built-in adapter must include:

1. a documented authority and revocation model;
2. a harmless authenticated ping;
3. the narrowest necessary hosts and credential delivery mode;
4. credential extraction and minting denials;
5. redaction fixtures for returned secret formats;
6. login, status, request, and failure-path tests;
7. installation guidance for any required native CLI;
8. an update to the provider matrix.

Prefer renewable browser/device authority and proxy delivery. Use decrypted session or environment
delivery only when the provider CLI cannot operate through the brokered HTTP boundary.

## Reporting vulnerabilities

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](./SECURITY.md).
