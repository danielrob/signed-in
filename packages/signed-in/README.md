# signed-in

Named, policy-aware vendor access for humans and coding agents without exposing reusable credentials.

```sh
npm install --global signed-in
signed-in login
signed-in status
signed-in ping
signed-in aws s3 ls
signed-in request polar GET /v1/products
```

The `signed-in` frontend talks to a private user-scoped daemon that owns the encrypted credential
vault, connection selection, provider sessions, policy, redaction, and audit. The calling process gets
the result of an allowed operation—not a credential it can copy elsewhere.

Connections are named and reusable across tools and projects:

```text
github@personal
github@work
clerk@acme-production
```

Projects are optional. A trusted project can bind an exact connection and narrow its policy without
placing credentials in the repository.

The package includes:

- `signed-in`, the human and agent CLI;
- `signed-in-daemon`, the private authorization service;
- native CLI and relative HTTP API transports;
- an optional MCP transport over the same daemon boundary;
- a skill installer for Codex, Claude Code, Cursor, GitHub Copilot, Gemini CLI, and OpenCode.

Read the full project documentation, including **Why not MCP?**, architecture, supported providers,
and explicit security boundary at [github.com/danielrob/signed-in](https://github.com/danielrob/signed-in).

> signed-in is pre-release software and is not a hostile-code sandbox for processes running as the
> same operating-system user.

## Library export

The intentionally small library surface includes policy classification, redaction, project-config
validation, and public types. Vault, keychain, pairing-private, and daemon service primitives remain
internal.

## License

MIT © Daniel Robinson
