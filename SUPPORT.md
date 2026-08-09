# Support

Start with the built-in diagnostics:

```sh
signed-in doctor
signed-in status --all
signed-in help troubleshooting
```

Use a GitHub issue for reproducible bugs and feature requests. Include the signed-in version,
operating system, provider, command shape with secrets removed, exit code, and the output of
`signed-in doctor`. Do not attach vault files, provider sessions, keychain exports, or live tokens.

Authentication failures often require a person at an interactive terminal. Follow the exact remedy
printed by signed-in; exit 75 deliberately means the operation needs that human step.

Report suspected vulnerabilities privately through [SECURITY.md](./SECURITY.md), not through a
public issue.
