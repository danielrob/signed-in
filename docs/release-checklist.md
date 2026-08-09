# Release checklist

This checklist is the durable release gate for signed-in. A private repository may complete the
engineering gates before the final public-launch section.

## Repository foundation

- [x] Standalone Git history contains only signed-in implementation, tests, documentation, and
  release tooling.
- [ ] Default branch is `main`; feature work reaches it through reviewed pull requests.
- [ ] Repository description, topics, homepage, and MIT license metadata are configured.
- [ ] Issues and private vulnerability reporting are enabled.
- [ ] Branch rules require CI before merge when the hosting plan supports them.
- [x] No machine-local state, generated archives, credentials, or unrelated product documentation is
  tracked.

## Product documentation

- [x] Root README explains the problem, account aliases, quick start, architecture, and limitations.
- [x] README includes the project's “Why not MCP?” position and explains the optional MCP transport.
- [x] CLI, architecture, security, provider, pairing, and project-policy documents match behavior.
- [x] Installation instructions cover source development and the future npm path without claiming an
  unpublished release exists.
- [x] Contribution, conduct, support, and vulnerability-reporting routes are present.
- [x] Examples use generic identities and contain no organization-specific secrets or private paths.

## Package quality

- [x] `signed-in` npm name and repository name are available or owned by the maintainer.
- [x] Package metadata includes license, author, repository, bugs, homepage, engines, keywords, and
  public publish configuration.
- [x] Published files contain both binaries, declarations, catalog data, README, license, and packaged
  agent skill.
- [x] Published files exclude TypeScript source, tests, local state, and repository-only tooling.
- [x] A clean tarball installs globally and both `signed-in --help` and `signed-in-daemon` resolve.
- [ ] Package version matches the release tag.

## Engineering gates

- [x] TypeScript strict typecheck passes from a clean checkout.
- [x] Unit, security, IPC reliability, CLI UX, installer, and skill tests pass.
- [ ] CI passes on Linux, macOS, and Windows across supported Node versions.
- [x] Dependency audit has no unresolved high or critical production vulnerability.
- [x] License review finds no dependency incompatible with MIT distribution.
- [x] Secret scanning finds no credential, private key, token, session, or machine-state artifact.
- [ ] Native provider commands authenticate through a tested broker transport on supported platforms.
- [ ] Upgrade, daemon restart, encrypted storage, and clean uninstall/recovery paths are documented and
  tested.

## Security review

- [x] Threat model distinguishes cooperative same-user guardrails from hostile-code isolation.
- [x] Credential extraction and minting remain denied through CLI, HTTP, MCP, and native passthrough.
- [x] Provider origins and auxiliary egress are allowlisted and tested.
- [x] Exact and structural redaction cover current provider credential formats.
- [x] Executables are resolved outside project dependency shims, pinned, and re-reviewed after change.
- [x] Pairing bundles are authenticated, recipient-bound, expiring, and contain only portable fields.
- [x] Audit receipts contain no request body, response body, secret header, or credential value.

## Release automation

- [x] CI is read-only and uses a frozen lockfile.
- [x] GitHub release publication checks the tag against `package.json`.
- [x] npm publication uses trusted publishing with provenance and no long-lived repository token.
- [ ] Release notes are prepared from `CHANGELOG.md` and call out migrations or credential rotation.
- [ ] A failed publish can be retried without changing the tagged source.

## Public launch

- [ ] Replace pre-release warnings only where the first release has proven the documented behavior.
- [ ] Enable npm trusted publishing for `danielrob/signed-in` and the release workflow environment.
- [ ] Publish a signed `v0.1.0` GitHub release and verify npm provenance.
- [ ] Install from the public registry on fresh macOS, Windows, and Linux accounts.
- [ ] Confirm README, license, repository links, binaries, skill files, and type declarations on npm.
- [ ] Make the GitHub repository public only after the tagged artifact and security reporting path are
  verified.
- [ ] Announce the explicit security boundary and pre-1.0 compatibility policy with the release.
