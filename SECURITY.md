# Security policy

## Supported versions

signed-in is pre-1.0. Until the first public release, security fixes are made on the default branch.
After releases begin, this table will identify supported release lines.

## Report a vulnerability

Use GitHub's private vulnerability reporting for `danielrob/signed-in`. If private reporting is not
available, contact the maintainer through the GitHub profile at https://github.com/danielrob and request a private channel.

Please include:

- the affected version or commit;
- the operating system and provider involved;
- the security property you expected;
- minimal reproduction steps;
- whether credential material may have been exposed.

Do not include live credentials, copied provider sessions, vault files, or keychain exports. Use
synthetic values and redact identifiers that are not necessary to reproduce the issue.

You should receive an acknowledgement within seven days. A remediation timeline depends on severity,
provider coordination, and whether users need credential-rotation guidance.

## Scope

High-priority reports include:

- reusable credentials reaching the invoking process, output, audit log, or ordinary provider files;
- policy or host-boundary bypasses through supported interfaces;
- unsafe migration, pairing, or vault behavior;
- unreviewed executable substitution;
- response-redaction failures with realistic provider output.

The documented [same-user hostile-code exclusions](./docs/security-model.md#explicit-boundary) remain
outside the intended security boundary unless a report demonstrates an avoidable escalation beyond
those exclusions.
