# Security Policy

## Reporting a Vulnerability

Please report vulnerabilities through a private security advisory in this repository,
or contact the maintainer directly using the repository owner contact.

Include:

- clear impact description
- reproduction steps
- affected versions
- mitigation suggestions

## Security Notes

For production middleware deployments, prefer strict constructors and validators:


For domain-specific Firebase + identity/session policy enforcement, use the optional adapter:

- `github.com/nhanpnt22/middleware/aipfirebase`

Strict paths are designed to fail closed and reject incomplete startup configuration.

Configuration and secrets guidance:

- keep secret-bearing values out of config files
- inject secrets via environment variables or secret manager bindings
- validate middleware config at startup using strict validation helpers
