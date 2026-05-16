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

For production authentication in AIP services, use strict Firebase middleware:

- `HTTPFirebaseAuthMiddleware`
- `GRPCFirebaseAuthInterceptor`

These paths are designed to fail closed and enforce server-side identity/session/provider invariants.
