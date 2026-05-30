# Security Policy

## Reporting a Vulnerability

Please report vulnerabilities through a private security advisory in this repository,
or contact the maintainer directly using the repository owner contact.

Include:

- Clear impact description
- Reproduction steps
- Affected versions
- Mitigation suggestions

## Security Notes

For production middleware deployments, prefer strict constructors and validators:

- `ValidateEnvironmentConfigStrict`
- `ValidateHTTPAuthConfigStrict` / `ValidateGRPCAuthConfigStrict`
- `ValidateHTTPValidationConfigStrict` / `ValidateGRPCValidationConfigStrict`
- `ValidateHTTPRateLimitConfigStrict` / `ValidateGRPCRateLimitConfigStrict`
- `ValidateLoggingConfigStrict` / `ValidateMetricsConfigStrict` / `ValidateTracingConfigStrict`

For domain-specific Firebase + identity/session policy enforcement, use the optional adapter:

- `github.com/nhanpnt22/middleware/aipfirebase`

Strict paths are designed to fail closed and reject incomplete startup configuration.

Configuration and secrets guidance:

- Keep secret-bearing values out of config files
- Inject secrets via environment variables or secret manager bindings
- Validate middleware config at startup using strict validation helpers
