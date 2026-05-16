# middleware

Deterministic, reusable Go middleware primitives for AIP services.

This package includes:

- Canonical chain composition
- Panic recovery
- Tracing context propagation
- Metrics and structured logging helpers
- Authentication and authorization middleware
- Strict Firebase ID token authentication middleware with AIP invariant hooks
- Rate limiting
- Circuit breaker wrappers
- Idempotency extraction and request validation

## Install

```sh
go get github.com/nhanpnt22/middleware
```

## Import

```go
import "github.com/nhanpnt22/middleware"
```

## Strict Firebase Auth

Use the strict constructors for production AIP auth enforcement:

- `HTTPFirebaseAuthMiddleware`
- `GRPCFirebaseAuthInterceptor`

Both require:

- token verifier
- project id
- session validator
- identity validator

Behavior:

- fail closed
- enforce issuer/audience/uid/exp
- enforce required claims and provider allowlist
- enforce session and identity binding via validators
- inject verified identity and binding claims into context

## Standard Chain Order

```text
panic_recovery
tracing
metrics
logging
authentication
authorization
rate_limiting
circuit_breaker
idempotency_extraction
request_validation
handler
```

Use `ValidateStandardOrder` to enforce order in tests/CI.
