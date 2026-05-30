# middleware

Deterministic, reusable Go middleware primitives for HTTP and gRPC services.

## Features

- Canonical chain composition
- Panic recovery
- Tracing context propagation
- Metrics and structured logging helpers
- Authentication and authorization middleware
- Auth xor guard middleware (`authorization` xor `x-api-key`)
- Pluggable foundation primitives (codec + digest + entropy)
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

## Optional Domain Adapter

Domain-specific Firebase + identity/session binding enforcement is isolated in the optional `aipfirebase` subpackage:

- `github.com/nhanpnt22/middleware/aipfirebase`

Compatibility constructors are still available in the root package:

- `HTTPFirebaseAuthMiddlewareStrict`
- `GRPCFirebaseAuthInterceptorStrict`

## Standard Chain Order

```text
panic_recovery
tracing
metrics
logging
auth_xor_guard
authentication
authorization
rate_limiting
circuit_breaker
idempotency_extraction
request_validation
handler
```

Use `ValidateStandardOrder` to enforce order in tests/CI.

## Strict Mode

This package does not read environment variables or config files directly.
All configuration must be injected by the caller at startup.

For fail-fast startup validation (no implicit defaults), use strict validators:

- `ValidateEnvironmentConfigStrict`
- `ValidateHTTPAuthConfigStrict`
- `ValidateGRPCAuthConfigStrict`
- `ValidateHTTPAuthXORConfigStrict`
- `ValidateGRPCAuthXORConfigStrict`
- `ValidateFirebaseAuthMiddlewareConfigStrict`
- `ValidateLoggingConfigStrict`
- `ValidateMetricsConfigStrict`
- `ValidateTracingConfigStrict`
- `ValidateHTTPValidationConfigStrict`
- `ValidateGRPCValidationConfigStrict`
- `ValidateHTTPRateLimitConfigStrict`
- `ValidateGRPCRateLimitConfigStrict`
- `ValidateFoundationConfigStrict`

For explicit wiring constructors, use strict constructors:

- `HTTPAuthenticationMiddlewareStrict`
- `GRPCAuthenticationInterceptorStrict`
- `HTTPAuthXORGuardMiddlewareStrict`
- `GRPCAuthXORGuardInterceptorStrict`
- `HTTPFirebaseAuthMiddlewareStrict`
- `GRPCFirebaseAuthInterceptorStrict`
- `HTTPTracingMiddlewareStrict`
- `GRPCTracingInterceptorStrict`
- `HTTPMetricsMiddlewareStrict`
- `GRPCMetricsInterceptorStrict`
- `HTTPLoggingMiddlewareStrict`
- `GRPCLoggingInterceptorStrict`
- `HTTPRateLimitMiddlewareStrict`
- `GRPCRateLimitInterceptorStrict`
- `HTTPIdempotencyExtractionMiddlewareStrict`
- `GRPCIdempotencyExtractionInterceptorStrict`
- `HTTPValidationMiddlewareStrict`
- `GRPCValidationInterceptorStrict`

## Quick Start: Default vs Strict

Default mode applies safe fallbacks:

```go
logging := middleware.HTTPLoggingMiddleware(middleware.LoggingConfig{})
metrics := middleware.HTTPMetricsMiddleware(middleware.MetricsConfig{})
```

Strict mode fails fast when required dependencies are missing:

```go
logging, err := middleware.HTTPLoggingMiddlewareStrict(middleware.LoggingConfig{
	ServiceName:       "orders-api",
	Environment:       middleware.EnvironmentProduction,
	Logger:            middleware.NewNoopLogSink(),
	Now:               time.Now,
	NormalizeEndpoint: func(s string) string { return s },
})
if err != nil {
	panic(err)
}

metrics, err := middleware.HTTPMetricsMiddlewareStrict(middleware.MetricsConfig{
	ServiceName: "orders-api",
	Recorder:    middleware.NewNoopMetricsRecorder(),
	Now:         time.Now,
})
if err != nil {
	panic(err)
}

_ = logging
_ = metrics
```

## Foundation Primitives

For reusable ID/hash/token generation across middleware and services, use `Foundation`.

Default constructor (safe baseline):

- `NewFoundation()` uses SHA-256 + Base64URL + `crypto/rand`

Strict constructor (no implicit defaults):

- `NewFoundationStrict(FoundationConfig)`

Pluggable interfaces:

- `BinaryTextCodec` (e.g. Base64URL, Base32, B57/F57 adapters)
- `DigestProvider` (e.g. SHA-256, BLAKE3 adapters)
- `FuncBinaryTextCodec` and `FuncDigestProvider` for function-based integration

Built-in no-op adapters:

- `NewNoopLogSink()`
- `NewNoopMetricsRecorder()`

Core operations:

- `NewToken()` for random transport-safe token generation
- `ContentHash(input)` for canonical digest representation
- `DeterministicID(namespace, payload, digestBytes)` for stable namespaced IDs

### F57 Family Compatibility Status

Direct middleware dependency on ID57/H57/R57/B57/S57 is intentionally deferred.

Current policy:

- Keep middleware transport/runtime surfaces dependency-clean.
- Use the `Foundation` interfaces for pluggable codec and digest integration.
- Add direct f57-family dependency only after upstream packaging and licensing are consumable.

Enablement criteria for future direct adoption:

- A publicly resolvable Go module path for the Go implementation.
- License terms that explicitly permit usage, modification, and redistribution for this project.
- Stable tagged releases with import instructions that work with standard Go tooling.

## Configurable Validation Headers

Validation middleware supports explicit header configuration:

- HTTP: `RequestIDHeader`, `IdempotencyHeader`, `AppIDHeader`, `SessionHeader`
- gRPC: `RequestIDHeader`, `IdempotencyHeader`, `AltIdempotencyHeader`, `AppIDHeader`, `SessionHeader`

This allows integration with non-default ingress and metadata conventions.

## Examples

See minimal examples:

- `examples/http/main.go`
- `examples/grpc/main.go`
- `examples/foundation/main.go`

## Security Notes

- Do not store secret values in configuration files.
- Inject secret-bearing values through environment variables or a secret manager.

## Release Checklist

- Run `go test ./...`
- Verify strict constructors for startup wiring return no errors in your service bootstrap
- Confirm middleware order with `ValidateStandardOrder` in CI/tests
- Tag releases with semantic versioning (for example `vX.Y.Z`)
