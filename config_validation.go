package middleware

import (
	"fmt"
	"strings"
)

const (
	EnvironmentLocalDev   = "local-dev"
	EnvironmentTesting    = "testing"
	EnvironmentStaging    = "staging"
	EnvironmentProduction = "production"
)

// EnvironmentConfig contains startup-level environment identity.
type EnvironmentConfig struct {
	Environment string
}

// ValidateEnvironmentConfigStrict validates environment identity against the configured allowlist.
func ValidateEnvironmentConfigStrict(cfg EnvironmentConfig) error {
	env := strings.TrimSpace(cfg.Environment)
	if env == "" {
		return fmt.Errorf("environment config: environment is required")
	}
	switch env {
	case EnvironmentLocalDev, EnvironmentTesting, EnvironmentStaging, EnvironmentProduction:
		return nil
	default:
		return fmt.Errorf("environment config: invalid environment %q (allowed: %s, %s, %s, %s)", env, EnvironmentLocalDev, EnvironmentTesting, EnvironmentStaging, EnvironmentProduction)
	}
}

// ValidateHTTPAuthConfigStrict validates HTTP auth config without applying implicit defaults.
func ValidateHTTPAuthConfigStrict(cfg HTTPAuthConfig) error {
	if cfg.AllowAnonymous == nil {
		return fmt.Errorf("http auth config: allow anonymous policy is required")
	}
	if cfg.Authenticator == nil && !isHTTPAPIKeyAuthConfigured(cfg) {
		return fmt.Errorf("http auth config: either authenticator or api key auth configuration is required")
	}
	if cfg.RequireAPIKey {
		if strings.TrimSpace(cfg.APIKeyHeader) == "" {
			return fmt.Errorf("http auth config: api key header is required when RequireAPIKey=true")
		}
		if strings.TrimSpace(cfg.ExpectedAPIKey) == "" {
			return fmt.Errorf("http auth config: expected api key is required when RequireAPIKey=true")
		}
	}
	if !cfg.RequireAPIKey && strings.TrimSpace(cfg.ExpectedAPIKey) != "" && strings.TrimSpace(cfg.APIKeyHeader) == "" {
		return fmt.Errorf("http auth config: api key header is required when expected api key is configured")
	}
	return nil
}

// ValidateGRPCAuthConfigStrict validates gRPC auth config without applying implicit defaults.
func ValidateGRPCAuthConfigStrict(cfg GRPCAuthConfig) error {
	if cfg.AllowAnonymous == nil {
		return fmt.Errorf("grpc auth config: allow anonymous policy is required")
	}
	if cfg.Authenticator == nil && !isGRPCAPIKeyAuthConfigured(cfg) {
		return fmt.Errorf("grpc auth config: either authenticator or api key auth configuration is required")
	}
	if cfg.RequireAPIKey {
		if strings.TrimSpace(cfg.APIKeyHeader) == "" {
			return fmt.Errorf("grpc auth config: api key header is required when RequireAPIKey=true")
		}
		if strings.TrimSpace(cfg.ExpectedAPIKey) == "" {
			return fmt.Errorf("grpc auth config: expected api key is required when RequireAPIKey=true")
		}
	}
	if !cfg.RequireAPIKey && strings.TrimSpace(cfg.ExpectedAPIKey) != "" && strings.TrimSpace(cfg.APIKeyHeader) == "" {
		return fmt.Errorf("grpc auth config: api key header is required when expected api key is configured")
	}
	return nil
}

// ValidateHTTPAuthXORConfigStrict validates HTTP auth xor guard config without implicit defaults.
func ValidateHTTPAuthXORConfigStrict(cfg HTTPAuthXORConfig) error {
	if strings.TrimSpace(cfg.AuthorizationHeader) == "" {
		return fmt.Errorf("http auth xor config: authorization header is required")
	}
	if strings.TrimSpace(cfg.APIKeyHeader) == "" {
		return fmt.Errorf("http auth xor config: api key header is required")
	}
	if cfg.AllowAnonymous == nil {
		return fmt.Errorf("http auth xor config: allow anonymous policy is required")
	}
	return nil
}

// ValidateGRPCAuthXORConfigStrict validates gRPC auth xor guard config without implicit defaults.
func ValidateGRPCAuthXORConfigStrict(cfg GRPCAuthXORConfig) error {
	if strings.TrimSpace(cfg.AuthorizationHeader) == "" {
		return fmt.Errorf("grpc auth xor config: authorization header is required")
	}
	if strings.TrimSpace(cfg.APIKeyHeader) == "" {
		return fmt.Errorf("grpc auth xor config: api key header is required")
	}
	if cfg.AllowAnonymous == nil {
		return fmt.Errorf("grpc auth xor config: allow anonymous policy is required")
	}
	return nil
}

// ValidateFirebaseAuthMiddlewareConfigStrict validates strict Firebase auth requirements.
func ValidateFirebaseAuthMiddlewareConfigStrict(cfg FirebaseAuthMiddlewareConfig) error {
	if cfg.Verifier == nil {
		return fmt.Errorf("firebase auth config: verifier is required")
	}
	if strings.TrimSpace(cfg.ProjectID) == "" {
		return fmt.Errorf("firebase auth config: project id is required")
	}
	if cfg.SessionValidator == nil {
		return fmt.Errorf("firebase auth config: session validator is required")
	}
	if cfg.IdentityValidator == nil {
		return fmt.Errorf("firebase auth config: identity validator is required")
	}
	if cfg.NowUnix == nil {
		return fmt.Errorf("firebase auth config: now unix function is required")
	}
	return nil
}

// ValidateHTTPValidationConfigStrict validates HTTP validation config without implicit defaults.
func ValidateHTTPValidationConfigStrict(cfg HTTPValidationConfig) error {
	if cfg.MaxBodyBytes <= 0 {
		return fmt.Errorf("http validation config: MaxBodyBytes must be > 0")
	}
	if cfg.RequireRequestID && strings.TrimSpace(cfg.RequestIDHeader) == "" {
		return fmt.Errorf("http validation config: request id header is required when RequireRequestID=true")
	}
	if cfg.RequireAppID && strings.TrimSpace(cfg.AppIDHeader) == "" {
		return fmt.Errorf("http validation config: app id header is required when RequireAppID=true")
	}
	if cfg.RequireSessionID && strings.TrimSpace(cfg.SessionHeader) == "" {
		return fmt.Errorf("http validation config: session header is required when RequireSessionID=true")
	}
	if cfg.RequireIdempotencyForMutations && strings.TrimSpace(cfg.IdempotencyHeader) == "" {
		return fmt.Errorf("http validation config: idempotency header is required when RequireIdempotencyForMutations=true")
	}
	if cfg.RequireIdempotencyForMutations && cfg.IsMutation == nil {
		return fmt.Errorf("http validation config: IsMutation is required when RequireIdempotencyForMutations=true")
	}
	return nil
}

// ValidateGRPCValidationConfigStrict validates gRPC validation config without implicit defaults.
func ValidateGRPCValidationConfigStrict(cfg GRPCValidationConfig) error {
	if cfg.MaxRequestBytes <= 0 {
		return fmt.Errorf("grpc validation config: MaxRequestBytes must be > 0")
	}
	if cfg.RequireRequestID && strings.TrimSpace(cfg.RequestIDHeader) == "" {
		return fmt.Errorf("grpc validation config: request id header is required when RequireRequestID=true")
	}
	if cfg.RequireAppID && strings.TrimSpace(cfg.AppIDHeader) == "" {
		return fmt.Errorf("grpc validation config: app id header is required when RequireAppID=true")
	}
	if cfg.RequireSessionID && strings.TrimSpace(cfg.SessionHeader) == "" {
		return fmt.Errorf("grpc validation config: session header is required when RequireSessionID=true")
	}
	if cfg.RequireIdempotencyForMutations && strings.TrimSpace(cfg.IdempotencyHeader) == "" {
		return fmt.Errorf("grpc validation config: idempotency header is required when RequireIdempotencyForMutations=true")
	}
	if cfg.RequireIdempotencyForMutations && cfg.IsMutation == nil {
		return fmt.Errorf("grpc validation config: IsMutation is required when RequireIdempotencyForMutations=true")
	}
	return nil
}

// ValidateHTTPIdempotencyConfigStrict validates HTTP idempotency extraction config.
func ValidateHTTPIdempotencyConfigStrict(cfg IdempotencyConfig) error {
	if cfg.RequiredForMutations && cfg.IsMutationHTTP == nil {
		return fmt.Errorf("http idempotency config: IsMutationHTTP is required when RequiredForMutations=true")
	}
	return nil
}

// ValidateGRPCIdempotencyConfigStrict validates gRPC idempotency extraction config.
func ValidateGRPCIdempotencyConfigStrict(cfg IdempotencyConfig) error {
	if cfg.RequiredForMutations && cfg.IsMutationGRPC == nil {
		return fmt.Errorf("grpc idempotency config: IsMutationGRPC is required when RequiredForMutations=true")
	}
	return nil
}

// ValidateHTTPRateLimitConfigStrict validates HTTP rate-limit config without implicit defaults.
func ValidateHTTPRateLimitConfigStrict(cfg HTTPRateLimitConfig) error {
	if cfg.Limiter == nil {
		return fmt.Errorf("http rate-limit config: limiter is required")
	}
	if cfg.Now == nil {
		return fmt.Errorf("http rate-limit config: now function is required")
	}
	if cfg.KeyFunc == nil {
		return fmt.Errorf("http rate-limit config: key function is required")
	}
	return nil
}

// ValidateGRPCRateLimitConfigStrict validates gRPC rate-limit config without implicit defaults.
func ValidateGRPCRateLimitConfigStrict(cfg GRPCRateLimitConfig) error {
	if cfg.Limiter == nil {
		return fmt.Errorf("grpc rate-limit config: limiter is required")
	}
	if cfg.Now == nil {
		return fmt.Errorf("grpc rate-limit config: now function is required")
	}
	if cfg.KeyFunc == nil {
		return fmt.Errorf("grpc rate-limit config: key function is required")
	}
	return nil
}

// ValidateLoggingConfigStrict validates logging config without implicit defaults.
func ValidateLoggingConfigStrict(cfg LoggingConfig) error {
	if strings.TrimSpace(cfg.ServiceName) == "" {
		return fmt.Errorf("logging config: service name is required")
	}
	if strings.TrimSpace(cfg.Environment) == "" {
		return fmt.Errorf("logging config: environment is required")
	}
	if cfg.Logger == nil {
		return fmt.Errorf("logging config: log sink is required")
	}
	if cfg.Now == nil {
		return fmt.Errorf("logging config: now function is required")
	}
	if cfg.NormalizeEndpoint == nil {
		return fmt.Errorf("logging config: normalize endpoint function is required")
	}
	return nil
}

// ValidateMetricsConfigStrict validates metrics config without implicit defaults.
func ValidateMetricsConfigStrict(cfg MetricsConfig) error {
	if strings.TrimSpace(cfg.ServiceName) == "" {
		return fmt.Errorf("metrics config: service name is required")
	}
	if cfg.Recorder == nil {
		return fmt.Errorf("metrics config: recorder is required")
	}
	if cfg.Now == nil {
		return fmt.Errorf("metrics config: now function is required")
	}
	return nil
}

// ValidateTracingConfigStrict validates tracing config without implicit defaults.
func ValidateTracingConfigStrict(cfg TracingConfig) error {
	if strings.TrimSpace(cfg.TraceHeader) == "" {
		return fmt.Errorf("tracing config: trace header is required")
	}
	if strings.TrimSpace(cfg.RequestHeader) == "" {
		return fmt.Errorf("tracing config: request header is required")
	}
	if strings.TrimSpace(cfg.TraceparentHeader) == "" {
		return fmt.Errorf("tracing config: traceparent header is required")
	}
	if strings.TrimSpace(cfg.TracePrefix) == "" {
		return fmt.Errorf("tracing config: trace prefix is required")
	}
	return nil
}

// ValidateFoundationConfigStrict validates foundation config without implicit defaults.
func ValidateFoundationConfigStrict(cfg FoundationConfig) error {
	if cfg.Codec == nil {
		return fmt.Errorf("foundation config: codec is required")
	}
	if strings.TrimSpace(cfg.Codec.Name()) == "" {
		return fmt.Errorf("foundation config: codec name is required")
	}
	if cfg.Digest == nil {
		return fmt.Errorf("foundation config: digest provider is required")
	}
	if strings.TrimSpace(cfg.Digest.Name()) == "" {
		return fmt.Errorf("foundation config: digest name is required")
	}
	if cfg.Entropy == nil {
		return fmt.Errorf("foundation config: entropy source is required")
	}
	if cfg.TokenBytes <= 0 {
		return fmt.Errorf("foundation config: TokenBytes must be > 0")
	}
	if cfg.MaxIDLength <= 0 {
		return fmt.Errorf("foundation config: MaxIDLength must be > 0")
	}
	return nil
}
