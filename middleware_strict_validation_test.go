package middleware

import (
	"net/http"
	"testing"
	"time"
)

func TestValidateFirebaseAuthMiddlewareConfigStrict(t *testing.T) {
	if err := ValidateFirebaseAuthMiddlewareConfigStrict(FirebaseAuthMiddlewareConfig{}); err == nil {
		t.Fatalf("expected validation error for empty config")
	}

	err := ValidateFirebaseAuthMiddlewareConfigStrict(FirebaseAuthMiddlewareConfig{
		Verifier:          stubClaimsVerifier{claims: map[string]interface{}{}},
		ProjectID:         "p1",
		SessionValidator:  stubSessionValidator{},
		IdentityValidator: stubIdentityValidator{},
		NowUnix:           func() int64 { return 1_700_000_000 },
	})
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestValidateHTTPAuthConfigStrict(t *testing.T) {
	err := ValidateHTTPAuthConfigStrict(HTTPAuthConfig{
		Authenticator:  StaticTokenAuthenticator{ExpectedToken: "t1"},
		AllowAnonymous: func(*http.Request) bool { return false },
		RequireAPIKey:  true,
		APIKeyHeader:   "X-API-Key",
	})
	if err == nil {
		t.Fatalf("expected error when expected api key is missing")
	}

	err = ValidateHTTPAuthConfigStrict(HTTPAuthConfig{
		Authenticator:  StaticTokenAuthenticator{ExpectedToken: "t1"},
		AllowAnonymous: func(*http.Request) bool { return false },
		RequireAPIKey:  true,
		APIKeyHeader:   "X-API-Key",
		ExpectedAPIKey: "expected",
	})
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}

	err = ValidateHTTPAuthConfigStrict(HTTPAuthConfig{
		AllowAnonymous: func(*http.Request) bool { return false },
		RequireAPIKey:  true,
		APIKeyHeader:   "X-API-Key",
		ExpectedAPIKey: "expected",
	})
	if err != nil {
		t.Fatalf("expected api-key-only strict config to be valid, got %v", err)
	}

	err = ValidateHTTPAuthConfigStrict(HTTPAuthConfig{
		AllowAnonymous: func(*http.Request) bool { return false },
	})
	if err == nil {
		t.Fatalf("expected invalid config when both authenticator and api key auth are missing")
	}
}

func TestValidateGRPCAuthConfigStrict(t *testing.T) {
	err := ValidateGRPCAuthConfigStrict(GRPCAuthConfig{
		Authenticator:  StaticTokenAuthenticator{ExpectedToken: "t1"},
		AllowAnonymous: func(string) bool { return false },
		RequireAPIKey:  true,
		APIKeyHeader:   "x-api-key",
	})
	if err == nil {
		t.Fatalf("expected error when expected api key is missing")
	}

	err = ValidateGRPCAuthConfigStrict(GRPCAuthConfig{
		Authenticator:  StaticTokenAuthenticator{ExpectedToken: "t1"},
		AllowAnonymous: func(string) bool { return false },
		RequireAPIKey:  true,
		APIKeyHeader:   "x-api-key",
		ExpectedAPIKey: "expected",
	})
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}

	err = ValidateGRPCAuthConfigStrict(GRPCAuthConfig{
		AllowAnonymous: func(string) bool { return false },
		RequireAPIKey:  true,
		APIKeyHeader:   "x-api-key",
		ExpectedAPIKey: "expected",
	})
	if err != nil {
		t.Fatalf("expected api-key-only strict config to be valid, got %v", err)
	}

	err = ValidateGRPCAuthConfigStrict(GRPCAuthConfig{
		AllowAnonymous: func(string) bool { return false },
	})
	if err == nil {
		t.Fatalf("expected invalid config when both authenticator and api key auth are missing")
	}
}

func TestValidateHTTPValidationConfigStrict(t *testing.T) {
	err := ValidateHTTPValidationConfigStrict(HTTPValidationConfig{MaxBodyBytes: 0})
	if err == nil {
		t.Fatalf("expected error for non-positive MaxBodyBytes")
	}

	err = ValidateHTTPValidationConfigStrict(HTTPValidationConfig{
		MaxBodyBytes:     1024,
		RequireRequestID: true,
	})
	if err == nil {
		t.Fatalf("expected error when request id header is missing")
	}

	err = ValidateHTTPValidationConfigStrict(HTTPValidationConfig{
		MaxBodyBytes:                   1024,
		RequireIdempotencyForMutations: true,
		IdempotencyHeader:              "Idempotency-Key",
		IsMutation:                     func(string, string) bool { return true },
	})
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestValidateGRPCValidationConfigStrict(t *testing.T) {
	err := ValidateGRPCValidationConfigStrict(GRPCValidationConfig{MaxRequestBytes: 0})
	if err == nil {
		t.Fatalf("expected error for non-positive MaxRequestBytes")
	}

	err = ValidateGRPCValidationConfigStrict(GRPCValidationConfig{
		MaxRequestBytes:  1024,
		RequireRequestID: true,
	})
	if err == nil {
		t.Fatalf("expected error when request id header is missing")
	}

	err = ValidateGRPCValidationConfigStrict(GRPCValidationConfig{
		MaxRequestBytes:                1024,
		RequireRequestID:               true,
		RequestIDHeader:                "x-request-id",
		RequireIdempotencyForMutations: true,
		IdempotencyHeader:              "idempotency-key",
		IsMutation:                     func(string) bool { return true },
	})
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestValidateHTTPRateLimitConfigStrict(t *testing.T) {
	err := ValidateHTTPRateLimitConfigStrict(HTTPRateLimitConfig{})
	if err == nil {
		t.Fatalf("expected error for missing strict dependencies")
	}

	err = ValidateHTTPRateLimitConfigStrict(HTTPRateLimitConfig{
		Limiter: stubRateLimiter{},
		Now:     time.Now,
		KeyFunc: func(*http.Request) string { return "k1" },
	})
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestValidateEnvironmentConfigStrict(t *testing.T) {
	validEnvs := []string{
		EnvironmentLocalDev,
		EnvironmentTesting,
		EnvironmentStaging,
		EnvironmentProduction,
	}

	for _, env := range validEnvs {
		err := ValidateEnvironmentConfigStrict(EnvironmentConfig{Environment: env})
		if err != nil {
			t.Fatalf("expected %q to be valid, got %v", env, err)
		}
	}

	if err := ValidateEnvironmentConfigStrict(EnvironmentConfig{}); err == nil {
		t.Fatalf("expected error for missing environment")
	}

	if err := ValidateEnvironmentConfigStrict(EnvironmentConfig{Environment: "prod"}); err == nil {
		t.Fatalf("expected error for invalid environment")
	}

	if err := ValidateEnvironmentConfigStrict(EnvironmentConfig{Environment: "PRODUCTION"}); err == nil {
		t.Fatalf("expected uppercase environment to fail strict validation")
	}
}

func TestValidateLoggingConfigStrict(t *testing.T) {
	err := ValidateLoggingConfigStrict(LoggingConfig{})
	if err == nil {
		t.Fatalf("expected error for missing logging dependencies")
	}

	err = ValidateLoggingConfigStrict(LoggingConfig{
		ServiceName:       "middleware",
		Environment:       EnvironmentTesting,
		Logger:            NewStdLogSink(nil),
		Now:               time.Now,
		NormalizeEndpoint: normalizeEndpoint,
	})
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestValidateMetricsConfigStrict(t *testing.T) {
	err := ValidateMetricsConfigStrict(MetricsConfig{})
	if err == nil {
		t.Fatalf("expected error for missing metrics dependencies")
	}

	err = ValidateMetricsConfigStrict(MetricsConfig{
		ServiceName: "middleware",
		Recorder:    NewInMemoryMetrics(),
		Now:         time.Now,
	})
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestValidateTracingConfigStrict(t *testing.T) {
	err := ValidateTracingConfigStrict(TracingConfig{})
	if err == nil {
		t.Fatalf("expected error for missing tracing config fields")
	}

	err = ValidateTracingConfigStrict(DefaultTracingConfig())
	if err != nil {
		t.Fatalf("expected valid tracing config, got %v", err)
	}
}
