package middleware

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestHTTPMiddlewareConstructorsStrictFailFast(t *testing.T) {
	if _, err := HTTPAuthenticationMiddlewareStrict(HTTPAuthConfig{}); err == nil {
		t.Fatalf("expected strict auth constructor to fail")
	}
	if _, err := HTTPTracingMiddlewareStrict(TracingConfig{}); err == nil {
		t.Fatalf("expected strict tracing constructor to fail")
	}
	if _, err := HTTPValidationMiddlewareStrict(HTTPValidationConfig{}); err == nil {
		t.Fatalf("expected strict validation constructor to fail")
	}
	if _, err := HTTPRateLimitMiddlewareStrict(HTTPRateLimitConfig{}); err == nil {
		t.Fatalf("expected strict rate limit constructor to fail")
	}
}

func TestGRPCInterceptorConstructorsStrictFailFast(t *testing.T) {
	if _, err := GRPCAuthenticationInterceptorStrict(GRPCAuthConfig{}); err == nil {
		t.Fatalf("expected strict grpc auth constructor to fail")
	}
	if _, err := GRPCTracingInterceptorStrict(TracingConfig{}); err == nil {
		t.Fatalf("expected strict grpc tracing constructor to fail")
	}
	if _, err := GRPCValidationInterceptorStrict(GRPCValidationConfig{}); err == nil {
		t.Fatalf("expected strict grpc validation constructor to fail")
	}
}

func TestStrictConstructorsBuildWithExplicitValidConfig(t *testing.T) {
	assertStrictHTTPConstructorsBuild(t)
	assertStrictGRPCConstructorsBuild(t)
	assertStrictXORConstructors(t)
	assertStrictAuthOptionalModes(t)
	assertStrictGRPCRateLimitConstructors(t)
}

func assertStrictHTTPConstructorsBuild(t *testing.T) {
	t.Helper()

	authMW, err := HTTPAuthenticationMiddlewareStrict(HTTPAuthConfig{
		Authenticator:  StaticTokenAuthenticator{ExpectedToken: "token-1", Identity: Identity{ID: "svc", Type: "service", Level: "L2"}},
		AllowAnonymous: func(*http.Request) bool { return false },
		RequireAPIKey:  true,
		APIKeyHeader:   "X-API-Key",
		ExpectedAPIKey: "k1",
	})
	if err != nil {
		t.Fatalf("auth strict constructor failed: %v", err)
	}
	if authMW == nil {
		t.Fatalf("auth middleware should not be nil")
	}

	tracingMW, err := HTTPTracingMiddlewareStrict(DefaultTracingConfig())
	if err != nil {
		t.Fatalf("tracing strict constructor failed: %v", err)
	}
	if tracingMW == nil {
		t.Fatalf("tracing middleware should not be nil")
	}

	validationMW, err := HTTPValidationMiddlewareStrict(HTTPValidationConfig{
		MaxBodyBytes:                   1024,
		RequireRequestID:               true,
		RequestIDHeader:                "X-Request-ID",
		RequireIdempotencyForMutations: true,
		IdempotencyHeader:              "Idempotency-Key",
		IsMutation: func(method, _ string) bool {
			return method == http.MethodPost
		},
		RequireAppID:     true,
		AppIDHeader:      "X-App-ID",
		RequireSessionID: true,
		SessionHeader:    "X-Session-ID",
	})
	if err != nil {
		t.Fatalf("validation strict constructor failed: %v", err)
	}
	if validationMW == nil {
		t.Fatalf("validation middleware should not be nil")
	}

	rateMW, err := HTTPRateLimitMiddlewareStrict(HTTPRateLimitConfig{
		Limiter: stubRateLimiter{},
		Now:     time.Now,
		KeyFunc: func(*http.Request) string { return "key-1" },
	})
	if err != nil {
		t.Fatalf("rate limit strict constructor failed: %v", err)
	}
	if rateMW == nil {
		t.Fatalf("rate limit middleware should not be nil")
	}
}

func assertStrictGRPCConstructorsBuild(t *testing.T) {
	t.Helper()

	grpcAuth, err := GRPCAuthenticationInterceptorStrict(GRPCAuthConfig{
		Authenticator:  StaticTokenAuthenticator{ExpectedToken: "token-1", Identity: Identity{ID: "svc", Type: "service", Level: "L2"}},
		AllowAnonymous: func(string) bool { return false },
	})
	if err != nil {
		t.Fatalf("grpc auth strict constructor failed: %v", err)
	}
	if grpcAuth == nil {
		t.Fatalf("grpc auth interceptor should not be nil")
	}

	grpcTrace, err := GRPCTracingInterceptorStrict(DefaultTracingConfig())
	if err != nil {
		t.Fatalf("grpc tracing strict constructor failed: %v", err)
	}
	if grpcTrace == nil {
		t.Fatalf("grpc tracing interceptor should not be nil")
	}

	grpcValidation, err := GRPCValidationInterceptorStrict(GRPCValidationConfig{
		MaxRequestBytes:                1024,
		RequireRequestID:               true,
		RequestIDHeader:                "x-request-id",
		RequireIdempotencyForMutations: true,
		IdempotencyHeader:              "idempotency-key",
		IsMutation: func(string) bool {
			return true
		},
		RequireAppID:     true,
		AppIDHeader:      "x-app-id",
		RequireSessionID: true,
		SessionHeader:    "x-session-id",
	})
	if err != nil {
		t.Fatalf("grpc validation strict constructor failed: %v", err)
	}
	if grpcValidation == nil {
		t.Fatalf("grpc validation interceptor should not be nil")
	}
}

func assertStrictXORConstructors(t *testing.T) {
	t.Helper()

	_, err := HTTPAuthXORGuardMiddlewareStrict(HTTPAuthXORConfig{
		AllowAnonymous: func(*http.Request) bool { return false },
	})
	if err == nil {
		t.Fatalf("strict HTTP auth xor constructor should fail without metadata configuration")
	}

	_, err = HTTPAuthXORGuardMiddlewareStrict(HTTPAuthXORConfig{
		AllowAnonymous:      func(*http.Request) bool { return false },
		APIKeyHeader:        "X-API-Key",
		AuthorizationHeader: "Authorization",
	})
	if err != nil {
		t.Fatalf("strict HTTP auth xor constructor failed with valid config: %v", err)
	}

	_, err = GRPCAuthXORGuardInterceptorStrict(GRPCAuthXORConfig{
		AllowAnonymous: func(string) bool { return false },
	})
	if err == nil {
		t.Fatalf("strict gRPC auth xor constructor should fail without metadata configuration")
	}

	_, err = GRPCAuthXORGuardInterceptorStrict(GRPCAuthXORConfig{
		AllowAnonymous:      func(string) bool { return false },
		APIKeyHeader:        "x-api-key",
		AuthorizationHeader: "authorization",
	})
	if err != nil {
		t.Fatalf("strict gRPC auth xor constructor failed with valid config: %v", err)
	}
}

func assertStrictAuthOptionalModes(t *testing.T) {
	t.Helper()

	_, err := HTTPAuthenticationMiddlewareStrict(HTTPAuthConfig{
		Authenticator:  StaticTokenAuthenticator{ExpectedToken: "token-1", Identity: Identity{ID: "svc", Type: "service", Level: "L2"}},
		AllowAnonymous: func(*http.Request) bool { return false },
	})
	if err != nil {
		t.Fatalf("strict HTTP auth constructor should allow optional API key, got: %v", err)
	}

	_, err = GRPCAuthenticationInterceptorStrict(GRPCAuthConfig{
		Authenticator:  StaticTokenAuthenticator{ExpectedToken: "token-1", Identity: Identity{ID: "svc", Type: "service", Level: "L2"}},
		AllowAnonymous: func(string) bool { return false },
	})
	if err != nil {
		t.Fatalf("strict gRPC auth constructor should allow explicit allow-anonymous policy, got: %v", err)
	}
}

func assertStrictGRPCRateLimitConstructors(t *testing.T) {
	t.Helper()

	_, err := GRPCRateLimitInterceptorStrict(GRPCRateLimitConfig{
		Limiter: stubRateLimiter{},
		Now:     time.Now,
		KeyFunc: func(context.Context, string) string { return "key-1" },
	})
	if err != nil {
		t.Fatalf("strict grpc rate-limit constructor failed with valid config: %v", err)
	}

	_, err = GRPCRateLimitInterceptorStrict(GRPCRateLimitConfig{
		Now:     time.Now,
		KeyFunc: func(context.Context, string) string { return "key-1" },
	})
	if err == nil {
		t.Fatalf("strict grpc rate-limit constructor should fail without limiter")
	}

	_, err = GRPCRateLimitInterceptorStrict(GRPCRateLimitConfig{
		Limiter: stubRateLimiter{},
		KeyFunc: func(context.Context, string) string { return "key-1" },
	})
	if err == nil {
		t.Fatalf("strict grpc rate-limit constructor should fail without clock")
	}

	_, err = GRPCRateLimitInterceptorStrict(GRPCRateLimitConfig{
		Limiter: stubRateLimiter{},
		Now:     time.Now,
	})
	if err == nil {
		t.Fatalf("strict grpc rate-limit constructor should fail without key func")
	}
}
