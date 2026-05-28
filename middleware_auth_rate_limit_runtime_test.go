package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type errorRateLimiter struct{}

func (errorRateLimiter) Decide(context.Context, string, time.Time) (RateLimitDecision, error) {
	return RateLimitDecision{}, errors.New("backend failure")
}

type deniedRateLimiter struct{}

func (deniedRateLimiter) Decide(context.Context, string, time.Time) (RateLimitDecision, error) {
	return RateLimitDecision{Allowed: false, Limit: 1, Remaining: 0, RetryAfterS: 1}, nil
}

func TestHTTPAuthenticationMiddleware_AllowsAPIKeyOnly(t *testing.T) {
	mw := HTTPAuthenticationMiddleware(HTTPAuthConfig{
		RequireAPIKey:  true,
		APIKeyHeader:   "X-API-Key",
		ExpectedAPIKey: "k1",
	})

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := IdentityFromContext(r.Context())
		if identity.ID != "api-key-client" {
			t.Fatalf("unexpected api key identity id: %q", identity.ID)
		}
		if identity.Type != "client" {
			t.Fatalf("unexpected api key identity type: %q", identity.Type)
		}
		if identity.Level != "L1" {
			t.Fatalf("unexpected api key identity level: %q", identity.Level)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/resource", nil)
	req.Header.Set("X-API-Key", "k1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected api-key-only request to pass, got %d", rr.Code)
	}
}

func TestHTTPAuthenticationMiddleware_RejectsAPIKeyOnlyWhenNotConfigured(t *testing.T) {
	mw := HTTPAuthenticationMiddleware(HTTPAuthConfig{
		Authenticator: StaticTokenAuthenticator{ExpectedToken: "token-1", Identity: Identity{ID: "client-1", Type: "client", Level: "L1"}},
	})

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/resource", nil)
	req.Header.Set("X-API-Key", "k1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized when api key auth is not configured, got %d", rr.Code)
	}
}

func TestGRPCAuthenticationInterceptor_AllowsAPIKeyOnly(t *testing.T) {
	interceptor := GRPCAuthenticationInterceptor(GRPCAuthConfig{
		RequireAPIKey:  true,
		APIKeyHeader:   "x-api-key",
		ExpectedAPIKey: "k1",
	})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "k1"))
	called := false
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		identity := IdentityFromContext(ctx)
		if identity.ID != "api-key-client" {
			return nil, status.Error(codes.Internal, "api key identity id not set")
		}
		if identity.Level != "L1" {
			return nil, status.Error(codes.Internal, "api key identity level not set")
		}
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("expected api-key-only request to pass, got %v", err)
	}
	if !called {
		t.Fatalf("handler should have been called")
	}
}

func TestGRPCAuthenticationInterceptor_RejectsAPIKeyOnlyWhenNotConfigured(t *testing.T) {
	interceptor := GRPCAuthenticationInterceptor(GRPCAuthConfig{
		Authenticator: StaticTokenAuthenticator{ExpectedToken: "token-1", Identity: Identity{ID: "client-1", Type: "client", Level: "L1"}},
	})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "k1"))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated when api key auth is not configured, got %v", status.Code(err))
	}
}

func TestHTTPRateLimitMiddleware_RejectsAndSetsRetryAfter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := NewFixedWindowLimiter(1, time.Minute, func() time.Time { return now })
	mw := HTTPRateLimitMiddleware(HTTPRateLimitConfig{
		Limiter: limiter,
		Now:     func() time.Time { return now },
		KeyFunc: func(*http.Request) string { return "key-1" },
	})

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	firstReq := httptest.NewRequest(http.MethodGet, "/v1/limited", nil)
	firstRR := httptest.NewRecorder()
	h.ServeHTTP(firstRR, firstReq)
	if firstRR.Code != http.StatusNoContent {
		t.Fatalf("expected first request to pass, got %d", firstRR.Code)
	}

	secondReq := httptest.NewRequest(http.MethodGet, "/v1/limited", nil)
	secondRR := httptest.NewRecorder()
	h.ServeHTTP(secondRR, secondReq)
	if secondRR.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request to be rate-limited, got %d", secondRR.Code)
	}
	if secondRR.Header().Get("Retry-After") == "" {
		t.Fatalf("retry-after header should be set when request is rejected")
	}
	if secondRR.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("remaining header should be 0 when request is rejected")
	}
}

func TestHTTPRateLimitMiddleware_BackendFailure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	mw := HTTPRateLimitMiddleware(HTTPRateLimitConfig{
		Limiter: errorRateLimiter{},
		Now:     func() time.Time { return now },
		KeyFunc: func(*http.Request) string { return "key-1" },
	})

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/limited", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected backend failure to return 429, got %d", rr.Code)
	}
}

func TestGRPCRateLimitInterceptor_BackendFailure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	interceptor := GRPCRateLimitInterceptor(GRPCRateLimitConfig{
		Limiter: errorRateLimiter{},
		Now:     func() time.Time { return now },
		KeyFunc: func(context.Context, string) string { return "key-1" },
	})

	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected resource exhausted on backend failure, got %v", status.Code(err))
	}
}

func TestGRPCRateLimitInterceptor_Denied(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	interceptor := GRPCRateLimitInterceptor(GRPCRateLimitConfig{
		Limiter: deniedRateLimiter{},
		Now:     func() time.Time { return now },
		KeyFunc: func(context.Context, string) string { return "key-1" },
	})

	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected resource exhausted when rate-limited, got %v", status.Code(err))
	}
}

func TestGRPCRateLimitInterceptor_Allowed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	interceptor := GRPCRateLimitInterceptor(GRPCRateLimitConfig{
		Limiter: stubRateLimiter{},
		Now:     func() time.Time { return now },
		KeyFunc: func(context.Context, string) string { return "key-1" },
	})

	called := false
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("expected success for allowed request, got %v", err)
	}
	if !called {
		t.Fatalf("handler should be called for allowed request")
	}
}
