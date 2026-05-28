package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestFixedWindowLimiter(t *testing.T) {
	now := time.Unix(1_000, 0)
	limiter := NewFixedWindowLimiter(2, time.Minute, func() time.Time { return now })

	for i := 0; i < 2; i++ {
		decision, err := limiter.Decide(context.Background(), "key-1", now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !decision.Allowed {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	third, err := limiter.Decide(context.Background(), "key-1", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if third.Allowed {
		t.Fatalf("third request should be rejected")
	}
	if third.RetryAfterS < 1 {
		t.Fatalf("retry-after should be set")
	}
}

func TestGRPCValidationInterceptor(t *testing.T) {
	cfg := GRPCValidationConfig{
		RequireRequestID: true,
	}
	interceptor := GRPCValidationInterceptor(cfg)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-request-id", "req-1"))
	called := false
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/CreateThing"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatalf("handler was not called")
	}

	missingReqIDCtx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("idempotency-key", "idem-1"))
	_, err = interceptor(missingReqIDCtx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/CreateThing"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if status.Code(err).String() != "InvalidArgument" {
		t.Fatalf("expected invalid argument, got %v", status.Code(err))
	}
}

func TestGRPCIdempotencyExtractionInterceptor(t *testing.T) {
	interceptor := GRPCIdempotencyExtractionInterceptor(IdempotencyConfig{
		RequiredForMutations: true,
		IsMutationGRPC:       func(string) bool { return true },
	})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("idempotency-key", "idem-1"))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/CreateThing"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		if Value(ctx, IdempotencyKeyKey) != "idem-1" {
			return nil, errors.New("idempotency key should be injected")
		}
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHTTPValidationMiddleware_CustomHeaders(t *testing.T) {
	mw := HTTPValidationMiddleware(HTTPValidationConfig{
		MaxBodyBytes:                   1024,
		RequireRequestID:               true,
		RequestIDHeader:                "X-Correlation-ID",
		RequireIdempotencyForMutations: true,
		IdempotencyHeader:              "X-Idempotency-Key",
		IsMutation: func(method, _ string) bool {
			return method == http.MethodPost
		},
	})

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if Value(r.Context(), RequestIDKey) != "req-1" {
			t.Fatalf("request id should be injected from custom header")
		}
		if Value(r.Context(), IdempotencyKeyKey) != "idem-1" {
			t.Fatalf("idempotency key should be injected from custom header")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/v1/create", nil)
	req.Header.Set("X-Correlation-ID", "req-1")
	req.Header.Set("X-Idempotency-Key", "idem-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected success, got %d", rr.Code)
	}
}

func TestGRPCValidationInterceptor_CustomHeaders(t *testing.T) {
	interceptor := GRPCValidationInterceptor(GRPCValidationConfig{
		MaxRequestBytes:                1024,
		RequireRequestID:               true,
		RequestIDHeader:                "x-correlation-id",
		RequireIdempotencyForMutations: true,
		IdempotencyHeader:              "x-idempotency-custom",
		IsMutation:                     func(string) bool { return true },
	})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-correlation-id", "req-1",
		"x-idempotency-custom", "idem-1",
	))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/CreateThing"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		if Value(ctx, RequestIDKey) != "req-1" {
			return nil, errors.New("request id should be injected from custom header")
		}
		if Value(ctx, IdempotencyKeyKey) != "idem-1" {
			return nil, errors.New("idempotency key should be injected from custom header")
		}
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestHTTPCircuitBreakerMiddleware(t *testing.T) {
	h := HTTPCircuitBreakerMiddleware(failingBreaker{}, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cb", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}

func TestGRPCCircuitBreakerInterceptor(t *testing.T) {
	interceptor := GRPCCircuitBreakerInterceptor(failingBreaker{}, nil)
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected unavailable, got %v (%v)", status.Code(err), fmt.Sprint(err))
	}
}
