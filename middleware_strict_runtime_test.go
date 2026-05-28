package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestHTTPTracingMiddlewareStrictRejectsMissingRequestID(t *testing.T) {
	mw, err := HTTPTracingMiddlewareStrict(DefaultTracingConfig())
	if err != nil {
		t.Fatalf("strict tracing constructor failed: %v", err)
	}

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for missing request id, got %d", rr.Code)
	}
}

func TestHTTPTracingMiddlewareStrictAcceptsPresentRequestID(t *testing.T) {
	mw, err := HTTPTracingMiddlewareStrict(DefaultTracingConfig())
	if err != nil {
		t.Fatalf("strict tracing constructor failed: %v", err)
	}

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if Value(r.Context(), RequestIDKey) != "req-123" {
			t.Fatalf("request id not propagated")
		}
		if Value(r.Context(), TraceIDKey) == "" {
			t.Fatalf("trace id should be present")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	req.Header.Set("X-Request-ID", "req-123")
	req.Header.Set("X-Trace-ID", "trace-123")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", rr.Code)
	}
}

func TestGRPCTracingInterceptorStrictRejectsMissingRequestID(t *testing.T) {
	interceptor, err := GRPCTracingInterceptorStrict(DefaultTracingConfig())
	if err != nil {
		t.Fatalf("strict tracing constructor failed: %v", err)
	}

	_, callErr := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if status.Code(callErr) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", status.Code(callErr))
	}
}

func TestGRPCTracingInterceptorStrictAcceptsPresentRequestID(t *testing.T) {
	interceptor, err := GRPCTracingInterceptorStrict(DefaultTracingConfig())
	if err != nil {
		t.Fatalf("strict tracing constructor failed: %v", err)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-request-id", "req-abc", "x-trace-id", "trace-abc"))
	_, callErr := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		if Value(ctx, RequestIDKey) != "req-abc" {
			return nil, status.Error(codes.Internal, "request id not propagated")
		}
		if Value(ctx, TraceIDKey) == "" {
			return nil, status.Error(codes.Internal, "trace id missing")
		}
		return "ok", nil
	})
	if callErr != nil {
		t.Fatalf("expected success, got %v", callErr)
	}
}

func TestHTTPValidationMiddlewareStrictRejectsMissingAppSessionHeaders(t *testing.T) {
	cfg := HTTPValidationConfig{
		MaxBodyBytes:     1024,
		RequireRequestID: true,
		RequestIDHeader:  "X-Request-ID",
		RequireAppID:     true,
		AppIDHeader:      "X-App-ID",
		RequireSessionID: true,
		SessionHeader:    "X-Session-ID",
	}

	mw, err := HTTPValidationMiddlewareStrict(cfg)
	if err != nil {
		t.Fatalf("strict validation constructor failed: %v", err)
	}

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	req.Header.Set("X-Request-ID", "req-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 when app/session headers missing, got %d", rr.Code)
	}
}

func TestHTTPValidationMiddlewareStrictAcceptsPresentAppSessionHeaders(t *testing.T) {
	cfg := HTTPValidationConfig{
		MaxBodyBytes:     1024,
		RequireRequestID: true,
		RequestIDHeader:  "X-Request-ID",
		RequireAppID:     true,
		AppIDHeader:      "X-App-ID",
		RequireSessionID: true,
		SessionHeader:    "X-Session-ID",
	}

	mw, err := HTTPValidationMiddlewareStrict(cfg)
	if err != nil {
		t.Fatalf("strict validation constructor failed: %v", err)
	}

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if Value(r.Context(), AppIDKey) != "app-1" {
			t.Fatalf("app id not injected")
		}
		if Value(r.Context(), SessionIDKey) != "session-1" {
			t.Fatalf("session id not injected")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	req.Header.Set("X-Request-ID", "req-1")
	req.Header.Set("X-App-ID", "app-1")
	req.Header.Set("X-Session-ID", "session-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", rr.Code)
	}
}

func TestGRPCValidationInterceptorStrictRejectsMissingAppSessionHeaders(t *testing.T) {
	cfg := GRPCValidationConfig{
		MaxRequestBytes:  1024,
		RequireRequestID: true,
		RequestIDHeader:  "x-request-id",
		RequireAppID:     true,
		AppIDHeader:      "x-app-id",
		RequireSessionID: true,
		SessionHeader:    "x-session-id",
	}

	interceptor, err := GRPCValidationInterceptorStrict(cfg)
	if err != nil {
		t.Fatalf("strict grpc validation constructor failed: %v", err)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-request-id", "req-1"))
	_, callErr := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if status.Code(callErr) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", status.Code(callErr))
	}
}

func TestGRPCValidationInterceptorStrictAcceptsPresentAppSessionHeaders(t *testing.T) {
	cfg := GRPCValidationConfig{
		MaxRequestBytes:  1024,
		RequireRequestID: true,
		RequestIDHeader:  "x-request-id",
		RequireAppID:     true,
		AppIDHeader:      "x-app-id",
		RequireSessionID: true,
		SessionHeader:    "x-session-id",
	}

	interceptor, err := GRPCValidationInterceptorStrict(cfg)
	if err != nil {
		t.Fatalf("strict grpc validation constructor failed: %v", err)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-request-id", "req-1",
		"x-app-id", "app-1",
		"x-session-id", "session-1",
	))
	_, callErr := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		if Value(ctx, AppIDKey) != "app-1" {
			return nil, status.Error(codes.Internal, "app id not injected")
		}
		if Value(ctx, SessionIDKey) != "session-1" {
			return nil, status.Error(codes.Internal, "session id not injected")
		}
		return "ok", nil
	})
	if callErr != nil {
		t.Fatalf("expected success, got %v", callErr)
	}
}
