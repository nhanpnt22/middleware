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

func TestHTTPAuthXORGuardMiddleware(t *testing.T) {
	mw := HTTPAuthXORGuardMiddleware(HTTPAuthXORConfig{
		APIKeyHeader:        "X-API-Key",
		AuthorizationHeader: "Authorization",
		RequireAuth:         true,
	})

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	cases := []struct {
		name       string
		apiKey     string
		authHeader string
		wantStatus int
	}{
		{name: "missing both", wantStatus: http.StatusUnauthorized},
		{name: "api key only", apiKey: "k1", wantStatus: http.StatusNoContent},
		{name: "auth only", authHeader: "Bearer token", wantStatus: http.StatusNoContent},
		{name: "both present", apiKey: "k1", authHeader: "Bearer token", wantStatus: http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/protected", nil)
			if tc.apiKey != "" {
				req.Header.Set("X-API-Key", tc.apiKey)
			}
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status mismatch: got %d want %d", rr.Code, tc.wantStatus)
			}
		})
	}
}

func TestHTTPAuthXORGuardMiddleware_AllowAnonymousBypass(t *testing.T) {
	mw := HTTPAuthXORGuardMiddleware(HTTPAuthXORConfig{
		AllowAnonymous: func(r *http.Request) bool {
			return r.URL.Path == "/healthz"
		},
		APIKeyHeader:        "X-API-Key",
		AuthorizationHeader: "Authorization",
		RequireAuth:         true,
	})

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected bypass status %d, got %d", http.StatusNoContent, rr.Code)
	}
}

func TestGRPCAuthXORGuardInterceptor(t *testing.T) {
	interceptor := GRPCAuthXORGuardInterceptor(GRPCAuthXORConfig{
		APIKeyHeader:        "x-api-key",
		AuthorizationHeader: "authorization",
		RequireAuth:         true,
	})

	cases := []struct {
		name    string
		mdPairs []string
		want    codes.Code
	}{
		{name: "missing both", mdPairs: nil, want: codes.Unauthenticated},
		{name: "api key only", mdPairs: []string{"x-api-key", "k1"}, want: codes.OK},
		{name: "auth only", mdPairs: []string{"authorization", "Bearer token"}, want: codes.OK},
		{name: "both present", mdPairs: []string{"x-api-key", "k1", "authorization", "Bearer token"}, want: codes.InvalidArgument},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if len(tc.mdPairs) > 0 {
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(tc.mdPairs...))
			}
			_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc.Method/Create"}, func(ctx context.Context, req interface{}) (interface{}, error) {
				return "ok", nil
			})
			if status.Code(err) != tc.want {
				t.Fatalf("code mismatch: got %v want %v", status.Code(err), tc.want)
			}
		})
	}
}

func TestGRPCAuthXORGuardInterceptor_AllowAnonymousBypass(t *testing.T) {
	interceptor := GRPCAuthXORGuardInterceptor(GRPCAuthXORConfig{
		AllowAnonymous: func(method string) bool {
			return method == "/health.Check"
		},
		APIKeyHeader:        "x-api-key",
		AuthorizationHeader: "authorization",
		RequireAuth:         true,
	})

	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/health.Check"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("expected anonymous bypass, got %v", err)
	}
}
