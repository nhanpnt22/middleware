package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestValidateStandardOrder(t *testing.T) {
	if err := ValidateStandardOrder(StandardOrder); err != nil {
		t.Fatalf("expected valid standard order, got error: %v", err)
	}

	broken := append([]string{}, StandardOrder...)
	broken[0], broken[1] = broken[1], broken[0]
	if err := ValidateStandardOrder(broken); err == nil {
		t.Fatalf("expected broken order to fail validation")
	}
}

func TestChainInterceptorsOrder(t *testing.T) {
	order := []string{}
	push := func(name string) grpc.UnaryServerInterceptor {
		return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			order = append(order, name)
			return handler(ctx, req)
		}
	}

	interceptor := ChainInterceptors(push("a"), push("b"), push("c"))
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/svc/method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		order = append(order, "handler")
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"a", "b", "c", "handler"}
	if len(order) != len(want) {
		t.Fatalf("order length mismatch: got %v want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order mismatch at %d: got %q want %q", i, order[i], want[i])
		}
	}
}

func TestHTTPPanicRecoveryMiddleware(t *testing.T) {
	h := HTTPPanicRecoveryMiddleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/panic", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
}

func TestGRPCPanicRecoveryInterceptor(t *testing.T) {
	interceptor := GRPCPanicRecoveryInterceptor()
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Panic"}, func(context.Context, interface{}) (interface{}, error) {
		panic("boom")
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected internal code, got %v", status.Code(err))
	}
}

func TestHTTPTracingMiddleware(t *testing.T) {
	mw := HTTPTracingMiddleware(DefaultTracingConfig())
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if Value(r.Context(), TraceIDKey) == "" {
			t.Fatalf("trace id should be injected")
		}
		if Value(r.Context(), RequestIDKey) != "req-1" {
			t.Fatalf("request id mismatch")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/users/123", nil)
	req.Header.Set("X-Request-ID", "req-1")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status mismatch: got %d", rr.Code)
	}
	if rr.Header().Get("X-Trace-ID") == "" {
		t.Fatalf("expected trace header in response")
	}
}

func TestHTTPAuthenticationMiddleware(t *testing.T) {
	cfg := HTTPAuthConfig{
		Authenticator: StaticTokenAuthenticator{ExpectedToken: "token-1", Identity: Identity{ID: "client-1", Type: "client", Level: "L1"}},
	}
	mw := HTTPAuthenticationMiddleware(cfg)

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IdentityFromContext(r.Context()).ID != "client-1" {
			t.Fatalf("identity not injected")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/resource", nil)
	req.Header.Set("Authorization", "Bearer token-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected success status, got %d", rr.Code)
	}

	badReq := httptest.NewRequest(http.MethodGet, "/v1/resource", nil)
	badReq.Header.Set("Authorization", "Bearer wrong")
	badRR := httptest.NewRecorder()
	h.ServeHTTP(badRR, badReq)
	if badRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", badRR.Code)
	}
}

func TestHTTPAuthenticationMiddleware_DefaultIsFailClosed(t *testing.T) {
	mw := HTTPAuthenticationMiddleware(HTTPAuthConfig{})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/resource", nil)
	req.Header.Set("Authorization", "Bearer token-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rr.Code)
	}
}

func TestFirebaseClaimsAuthenticator(t *testing.T) {
	now := time.Now().Add(5 * time.Minute).Unix()
	auth := FirebaseClaimsAuthenticator{
		Verifier:  stubClaimsVerifier{claims: map[string]interface{}{"iss": "https://securetoken.google.com/p1", "aud": "p1", "uid": "u1", "exp": float64(now), "provider": "email", "session_id": "s1"}},
		ProjectID: "p1",
	}

	identity, err := auth.Authenticate(context.Background(), "token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity.ID != "u1" || identity.Level != "L2" {
		t.Fatalf("unexpected identity: %+v", identity)
	}
}

func TestHTTPAuthorizationMiddleware(t *testing.T) {
	authz := HTTPAuthorizationMiddleware(HTTPAuthorizationConfig{Authorizer: MinLevelAuthorizer{DefaultLevel: "L2"}})

	h := authz(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/resource", nil)
	req = req.WithContext(WithIdentity(req.Context(), Identity{ID: "u1", Level: "L1", Type: "user"}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d", rr.Code)
	}
}

func TestGRPCAuthorizationInterceptor(t *testing.T) {
	interceptor := GRPCAuthorizationInterceptor(GRPCAuthorizationConfig{Authorizer: MinLevelAuthorizer{DefaultLevel: "L2"}})
	ctx := WithIdentity(context.Background(), Identity{ID: "u1", Level: "L1", Type: "user"})
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected permission denied, got %v", status.Code(err))
	}
}
