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

type stubClaimsVerifier struct {
	claims map[string]interface{}
	err    error
}

func (s stubClaimsVerifier) VerifyToken(context.Context, string) (map[string]interface{}, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.claims, nil
}

type stubSessionValidator struct{ err error }

func (s stubSessionValidator) ValidateSession(context.Context, string, string, string, string) error {
	return s.err
}

type stubIdentityValidator struct{ err error }

func (s stubIdentityValidator) ValidateIdentity(context.Context, string, string, string) error {
	return s.err
}

type failingBreaker struct{}

func (failingBreaker) Allow(context.Context, string) error   { return errors.New("open") }
func (failingBreaker) Record(context.Context, string, error) {}

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

func TestHTTPFirebaseAuthMiddleware_Success(t *testing.T) {
	now := time.Now().Add(5 * time.Minute).Unix()
	cfg := FirebaseAuthMiddlewareConfig{
		Verifier: stubClaimsVerifier{claims: map[string]interface{}{
			"iss": "https://securetoken.google.com/p1",
			"aud": "p1",
			"uid": "u1",
			"exp": float64(now),
			"claims": map[string]interface{}{
				"role":        "user",
				"identity_id": "idn1",
				"platform":    "web",
				"device_id":   "dev1",
				"session_id":  "ses1",
				"provider":    "zalo",
			},
		}},
		ProjectID:         "p1",
		SessionValidator:  stubSessionValidator{},
		IdentityValidator: stubIdentityValidator{},
	}

	h := HTTPFirebaseAuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := IdentityFromContext(r.Context())
		if identity.ID != "u1" || identity.Level != "L2" || identity.Type != "user" {
			t.Fatalf("unexpected identity: %+v", identity)
		}
		if Value(r.Context(), ClaimIdentityIDKey) != "idn1" || Value(r.Context(), SessionIDKey) != "ses1" || Value(r.Context(), DeviceIDKey) != "dev1" {
			t.Fatalf("missing strict context claims")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/secure", nil)
	req.Header.Set("Authorization", "Bearer token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected success, got %d", rr.Code)
	}
}

func TestHTTPFirebaseAuthMiddleware_FailsOnExtraClaims(t *testing.T) {
	now := time.Now().Add(5 * time.Minute).Unix()
	cfg := FirebaseAuthMiddlewareConfig{
		Verifier: stubClaimsVerifier{claims: map[string]interface{}{
			"iss": "https://securetoken.google.com/p1",
			"aud": "p1",
			"uid": "u1",
			"exp": float64(now),
			"claims": map[string]interface{}{
				"role":        "user",
				"identity_id": "idn1",
				"platform":    "web",
				"device_id":   "dev1",
				"session_id":  "ses1",
				"provider":    "zalo",
				"extra":       "forbidden",
			},
		}},
		ProjectID:         "p1",
		SessionValidator:  stubSessionValidator{},
		IdentityValidator: stubIdentityValidator{},
	}

	h := HTTPFirebaseAuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/secure", nil)
	req.Header.Set("Authorization", "Bearer token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rr.Code)
	}
}

func TestHTTPFirebaseAuthMiddleware_RejectsIssuerMismatch(t *testing.T) {
	now := time.Now().Add(5 * time.Minute).Unix()
	cfg := FirebaseAuthMiddlewareConfig{
		Verifier: stubClaimsVerifier{claims: map[string]interface{}{
			"iss": "https://securetoken.google.com/p2",
			"aud": "p1",
			"uid": "u1",
			"exp": float64(now),
			"claims": map[string]interface{}{
				"role":        "user",
				"identity_id": "idn1",
				"platform":    "web",
				"device_id":   "dev1",
				"session_id":  "ses1",
				"provider":    "zalo",
			},
		}},
		ProjectID:         "p1",
		SessionValidator:  stubSessionValidator{},
		IdentityValidator: stubIdentityValidator{},
	}

	h := HTTPFirebaseAuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/secure", nil)
	req.Header.Set("Authorization", "Bearer token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rr.Code)
	}
}

func TestHTTPFirebaseAuthMiddleware_RejectsAudienceMismatch(t *testing.T) {
	now := time.Now().Add(5 * time.Minute).Unix()
	cfg := FirebaseAuthMiddlewareConfig{
		Verifier: stubClaimsVerifier{claims: map[string]interface{}{
			"iss": "https://securetoken.google.com/p1",
			"aud": "p2",
			"uid": "u1",
			"exp": float64(now),
			"claims": map[string]interface{}{
				"role":        "user",
				"identity_id": "idn1",
				"platform":    "web",
				"device_id":   "dev1",
				"session_id":  "ses1",
				"provider":    "zalo",
			},
		}},
		ProjectID:         "p1",
		SessionValidator:  stubSessionValidator{},
		IdentityValidator: stubIdentityValidator{},
	}

	h := HTTPFirebaseAuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/secure", nil)
	req.Header.Set("Authorization", "Bearer token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rr.Code)
	}
}

func TestHTTPFirebaseAuthMiddleware_RejectsProviderMismatch(t *testing.T) {
	now := time.Now().Add(5 * time.Minute).Unix()
	cfg := FirebaseAuthMiddlewareConfig{
		Verifier: stubClaimsVerifier{claims: map[string]interface{}{
			"iss": "https://securetoken.google.com/p1",
			"aud": "p1",
			"uid": "u1",
			"exp": float64(now),
			"claims": map[string]interface{}{
				"role":        "user",
				"identity_id": "idn1",
				"platform":    "web",
				"device_id":   "dev1",
				"session_id":  "ses1",
				"provider":    "line",
			},
		}},
		ProjectID:         "p1",
		SessionValidator:  stubSessionValidator{},
		IdentityValidator: stubIdentityValidator{},
	}

	h := HTTPFirebaseAuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/secure", nil)
	req.Header.Set("Authorization", "Bearer token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rr.Code)
	}
}

func TestGRPCFirebaseAuthInterceptor_SessionValidationFailure(t *testing.T) {
	now := time.Now().Add(5 * time.Minute).Unix()
	interceptor := GRPCFirebaseAuthInterceptor(FirebaseAuthMiddlewareConfig{
		Verifier: stubClaimsVerifier{claims: map[string]interface{}{
			"iss": "https://securetoken.google.com/p1",
			"aud": "p1",
			"uid": "u1",
			"exp": float64(now),
			"claims": map[string]interface{}{
				"role":        "user",
				"identity_id": "idn1",
				"platform":    "web",
				"device_id":   "dev1",
				"session_id":  "ses1",
				"provider":    "whatsapp",
			},
		}},
		ProjectID:         "p1",
		SessionValidator:  stubSessionValidator{err: errors.New("not active")},
		IdentityValidator: stubIdentityValidator{},
	})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer token"))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", status.Code(err))
	}
}

func TestGRPCFirebaseAuthInterceptor_IdentityValidationFailure(t *testing.T) {
	now := time.Now().Add(5 * time.Minute).Unix()
	interceptor := GRPCFirebaseAuthInterceptor(FirebaseAuthMiddlewareConfig{
		Verifier: stubClaimsVerifier{claims: map[string]interface{}{
			"iss": "https://securetoken.google.com/p1",
			"aud": "p1",
			"uid": "u1",
			"exp": float64(now),
			"claims": map[string]interface{}{
				"role":        "user",
				"identity_id": "idn1",
				"platform":    "web",
				"device_id":   "dev1",
				"session_id":  "ses1",
				"provider":    "whatsapp",
			},
		}},
		ProjectID:         "p1",
		SessionValidator:  stubSessionValidator{},
		IdentityValidator: stubIdentityValidator{err: errors.New("identity mismatch")},
	})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer token"))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", status.Code(err))
	}
}

func TestHTTPFirebaseAuthMiddleware_RejectsMissingUIDEvenWithSub(t *testing.T) {
	now := time.Now().Add(5 * time.Minute).Unix()
	cfg := FirebaseAuthMiddlewareConfig{
		Verifier: stubClaimsVerifier{claims: map[string]interface{}{
			"iss": "https://securetoken.google.com/p1",
			"aud": "p1",
			"sub": "u1",
			"exp": float64(now),
			"claims": map[string]interface{}{
				"role":        "user",
				"identity_id": "idn1",
				"platform":    "web",
				"device_id":   "dev1",
				"session_id":  "ses1",
				"provider":    "zalo",
			},
		}},
		ProjectID:         "p1",
		SessionValidator:  stubSessionValidator{},
		IdentityValidator: stubIdentityValidator{},
	}

	h := HTTPFirebaseAuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/secure", nil)
	req.Header.Set("Authorization", "Bearer token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rr.Code)
	}
}
