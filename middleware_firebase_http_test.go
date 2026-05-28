package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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

func TestHTTPFirebaseAuthMiddleware_CustomPolicySuccess(t *testing.T) {
	now := time.Now().Add(5 * time.Minute).Unix()
	cfg := FirebaseAuthMiddlewareConfig{
		Verifier: stubClaimsVerifier{claims: map[string]interface{}{
			"iss": "https://securetoken.google.com/p1",
			"aud": "p1",
			"uid": "u1",
			"exp": float64(now),
			"claims": map[string]interface{}{
				"role":        "admin",
				"identity_id": "idn1",
				"platform":    "mobile",
				"device_id":   "dev1",
				"session_id":  "ses1",
				"provider":    "line",
			},
		}},
		ProjectID:         "p1",
		SessionValidator:  stubSessionValidator{},
		IdentityValidator: stubIdentityValidator{},
		RequiredRole:      "admin",
		RequiredPlatform:  "mobile",
		AllowedProviders: map[string]struct{}{
			"line": {},
		},
	}

	h := HTTPFirebaseAuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/secure", nil)
	req.Header.Set("Authorization", "Bearer token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected success with custom policy, got %d", rr.Code)
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
