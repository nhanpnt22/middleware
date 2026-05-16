package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var ErrUnauthorized = errors.New("unauthorized")

type ErrorResponse struct {
	Code      string `json:"code"`
	Type      string `json:"type"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type Authenticator interface {
	Authenticate(ctx context.Context, bearerToken string) (Identity, error)
}

type rejectingAuthenticator struct{}

func (rejectingAuthenticator) Authenticate(context.Context, string) (Identity, error) {
	return Identity{}, ErrUnauthorized
}

type StaticTokenAuthenticator struct {
	ExpectedToken string
	Identity      Identity
}

func (a StaticTokenAuthenticator) Authenticate(_ context.Context, bearerToken string) (Identity, error) {
	if strings.TrimSpace(a.ExpectedToken) == "" {
		return Identity{}, ErrUnauthorized
	}
	if bearerToken != strings.TrimSpace(a.ExpectedToken) {
		return Identity{}, ErrUnauthorized
	}
	identity := a.Identity
	if identity.Type == "" {
		identity.Type = "client"
	}
	if identity.Level == "" {
		identity.Level = "L1"
	}
	if identity.ID == "" {
		identity.ID = "configured-client"
	}
	return identity, nil
}

// TokenClaimsVerifier should verify token integrity and return claims when valid.
// The implementation can use Firebase Admin SDK or any equivalent verifier.
type TokenClaimsVerifier interface {
	VerifyToken(ctx context.Context, bearerToken string) (map[string]interface{}, error)
}

type SessionBindingValidator interface {
	ValidateSession(ctx context.Context, sessionID, userID, deviceID, provider string) error
}

type IdentityBindingValidator interface {
	ValidateIdentity(ctx context.Context, identityID, userID, provider string) error
}

type FirebaseAuthMiddlewareConfig struct {
	Verifier          TokenClaimsVerifier
	ProjectID         string
	SessionValidator  SessionBindingValidator
	IdentityValidator IdentityBindingValidator
}

type aipVerifiedIdentity struct {
	UID        string
	IdentityID string
	SessionID  string
	DeviceID   string
	Provider   string
}

type FirebaseClaimsAuthenticator struct {
	Verifier  TokenClaimsVerifier
	ProjectID string
}

func (a FirebaseClaimsAuthenticator) Authenticate(ctx context.Context, bearerToken string) (Identity, error) {
	if a.Verifier == nil || strings.TrimSpace(a.ProjectID) == "" {
		return Identity{}, ErrUnauthorized
	}

	claims, err := a.Verifier.VerifyToken(ctx, bearerToken)
	if err != nil {
		return Identity{}, ErrUnauthorized
	}

	iss, _ := claims["iss"].(string)
	aud, _ := claims["aud"].(string)
	uid, _ := claims["uid"].(string)
	if strings.TrimSpace(uid) == "" {
		if sub, _ := claims["sub"].(string); strings.TrimSpace(sub) != "" {
			uid = sub
		}
	}

	expectedIss := "https://securetoken.google.com/" + strings.TrimSpace(a.ProjectID)
	if strings.TrimSpace(iss) != expectedIss || strings.TrimSpace(aud) != strings.TrimSpace(a.ProjectID) || strings.TrimSpace(uid) == "" {
		return Identity{}, ErrUnauthorized
	}

	if !isExpValid(claims["exp"], time.Now().Unix()) {
		return Identity{}, ErrUnauthorized
	}

	identity := Identity{
		ID:        uid,
		Type:      "user",
		Level:     "L2",
		Provider:  stringClaim(claims, "provider"),
		SessionID: stringClaim(claims, "session_id"),
	}

	if identity.Provider == "" {
		if provider, ok := nestedStringClaim(claims, "claims", "provider"); ok {
			identity.Provider = provider
		}
	}
	if identity.SessionID == "" {
		if sessionID, ok := nestedStringClaim(claims, "claims", "session_id"); ok {
			identity.SessionID = sessionID
		}
	}

	return identity, nil
}

type Authorizer interface {
	Authorize(ctx context.Context, identity Identity, endpoint string) error
}

type MinLevelAuthorizer struct {
	DefaultLevel string
	MethodLevels map[string]string
}

func (a MinLevelAuthorizer) Authorize(_ context.Context, identity Identity, endpoint string) error {
	required := strings.ToUpper(strings.TrimSpace(a.DefaultLevel))
	if required == "" {
		required = "L0"
	}
	if lvl, ok := a.MethodLevels[endpoint]; ok {
		required = strings.ToUpper(strings.TrimSpace(lvl))
	}
	if levelRank(identity.Level) < levelRank(required) {
		return ErrUnauthorized
	}
	return nil
}

type HTTPAuthConfig struct {
	Authenticator      Authenticator
	AllowAnonymous     func(r *http.Request) bool
	RequireAPIKey      bool
	APIKeyHeader       string
	ExpectedAPIKey     string
	IdentityHeaderHint string
}

type GRPCAuthConfig struct {
	Authenticator      Authenticator
	AllowAnonymous     func(fullMethod string) bool
	RequireAPIKey      bool
	APIKeyHeader       string
	ExpectedAPIKey     string
	IdentityHeaderHint string
}

type HTTPAuthorizationConfig struct {
	Authorizer Authorizer
}

type GRPCAuthorizationConfig struct {
	Authorizer Authorizer
}

func HTTPAuthenticationMiddleware(cfg HTTPAuthConfig) func(http.Handler) http.Handler {
	cfg = resolveHTTPAuthConfig(cfg)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.AllowAnonymous(r) {
				next.ServeHTTP(w, r)
				return
			}
			if cfg.RequireAPIKey {
				apiKey := strings.TrimSpace(r.Header.Get(cfg.APIKeyHeader))
				if apiKey == "" || (cfg.ExpectedAPIKey != "" && apiKey != cfg.ExpectedAPIKey) {
					writeHTTPAuthError(w)
					return
				}
			}
			token, ok := parseBearerToken(r.Header.Get("Authorization"))
			if !ok {
				writeHTTPAuthError(w)
				return
			}
			identity, err := cfg.Authenticator.Authenticate(r.Context(), token)
			if err != nil {
				writeHTTPAuthError(w)
				return
			}
			ctx := WithIdentity(r.Context(), identity)
			if cfg.IdentityHeaderHint != "" {
				ctx = WithValueIfAbsent(ctx, IdentityTypeKey, cfg.IdentityHeaderHint)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GRPCAuthenticationInterceptor(cfg GRPCAuthConfig) grpc.UnaryServerInterceptor {
	cfg = resolveGRPCAuthConfig(cfg)
	apiKeyHeader := strings.ToLower(cfg.APIKeyHeader)
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if cfg.AllowAnonymous(info.FullMethod) {
			return handler(ctx, req)
		}
		md, _ := metadata.FromIncomingContext(ctx)
		if cfg.RequireAPIKey {
			apiKey := first(md.Get(apiKeyHeader))
			if apiKey == "" || (cfg.ExpectedAPIKey != "" && apiKey != cfg.ExpectedAPIKey) {
				return nil, status.Error(codes.Unauthenticated, "invalid api key")
			}
		}
		token, ok := parseBearerToken(first(md.Get("authorization")))
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "authorization is required")
		}
		identity, err := cfg.Authenticator.Authenticate(ctx, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		ctx = WithIdentity(ctx, identity)
		if cfg.IdentityHeaderHint != "" {
			ctx = WithValueIfAbsent(ctx, IdentityTypeKey, cfg.IdentityHeaderHint)
		}
		return handler(ctx, req)
	}
}

// HTTPFirebaseAuthMiddleware enforces the AIP Firebase authentication contract (L2).
func HTTPFirebaseAuthMiddleware(cfg FirebaseAuthMiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := parseBearerToken(r.Header.Get("Authorization"))
			if !ok {
				writeHTTPUnauthenticatedUser(w)
				return
			}

			verified, err := verifyAIPFirebaseIdentity(r.Context(), cfg, token)
			if err != nil {
				writeHTTPUnauthenticatedUser(w)
				return
			}

			ctx := r.Context()
			ctx = WithValue(ctx, IdentityKey, verified.UID)
			ctx = WithValue(ctx, IdentityIDKey, verified.UID)
			ctx = WithValue(ctx, IdentityTypeKey, "user")
			ctx = WithValue(ctx, IdentityLevelKey, "L2")
			ctx = WithValue(ctx, ClaimIdentityIDKey, verified.IdentityID)
			ctx = WithValue(ctx, SessionIDKey, verified.SessionID)
			ctx = WithValue(ctx, DeviceIDKey, verified.DeviceID)
			ctx = WithValue(ctx, IdentityProviderKey, verified.Provider)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GRPCFirebaseAuthInterceptor enforces the AIP Firebase authentication contract (L2).
func GRPCFirebaseAuthInterceptor(cfg FirebaseAuthMiddlewareConfig) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		_ = info
		md, _ := metadata.FromIncomingContext(ctx)
		token, ok := parseBearerToken(first(md.Get("authorization")))
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "unauthenticated")
		}

		verified, err := verifyAIPFirebaseIdentity(ctx, cfg, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "unauthenticated")
		}

		ctx = WithValue(ctx, IdentityKey, verified.UID)
		ctx = WithValue(ctx, IdentityIDKey, verified.UID)
		ctx = WithValue(ctx, IdentityTypeKey, "user")
		ctx = WithValue(ctx, IdentityLevelKey, "L2")
		ctx = WithValue(ctx, ClaimIdentityIDKey, verified.IdentityID)
		ctx = WithValue(ctx, SessionIDKey, verified.SessionID)
		ctx = WithValue(ctx, DeviceIDKey, verified.DeviceID)
		ctx = WithValue(ctx, IdentityProviderKey, verified.Provider)

		return handler(ctx, req)
	}
}

func HTTPAuthorizationMiddleware(cfg HTTPAuthorizationConfig) func(http.Handler) http.Handler {
	if cfg.Authorizer == nil {
		cfg.Authorizer = MinLevelAuthorizer{DefaultLevel: "L0"}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity := IdentityFromContext(r.Context())
			if err := cfg.Authorizer.Authorize(r.Context(), identity, r.URL.Path); err != nil {
				writeHTTPForbidden(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func GRPCAuthorizationInterceptor(cfg GRPCAuthorizationConfig) grpc.UnaryServerInterceptor {
	if cfg.Authorizer == nil {
		cfg.Authorizer = MinLevelAuthorizer{DefaultLevel: "L0"}
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		identity := IdentityFromContext(ctx)
		if err := cfg.Authorizer.Authorize(ctx, identity, info.FullMethod); err != nil {
			return nil, status.Error(codes.PermissionDenied, "forbidden")
		}
		return handler(ctx, req)
	}
}

func resolveHTTPAuthConfig(cfg HTTPAuthConfig) HTTPAuthConfig {
	if cfg.Authenticator == nil {
		cfg.Authenticator = rejectingAuthenticator{}
	}
	if cfg.AllowAnonymous == nil {
		cfg.AllowAnonymous = func(*http.Request) bool { return false }
	}
	if strings.TrimSpace(cfg.APIKeyHeader) == "" {
		cfg.APIKeyHeader = "X-API-Key"
	}
	return cfg
}

func resolveGRPCAuthConfig(cfg GRPCAuthConfig) GRPCAuthConfig {
	if cfg.Authenticator == nil {
		cfg.Authenticator = rejectingAuthenticator{}
	}
	if cfg.AllowAnonymous == nil {
		cfg.AllowAnonymous = func(string) bool { return false }
	}
	if strings.TrimSpace(cfg.APIKeyHeader) == "" {
		cfg.APIKeyHeader = "x-api-key"
	}
	return cfg
}

func parseBearerToken(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}
	if len(header) < len("Bearer ") || !strings.EqualFold(header[:len("Bearer ")], "Bearer ") {
		return "", false
	}
	token := strings.TrimSpace(header[len("Bearer "):])
	if token == "" {
		return "", false
	}
	return token, true
}

func writeHTTPAuthError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Code: "AUTH_INVALID_TOKEN", Type: "client", Message: "authentication failed", Retryable: false})
}

func writeHTTPUnauthenticatedUser(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Code: "UNAUTHENTICATED", Type: "user", Message: "unauthenticated", Retryable: false})
}

func writeHTTPForbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Code: "FORBIDDEN", Type: "user", Message: "forbidden", Retryable: false})
}

func verifyAIPFirebaseIdentity(ctx context.Context, cfg FirebaseAuthMiddlewareConfig, bearerToken string) (aipVerifiedIdentity, error) {
	if cfg.Verifier == nil || strings.TrimSpace(cfg.ProjectID) == "" || cfg.SessionValidator == nil || cfg.IdentityValidator == nil {
		return aipVerifiedIdentity{}, ErrUnauthorized
	}

	claims, err := cfg.Verifier.VerifyToken(ctx, bearerToken)
	if err != nil {
		return aipVerifiedIdentity{}, ErrUnauthorized
	}

	uid := stringClaim(claims, "uid")
	if uid == "" {
		return aipVerifiedIdentity{}, ErrUnauthorized
	}

	iss := stringClaim(claims, "iss")
	aud := stringClaim(claims, "aud")
	expectedIss := "https://securetoken.google.com/" + strings.TrimSpace(cfg.ProjectID)
	if iss != expectedIss || aud != strings.TrimSpace(cfg.ProjectID) {
		return aipVerifiedIdentity{}, ErrUnauthorized
	}

	if !isExpValid(claims["exp"], time.Now().Unix()) {
		return aipVerifiedIdentity{}, ErrUnauthorized
	}

	aipClaims, err := extractAndValidateAIPClaims(claims)
	if err != nil {
		return aipVerifiedIdentity{}, ErrUnauthorized
	}

	if err := cfg.SessionValidator.ValidateSession(ctx, aipClaims.SessionID, uid, aipClaims.DeviceID, aipClaims.Provider); err != nil {
		return aipVerifiedIdentity{}, ErrUnauthorized
	}
	if err := cfg.IdentityValidator.ValidateIdentity(ctx, aipClaims.IdentityID, uid, aipClaims.Provider); err != nil {
		return aipVerifiedIdentity{}, ErrUnauthorized
	}

	return aipVerifiedIdentity{
		UID:        uid,
		IdentityID: aipClaims.IdentityID,
		SessionID:  aipClaims.SessionID,
		DeviceID:   aipClaims.DeviceID,
		Provider:   aipClaims.Provider,
	}, nil
}

func extractAndValidateAIPClaims(claims map[string]interface{}) (aipVerifiedIdentity, error) {
	custom, ok := claims["claims"].(map[string]interface{})
	if !ok {
		custom = map[string]interface{}{}
		for _, key := range []string{"role", "identity_id", "platform", "device_id", "session_id", "provider"} {
			if _, exists := claims[key]; exists {
				custom[key] = claims[key]
			}
		}
	}

	allowed := map[string]struct{}{
		"role": {}, "identity_id": {}, "platform": {}, "device_id": {}, "session_id": {}, "provider": {},
	}
	for key := range custom {
		if _, ok := allowed[key]; !ok {
			return aipVerifiedIdentity{}, ErrUnauthorized
		}
	}

	role := stringClaim(custom, "role")
	identityID := stringClaim(custom, "identity_id")
	platform := stringClaim(custom, "platform")
	deviceID := stringClaim(custom, "device_id")
	sessionID := stringClaim(custom, "session_id")
	provider := stringClaim(custom, "provider")

	if role != "user" || platform != "web" || identityID == "" || deviceID == "" || sessionID == "" {
		return aipVerifiedIdentity{}, ErrUnauthorized
	}
	if provider != "zalo" && provider != "whatsapp" {
		return aipVerifiedIdentity{}, ErrUnauthorized
	}

	return aipVerifiedIdentity{IdentityID: identityID, SessionID: sessionID, DeviceID: deviceID, Provider: provider}, nil
}

func levelRank(level string) int {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "L0":
		return 0
	case "L1":
		return 1
	case "L2":
		return 2
	case "L3":
		return 3
	case "L4":
		return 4
	default:
		return -1
	}
}

func stringClaim(claims map[string]interface{}, key string) string {
	v, _ := claims[key].(string)
	return strings.TrimSpace(v)
}

func nestedStringClaim(claims map[string]interface{}, parent, child string) (string, bool) {
	raw, ok := claims[parent]
	if !ok {
		return "", false
	}
	obj, ok := raw.(map[string]interface{})
	if !ok {
		return "", false
	}
	v, ok := obj[child].(string)
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	return v, v != ""
}

func isExpValid(raw interface{}, nowUnix int64) bool {
	switch v := raw.(type) {
	case int64:
		return v > nowUnix
	case int:
		return int64(v) > nowUnix
	case float64:
		return int64(v) > nowUnix
	case json.Number:
		n, err := v.Int64()
		return err == nil && n > nowUnix
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return err == nil && n > nowUnix
	default:
		_ = fmt.Sprintf("%T", raw)
		return false
	}
}
