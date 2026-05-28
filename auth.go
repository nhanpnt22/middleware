package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

const MiddlewareVersion = "v0.1.0"

type ContextKey string

const (
	TraceIDKey           ContextKey = "trace-id"
	RequestIDKey         ContextKey = "request-id"
	AppIDKey             ContextKey = "app-id"
	IdentityKey          ContextKey = "identity"
	IdentityIDKey        ContextKey = "identity.id"
	ClaimIdentityIDKey   ContextKey = "identity_id"
	IdentityTypeKey      ContextKey = "identity.type"
	IdentityLevelKey     ContextKey = "identity.level"
	IdentityProviderKey  ContextKey = "identity.provider"
	DeviceIDKey          ContextKey = "device-id"
	SessionIDKey         ContextKey = "identity.session-id"
	IdempotencyKeyKey    ContextKey = "idempotency-key"
	MiddlewareVersionKey ContextKey = "middleware-version"
)

var ErrUnauthorized = errors.New("unauthorized")

type Identity struct {
	ID        string
	Type      string
	Level     string
	Provider  string
	SessionID string
}

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
	NowUnix           func() int64
	RequiredRole      string
	RequiredPlatform  string
	AllowedProviders  map[string]struct{}
}

type firebaseVerifiedIdentity struct {
	UID        string
	IdentityID string
	SessionID  string
	DeviceID   string
	Provider   string
}

type FirebaseClaimsAuthenticator struct {
	Verifier  TokenClaimsVerifier
	ProjectID string
	NowUnix   func() int64
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

type HTTPAuthXORConfig struct {
	AuthorizationHeader string
	APIKeyHeader        string
	RequireAuth         bool
	AllowAnonymous      func(r *http.Request) bool
}

type GRPCAuthXORConfig struct {
	AuthorizationHeader string
	APIKeyHeader        string
	RequireAuth         bool
	AllowAnonymous      func(fullMethod string) bool
}

type HTTPAuthorizationConfig struct {
	Authorizer Authorizer
}

type GRPCAuthorizationConfig struct {
	Authorizer Authorizer
}

func apiKeyIdentity(identityTypeHint string) Identity {
	identityType := strings.TrimSpace(identityTypeHint)
	if identityType == "" {
		identityType = "client"
	}
	return Identity{ID: "api-key-client", Type: identityType, Level: "L1"}
}

func WithValue(ctx context.Context, key ContextKey, value string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, key, value)
}

func WithValueIfAbsent(ctx context.Context, key ContextKey, value string) context.Context {
	if Value(ctx, key) != "" {
		return ctx
	}
	return WithValue(ctx, key, value)
}

func Value(ctx context.Context, key ContextKey) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(key).(string)
	return v
}

func WithIdentity(ctx context.Context, identity Identity) context.Context {
	ctx = WithValueIfAbsent(ctx, IdentityKey, identity.ID)
	ctx = WithValueIfAbsent(ctx, IdentityIDKey, identity.ID)
	ctx = WithValueIfAbsent(ctx, IdentityTypeKey, identity.Type)
	ctx = WithValueIfAbsent(ctx, IdentityLevelKey, identity.Level)
	ctx = WithValueIfAbsent(ctx, IdentityProviderKey, identity.Provider)
	ctx = WithValueIfAbsent(ctx, SessionIDKey, identity.SessionID)
	return ctx
}

func IdentityFromContext(ctx context.Context) Identity {
	return Identity{
		ID:        Value(ctx, IdentityIDKey),
		Type:      Value(ctx, IdentityTypeKey),
		Level:     Value(ctx, IdentityLevelKey),
		Provider:  Value(ctx, IdentityProviderKey),
		SessionID: Value(ctx, SessionIDKey),
	}
}
