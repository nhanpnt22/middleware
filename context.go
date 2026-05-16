package middleware

import "context"

const MiddlewareVersion = "v0.1.0"

type ContextKey string

const (
	TraceIDKey           ContextKey = "trace-id"
	RequestIDKey         ContextKey = "request-id"
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

type Identity struct {
	ID        string
	Type      string
	Level     string
	Provider  string
	SessionID string
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
