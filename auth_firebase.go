package middleware

import (
	"context"
	"net/http"
	"strings"

	aipfirebasepkg "github.com/nhanpnt22/middleware/aipfirebase"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Authenticate implements the Authenticator interface for FirebaseClaimsAuthenticator.
// It verifies the JWT issuer, audience, uid, and expiry against the configured project.
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

	if !isExpValid(claims["exp"], currentUnix(a.NowUnix)) {
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

// HTTPFirebaseAuthMiddleware applies Firebase user authentication with bound-identity checks.
func HTTPFirebaseAuthMiddleware(cfg FirebaseAuthMiddlewareConfig) func(http.Handler) http.Handler {
	return httpFirebaseAuthMiddleware(cfg)
}

// HTTPFirebaseAuthMiddlewareStrict builds strict Firebase HTTP middleware and validates config fail-fast.
func HTTPFirebaseAuthMiddlewareStrict(cfg FirebaseAuthMiddlewareConfig) (func(http.Handler) http.Handler, error) {
	if err := ValidateFirebaseAuthMiddlewareConfigStrict(cfg); err != nil {
		return nil, err
	}
	return httpFirebaseAuthMiddleware(cfg), nil
}

func httpFirebaseAuthMiddleware(cfg FirebaseAuthMiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := parseBearerToken(r.Header.Get("Authorization"))
			if !ok {
				writeHTTPUnauthenticatedUser(w)
				return
			}
			verified, err := verifyFirebaseBoundIdentity(r.Context(), cfg, token)
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

// GRPCFirebaseAuthInterceptor applies Firebase user authentication with bound-identity checks.
func GRPCFirebaseAuthInterceptor(cfg FirebaseAuthMiddlewareConfig) grpc.UnaryServerInterceptor {
	return grpcFirebaseAuthInterceptor(cfg)
}

// GRPCFirebaseAuthInterceptorStrict builds strict Firebase gRPC interceptor and validates config fail-fast.
func GRPCFirebaseAuthInterceptorStrict(cfg FirebaseAuthMiddlewareConfig) (grpc.UnaryServerInterceptor, error) {
	if err := ValidateFirebaseAuthMiddlewareConfigStrict(cfg); err != nil {
		return nil, err
	}
	return grpcFirebaseAuthInterceptor(cfg), nil
}

func grpcFirebaseAuthInterceptor(cfg FirebaseAuthMiddlewareConfig) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		_ = info
		md, _ := metadata.FromIncomingContext(ctx)
		token, ok := parseBearerToken(first(md.Get("authorization")))
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "unauthenticated")
		}
		verified, err := verifyFirebaseBoundIdentity(ctx, cfg, token)
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

func verifyFirebaseBoundIdentity(ctx context.Context, cfg FirebaseAuthMiddlewareConfig, bearerToken string) (firebaseVerifiedIdentity, error) {
	verified, err := aipfirebasepkg.VerifyIdentity(ctx, aipfirebasepkg.Config{
		Verifier:          cfg.Verifier,
		ProjectID:         cfg.ProjectID,
		SessionValidator:  cfg.SessionValidator,
		IdentityValidator: cfg.IdentityValidator,
		NowUnix:           cfg.NowUnix,
		RequiredRole:      cfg.RequiredRole,
		RequiredPlatform:  cfg.RequiredPlatform,
		AllowedProviders:  cfg.AllowedProviders,
	}, bearerToken)
	if err != nil {
		return firebaseVerifiedIdentity{}, ErrUnauthorized
	}

	return firebaseVerifiedIdentity{
		UID:        verified.UID,
		IdentityID: verified.IdentityID,
		SessionID:  verified.SessionID,
		DeviceID:   verified.DeviceID,
		Provider:   verified.Provider,
	}, nil
}
