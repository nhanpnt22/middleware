package middleware

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GRPCAuthenticationInterceptor enforces bearer-token or API-key authentication on gRPC handlers.
// Implicit defaults are applied: nil Authenticator rejects all; nil AllowAnonymous denies all.
func GRPCAuthenticationInterceptor(cfg GRPCAuthConfig) grpc.UnaryServerInterceptor {
	cfg = resolveGRPCAuthConfig(cfg)
	return grpcAuthenticationInterceptor(cfg)
}

// GRPCAuthenticationInterceptorStrict builds an authentication interceptor without implicit defaults.
// Returns an error at construction time if the configuration is invalid.
func GRPCAuthenticationInterceptorStrict(cfg GRPCAuthConfig) (grpc.UnaryServerInterceptor, error) {
	if err := ValidateGRPCAuthConfigStrict(cfg); err != nil {
		return nil, err
	}
	return grpcAuthenticationInterceptor(cfg), nil
}

func grpcAuthenticationInterceptor(cfg GRPCAuthConfig) grpc.UnaryServerInterceptor {
	apiKeyHeader := strings.ToLower(cfg.APIKeyHeader)
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if cfg.AllowAnonymous(info.FullMethod) {
			return handler(ctx, req)
		}

		md, _ := metadata.FromIncomingContext(ctx)
		apiKeyPresent, apiKeyValid := validateGRPCAPIKey(md, cfg, apiKeyHeader)
		if (apiKeyPresent && !apiKeyValid) || (cfg.RequireAPIKey && !apiKeyValid) {
			return nil, status.Error(codes.Unauthenticated, "invalid api key")
		}

		authenticatedCtx, ok := buildAuthenticatedGRPCContext(ctx, md, cfg, apiKeyPresent, apiKeyValid)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "authorization is required")
		}

		return handler(authenticatedCtx, req)
	}
}

func validateGRPCAPIKey(md metadata.MD, cfg GRPCAuthConfig, apiKeyHeader string) (bool, bool) {
	if strings.TrimSpace(apiKeyHeader) == "" {
		return false, !cfg.RequireAPIKey
	}

	apiKey := first(md.Get(apiKeyHeader))
	if apiKey == "" {
		return false, !cfg.RequireAPIKey
	}
	if cfg.ExpectedAPIKey != "" && apiKey != cfg.ExpectedAPIKey {
		return true, false
	}

	return true, true
}

func buildAuthenticatedGRPCContext(ctx context.Context, md metadata.MD, cfg GRPCAuthConfig, apiKeyPresent bool, apiKeyValid bool) (context.Context, bool) {
	token, ok := parseBearerToken(first(md.Get("authorization")))
	if ok {
		identity, err := cfg.Authenticator.Authenticate(ctx, token)
		if err != nil {
			return nil, false
		}

		authCtx := WithIdentity(ctx, identity)
		if cfg.IdentityHeaderHint != "" {
			authCtx = WithValueIfAbsent(authCtx, IdentityTypeKey, cfg.IdentityHeaderHint)
		}

		return authCtx, true
	}

	if !isGRPCAPIKeyAuthConfigured(cfg) || !apiKeyPresent || !apiKeyValid {
		return nil, false
	}

	return WithIdentity(ctx, apiKeyIdentity(cfg.IdentityHeaderHint)), true
}

func isGRPCAPIKeyAuthConfigured(cfg GRPCAuthConfig) bool {
	return cfg.RequireAPIKey || strings.TrimSpace(cfg.ExpectedAPIKey) != ""
}

// GRPCAuthorizationInterceptor enforces minimum identity level on gRPC handlers.
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

// resolveGRPCAuthConfig applies implicit defaults to a GRPCAuthConfig.
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
