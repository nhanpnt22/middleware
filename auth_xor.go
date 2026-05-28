package middleware

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	authXORMutuallyExclusiveMessage = "authorization and x-api-key are mutually exclusive"
	missingAuthorizationMetadataMsg = "missing authorization metadata"

	defaultHTTPAuthorizationHeader = "Authorization"
	defaultHTTPAPIKeyHeader        = "X-API-Key"
	defaultGRPCAuthorizationHeader = "authorization"
	defaultGRPCAPIKeyHeader        = "x-api-key"

	unauthenticatedErrorCode = "UNAUTHENTICATED"
)

// HTTPAuthXORGuardMiddleware enforces CEP auth metadata exclusivity (authorization xor x-api-key).
func HTTPAuthXORGuardMiddleware(cfg HTTPAuthXORConfig) func(http.Handler) http.Handler {
	cfg = resolveHTTPAuthXORConfig(cfg)
	return httpAuthXORGuardMiddleware(cfg)
}

// HTTPAuthXORGuardMiddlewareStrict builds middleware without implicit defaults.
func HTTPAuthXORGuardMiddlewareStrict(cfg HTTPAuthXORConfig) (func(http.Handler) http.Handler, error) {
	if err := ValidateHTTPAuthXORConfigStrict(cfg); err != nil {
		return nil, err
	}
	return httpAuthXORGuardMiddleware(cfg), nil
}

func httpAuthXORGuardMiddleware(cfg HTTPAuthXORConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.AllowAnonymous(r) {
				next.ServeHTTP(w, r)
				return
			}

			hasAuthorization := strings.TrimSpace(r.Header.Get(cfg.AuthorizationHeader)) != ""
			hasAPIKey := strings.TrimSpace(r.Header.Get(cfg.APIKeyHeader)) != ""
			if hasAuthorization && hasAPIKey {
				writeValidationError(w, http.StatusBadRequest, validationErrorCode, authXORMutuallyExclusiveMessage)
				return
			}
			if cfg.RequireAuth && !hasAuthorization && !hasAPIKey {
				writeValidationError(w, http.StatusUnauthorized, unauthenticatedErrorCode, missingAuthorizationMetadataMsg)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func resolveHTTPAuthXORConfig(cfg HTTPAuthXORConfig) HTTPAuthXORConfig {
	if strings.TrimSpace(cfg.AuthorizationHeader) == "" {
		cfg.AuthorizationHeader = defaultHTTPAuthorizationHeader
	}
	if strings.TrimSpace(cfg.APIKeyHeader) == "" {
		cfg.APIKeyHeader = defaultHTTPAPIKeyHeader
	}
	if cfg.AllowAnonymous == nil {
		cfg.AllowAnonymous = func(*http.Request) bool { return false }
	}
	return cfg
}

// GRPCAuthXORGuardInterceptor enforces CEP auth metadata exclusivity (authorization xor x-api-key).
func GRPCAuthXORGuardInterceptor(cfg GRPCAuthXORConfig) grpc.UnaryServerInterceptor {
	cfg = resolveGRPCAuthXORConfig(cfg)
	return grpcAuthXORGuardInterceptor(cfg)
}

// GRPCAuthXORGuardInterceptorStrict builds an interceptor without implicit defaults.
func GRPCAuthXORGuardInterceptorStrict(cfg GRPCAuthXORConfig) (grpc.UnaryServerInterceptor, error) {
	if err := ValidateGRPCAuthXORConfigStrict(cfg); err != nil {
		return nil, err
	}
	return grpcAuthXORGuardInterceptor(cfg), nil
}

func grpcAuthXORGuardInterceptor(cfg GRPCAuthXORConfig) grpc.UnaryServerInterceptor {
	authorizationHeader := strings.ToLower(cfg.AuthorizationHeader)
	apiKeyHeader := strings.ToLower(cfg.APIKeyHeader)

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if cfg.AllowAnonymous(info.FullMethod) {
			return handler(ctx, req)
		}

		md, _ := metadata.FromIncomingContext(ctx)
		hasAuthorization := first(md.Get(authorizationHeader)) != ""
		hasAPIKey := first(md.Get(apiKeyHeader)) != ""
		if hasAuthorization && hasAPIKey {
			return nil, status.Error(codes.InvalidArgument, authXORMutuallyExclusiveMessage)
		}
		if cfg.RequireAuth && !hasAuthorization && !hasAPIKey {
			return nil, status.Error(codes.Unauthenticated, missingAuthorizationMetadataMsg)
		}

		return handler(ctx, req)
	}
}

func resolveGRPCAuthXORConfig(cfg GRPCAuthXORConfig) GRPCAuthXORConfig {
	if strings.TrimSpace(cfg.AuthorizationHeader) == "" {
		cfg.AuthorizationHeader = defaultGRPCAuthorizationHeader
	}
	if strings.TrimSpace(cfg.APIKeyHeader) == "" {
		cfg.APIKeyHeader = defaultGRPCAPIKeyHeader
	}
	if cfg.AllowAnonymous == nil {
		cfg.AllowAnonymous = func(string) bool { return false }
	}
	return cfg
}
