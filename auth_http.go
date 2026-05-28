package middleware

import (
	"context"
	"net/http"
	"strings"
)

// HTTPAuthenticationMiddleware enforces bearer-token or API-key authentication on HTTP handlers.
// Implicit defaults are applied: nil Authenticator rejects all; nil AllowAnonymous denies all.
func HTTPAuthenticationMiddleware(cfg HTTPAuthConfig) func(http.Handler) http.Handler {
	cfg = resolveHTTPAuthConfig(cfg)
	return httpAuthenticationMiddleware(cfg)
}

// HTTPAuthenticationMiddlewareStrict builds authentication middleware without implicit defaults.
// Returns an error at construction time if the configuration is invalid.
func HTTPAuthenticationMiddlewareStrict(cfg HTTPAuthConfig) (func(http.Handler) http.Handler, error) {
	if err := ValidateHTTPAuthConfigStrict(cfg); err != nil {
		return nil, err
	}
	return httpAuthenticationMiddleware(cfg), nil
}

func httpAuthenticationMiddleware(cfg HTTPAuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.AllowAnonymous(r) {
				next.ServeHTTP(w, r)
				return
			}

			apiKeyPresent, apiKeyValid := validateHTTPAPIKey(r, cfg)
			if (apiKeyPresent && !apiKeyValid) || (cfg.RequireAPIKey && !apiKeyValid) {
				writeHTTPAuthError(w)
				return
			}

			ctx, ok := buildAuthenticatedHTTPContext(r, cfg, apiKeyPresent, apiKeyValid)
			if !ok {
				writeHTTPAuthError(w)
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func validateHTTPAPIKey(r *http.Request, cfg HTTPAuthConfig) (bool, bool) {
	if strings.TrimSpace(cfg.APIKeyHeader) == "" {
		return false, !cfg.RequireAPIKey
	}

	apiKey := strings.TrimSpace(r.Header.Get(cfg.APIKeyHeader))
	if apiKey == "" {
		return false, !cfg.RequireAPIKey
	}
	if cfg.ExpectedAPIKey != "" && apiKey != cfg.ExpectedAPIKey {
		return true, false
	}

	return true, true
}

func buildAuthenticatedHTTPContext(r *http.Request, cfg HTTPAuthConfig, apiKeyPresent bool, apiKeyValid bool) (context.Context, bool) {
	token, ok := parseBearerToken(r.Header.Get("Authorization"))
	if ok {
		identity, err := cfg.Authenticator.Authenticate(r.Context(), token)
		if err != nil {
			return nil, false
		}

		ctx := WithIdentity(r.Context(), identity)
		if cfg.IdentityHeaderHint != "" {
			ctx = WithValueIfAbsent(ctx, IdentityTypeKey, cfg.IdentityHeaderHint)
		}

		return ctx, true
	}

	if !isHTTPAPIKeyAuthConfigured(cfg) || !apiKeyPresent || !apiKeyValid {
		return nil, false
	}

	return WithIdentity(r.Context(), apiKeyIdentity(cfg.IdentityHeaderHint)), true
}

func isHTTPAPIKeyAuthConfigured(cfg HTTPAuthConfig) bool {
	return cfg.RequireAPIKey || strings.TrimSpace(cfg.ExpectedAPIKey) != ""
}

// HTTPAuthorizationMiddleware enforces minimum identity level on HTTP handlers.
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

// resolveHTTPAuthConfig applies implicit defaults to an HTTPAuthConfig.
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
