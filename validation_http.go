package middleware

import (
	"context"
	"net/http"
	"strings"
)

func HTTPValidationMiddleware(cfg HTTPValidationConfig) func(http.Handler) http.Handler {
	cfg = resolveHTTPValidationConfig(cfg)
	return httpValidationMiddleware(cfg)
}

// HTTPValidationMiddlewareStrict builds middleware without implicit defaults.
func HTTPValidationMiddlewareStrict(cfg HTTPValidationConfig) (func(http.Handler) http.Handler, error) {
	if err := ValidateHTTPValidationConfigStrict(cfg); err != nil {
		return nil, err
	}
	return httpValidationMiddleware(cfg), nil
}

func httpValidationMiddleware(cfg HTTPValidationConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, ok := validateHTTPMiddlewareContext(w, r, cfg)
			if !ok {
				return
			}
			if cfg.MaxBodyBytes > 0 && r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func validateHTTPMiddlewareContext(w http.ResponseWriter, r *http.Request, cfg HTTPValidationConfig) (context.Context, bool) {
	ctx := r.Context()
	var ok bool

	if ctx, ok = injectHTTPRequestID(w, r, cfg, ctx); !ok {
		return nil, false
	}
	if ctx, ok = injectHTTPAppID(w, r, cfg, ctx); !ok {
		return nil, false
	}
	if ctx, ok = injectHTTPSessionID(w, r, cfg, ctx); !ok {
		return nil, false
	}
	if ctx, ok = injectHTTPIdempotencyKey(w, r, cfg, ctx); !ok {
		return nil, false
	}

	return ctx, true
}

func injectHTTPRequestID(w http.ResponseWriter, r *http.Request, cfg HTTPValidationConfig, ctx context.Context) (context.Context, bool) {
	if !cfg.RequireRequestID {
		return ctx, true
	}

	requestIDHeader := strings.TrimSpace(cfg.RequestIDHeader)
	requestID := Value(ctx, RequestIDKey)
	if requestID == "" {
		requestID = strings.TrimSpace(r.Header.Get(requestIDHeader))
	}
	if requestID == "" {
		writeValidationError(w, http.StatusBadRequest, validationErrorCode, requiredHeaderMessage(requestIDHeader))
		return nil, false
	}

	return WithValueIfAbsent(ctx, RequestIDKey, requestID), true
}

func injectHTTPAppID(w http.ResponseWriter, r *http.Request, cfg HTTPValidationConfig, ctx context.Context) (context.Context, bool) {
	if !cfg.RequireAppID {
		return ctx, true
	}

	appID := strings.TrimSpace(r.Header.Get(cfg.AppIDHeader))
	if appID == "" {
		writeValidationError(w, http.StatusBadRequest, validationErrorCode, requiredHeaderMessage(cfg.AppIDHeader))
		return nil, false
	}

	return WithValueIfAbsent(ctx, AppIDKey, appID), true
}

func injectHTTPSessionID(w http.ResponseWriter, r *http.Request, cfg HTTPValidationConfig, ctx context.Context) (context.Context, bool) {
	if !cfg.RequireSessionID {
		return ctx, true
	}

	sessionID := strings.TrimSpace(r.Header.Get(cfg.SessionHeader))
	if sessionID == "" {
		writeValidationError(w, http.StatusBadRequest, validationErrorCode, requiredHeaderMessage(cfg.SessionHeader))
		return nil, false
	}

	return WithValueIfAbsent(ctx, SessionIDKey, sessionID), true
}

func injectHTTPIdempotencyKey(w http.ResponseWriter, r *http.Request, cfg HTTPValidationConfig, ctx context.Context) (context.Context, bool) {
	if !cfg.RequireIdempotencyForMutations || !cfg.IsMutation(r.Method, r.URL.Path) {
		return ctx, true
	}

	idempotencyHeader := strings.TrimSpace(cfg.IdempotencyHeader)
	idempotencyKey := strings.TrimSpace(r.Header.Get(idempotencyHeader))
	if idempotencyKey == "" {
		writeValidationError(w, http.StatusBadRequest, validationErrorCode, requiredHeaderMessage(idempotencyHeader))
		return nil, false
	}

	return WithValueIfAbsent(ctx, IdempotencyKeyKey, idempotencyKey), true
}

func resolveHTTPValidationConfig(cfg HTTPValidationConfig) HTTPValidationConfig {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if strings.TrimSpace(cfg.RequestIDHeader) == "" {
		cfg.RequestIDHeader = httpHeaderRequestID
	}
	if strings.TrimSpace(cfg.AppIDHeader) == "" {
		cfg.AppIDHeader = "X-App-ID"
	}
	if strings.TrimSpace(cfg.SessionHeader) == "" {
		cfg.SessionHeader = "X-Session-ID"
	}
	if strings.TrimSpace(cfg.IdempotencyHeader) == "" {
		cfg.IdempotencyHeader = httpHeaderIdempotencyKey
	}
	if cfg.IsMutation == nil {
		cfg.IsMutation = func(method, _ string) bool {
			switch strings.ToUpper(strings.TrimSpace(method)) {
			case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				return true
			default:
				return false
			}
		}
	}
	return cfg
}
