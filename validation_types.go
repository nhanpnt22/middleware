package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var ErrValidationFailed = errors.New("validation failed")

const (
	validationErrorCode           = "VALIDATION_FAILED"
	httpHeaderRequestID           = "X-Request-ID"
	httpHeaderIdempotencyKey      = "Idempotency-Key"
	grpcHeaderRequestID           = "x-request-id"
	grpcHeaderIdempotencyKey      = "idempotency-key"
	grpcHeaderAltIdempotencyKey   = "x-idempotency-key"
	requiredMessageSuffix         = " is required"
	idempotencyKeyRequiredMessage = "idempotency-key is required"
)

func requiredHeaderMessage(header string) string {
	return strings.ToLower(strings.TrimSpace(header)) + requiredMessageSuffix
}

type HTTPValidationConfig struct {
	MaxBodyBytes      int64
	RequireRequestID  bool
	RequestIDHeader   string
	RequireAppID      bool
	AppIDHeader       string
	RequireSessionID  bool
	SessionHeader     string
	IdempotencyHeader string
	// Deprecated: prefer HTTPIdempotencyExtractionMiddleware for extraction.
	RequireIdempotencyForMutations bool
	IsMutation                     func(method, path string) bool
}

type GRPCValidationConfig struct {
	MaxRequestBytes      int
	RequireRequestID     bool
	RequestIDHeader      string
	RequireAppID         bool
	AppIDHeader          string
	RequireSessionID     bool
	SessionHeader        string
	IdempotencyHeader    string
	AltIdempotencyHeader string
	// Deprecated: prefer GRPCIdempotencyExtractionInterceptor for extraction.
	RequireIdempotencyForMutations bool
	IsMutation                     func(fullMethod string) bool
	ValidateRequest                func(ctx context.Context, fullMethod string, req interface{}) error
}

type IdempotencyConfig struct {
	RequiredForMutations bool
	IsMutationHTTP       func(method, path string) bool
	IsMutationGRPC       func(fullMethod string) bool
}

func defaultIsMutationMethod(fullMethod string) bool {
	upper := strings.ToUpper(strings.TrimSpace(fullMethod))
	verbs := []string{"CREATE", "UPDATE", "PATCH", "DELETE", "INIT", "SET", "SYNC"}
	for _, verb := range verbs {
		if strings.Contains(upper, verb) {
			return true
		}
	}
	return false
}

func writeValidationError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Code: code, Type: "client", Message: message, Retryable: false})
}

func HTTPIdempotencyExtractionMiddleware(cfg IdempotencyConfig) func(http.Handler) http.Handler {
	if cfg.IsMutationHTTP == nil {
		cfg.IsMutationHTTP = func(method, _ string) bool {
			switch strings.ToUpper(strings.TrimSpace(method)) {
			case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				return true
			default:
				return false
			}
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.RequiredForMutations || !cfg.IsMutationHTTP(r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			idempotencyKey := strings.TrimSpace(r.Header.Get(httpHeaderIdempotencyKey))
			if idempotencyKey == "" {
				writeValidationError(w, http.StatusBadRequest, validationErrorCode, idempotencyKeyRequiredMessage)
				return
			}

			next.ServeHTTP(w, r.WithContext(WithValueIfAbsent(r.Context(), IdempotencyKeyKey, idempotencyKey)))
		})
	}
}

// HTTPIdempotencyExtractionMiddlewareStrict builds middleware without implicit defaults.
func HTTPIdempotencyExtractionMiddlewareStrict(cfg IdempotencyConfig) (func(http.Handler) http.Handler, error) {
	if err := ValidateHTTPIdempotencyConfigStrict(cfg); err != nil {
		return nil, err
	}
	return httpIdempotencyExtractionMiddleware(cfg), nil
}

func httpIdempotencyExtractionMiddleware(cfg IdempotencyConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.RequiredForMutations || !cfg.IsMutationHTTP(r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			idempotencyKey := strings.TrimSpace(r.Header.Get(httpHeaderIdempotencyKey))
			if idempotencyKey == "" {
				writeValidationError(w, http.StatusBadRequest, validationErrorCode, idempotencyKeyRequiredMessage)
				return
			}

			next.ServeHTTP(w, r.WithContext(WithValueIfAbsent(r.Context(), IdempotencyKeyKey, idempotencyKey)))
		})
	}
}

func GRPCIdempotencyExtractionInterceptor(cfg IdempotencyConfig) grpc.UnaryServerInterceptor {
	if cfg.IsMutationGRPC == nil {
		cfg.IsMutationGRPC = defaultIsMutationMethod
	}
	return grpcIdempotencyExtractionInterceptor(cfg)
}

// GRPCIdempotencyExtractionInterceptorStrict builds an interceptor without implicit defaults.
func GRPCIdempotencyExtractionInterceptorStrict(cfg IdempotencyConfig) (grpc.UnaryServerInterceptor, error) {
	if err := ValidateGRPCIdempotencyConfigStrict(cfg); err != nil {
		return nil, err
	}
	return grpcIdempotencyExtractionInterceptor(cfg), nil
}

func grpcIdempotencyExtractionInterceptor(cfg IdempotencyConfig) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if !cfg.RequiredForMutations || !cfg.IsMutationGRPC(info.FullMethod) {
			return handler(ctx, req)
		}

		md, _ := metadata.FromIncomingContext(ctx)
		idempotencyKey := first(md.Get(grpcHeaderIdempotencyKey))
		if idempotencyKey == "" {
			idempotencyKey = first(md.Get(grpcHeaderAltIdempotencyKey))
		}
		if idempotencyKey == "" {
			return nil, status.Error(codes.InvalidArgument, idempotencyKeyRequiredMessage)
		}

		return handler(WithValueIfAbsent(ctx, IdempotencyKeyKey, idempotencyKey), req)
	}
}
