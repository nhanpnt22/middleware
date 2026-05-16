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
	"google.golang.org/protobuf/proto"
)

var ErrValidationFailed = errors.New("validation failed")

type HTTPValidationConfig struct {
	MaxBodyBytes     int64
	RequireRequestID bool
	// Deprecated: prefer HTTPIdempotencyExtractionMiddleware for extraction.
	RequireIdempotencyForMutations bool
	IsMutation                     func(method, path string) bool
}

type GRPCValidationConfig struct {
	MaxRequestBytes  int
	RequireRequestID bool
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

			idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
			if idempotencyKey == "" {
				writeValidationError(w, http.StatusBadRequest, "VALIDATION_FAILED", "idempotency-key is required")
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

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if !cfg.RequiredForMutations || !cfg.IsMutationGRPC(info.FullMethod) {
			return handler(ctx, req)
		}

		md, _ := metadata.FromIncomingContext(ctx)
		idempotencyKey := first(md.Get("idempotency-key"))
		if idempotencyKey == "" {
			idempotencyKey = first(md.Get("x-idempotency-key"))
		}
		if idempotencyKey == "" {
			return nil, status.Error(codes.InvalidArgument, "idempotency-key is required")
		}

		return handler(WithValueIfAbsent(ctx, IdempotencyKeyKey, idempotencyKey), req)
	}
}

func HTTPValidationMiddleware(cfg HTTPValidationConfig) func(http.Handler) http.Handler {
	cfg = resolveHTTPValidationConfig(cfg)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.RequireRequestID && Value(r.Context(), RequestIDKey) == "" {
				writeValidationError(w, http.StatusBadRequest, "VALIDATION_FAILED", "x-request-id is required")
				return
			}
			if cfg.RequireIdempotencyForMutations && cfg.IsMutation(r.Method, r.URL.Path) {
				idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
				if idempotencyKey == "" {
					writeValidationError(w, http.StatusBadRequest, "VALIDATION_FAILED", "idempotency-key is required")
					return
				}
				r = r.WithContext(WithValueIfAbsent(r.Context(), IdempotencyKeyKey, idempotencyKey))
			}
			if cfg.MaxBodyBytes > 0 && r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func GRPCValidationInterceptor(cfg GRPCValidationConfig) grpc.UnaryServerInterceptor {
	cfg = resolveGRPCValidationConfig(cfg)
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		if cfg.RequireRequestID {
			if Value(ctx, RequestIDKey) == "" && first(md.Get("x-request-id")) == "" {
				return nil, status.Error(codes.InvalidArgument, "x-request-id is required")
			}
		}
		if cfg.RequireIdempotencyForMutations && cfg.IsMutation(info.FullMethod) {
			idempotencyKey := first(md.Get("idempotency-key"))
			if idempotencyKey == "" {
				idempotencyKey = first(md.Get("x-idempotency-key"))
			}
			if idempotencyKey == "" {
				return nil, status.Error(codes.InvalidArgument, "idempotency-key is required")
			}
			ctx = WithValueIfAbsent(ctx, IdempotencyKeyKey, idempotencyKey)
		}
		if cfg.MaxRequestBytes > 0 {
			message, ok := req.(proto.Message)
			if ok {
				if proto.Size(message) > cfg.MaxRequestBytes {
					return nil, status.Error(codes.InvalidArgument, "request too large")
				}
			}
		}
		if cfg.ValidateRequest != nil {
			if err := cfg.ValidateRequest(ctx, info.FullMethod, req); err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
		}
		return handler(ctx, req)
	}
}

func resolveHTTPValidationConfig(cfg HTTPValidationConfig) HTTPValidationConfig {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
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

func resolveGRPCValidationConfig(cfg GRPCValidationConfig) GRPCValidationConfig {
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = 1 << 20
	}
	if cfg.IsMutation == nil {
		cfg.IsMutation = defaultIsMutationMethod
	}
	return cfg
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
