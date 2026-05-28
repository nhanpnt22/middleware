package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Handler and Middleware are the canonical transport-agnostic contracts.
type Handler func(ctx context.Context, req interface{}) (interface{}, error)

type Middleware func(next Handler) Handler

type UnaryHandler func(ctx context.Context, req interface{}) (interface{}, error)

type UnaryMiddleware func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, next UnaryHandler) (interface{}, error)

const (
	NamePanicRecovery      = "panic_recovery"
	NameTracing            = "tracing"
	NameMetrics            = "metrics"
	NameLogging            = "logging"
	NameAuthXORGuard       = "auth_xor_guard"
	NameAuthentication     = "authentication"
	NameAuthorization      = "authorization"
	NameRateLimiting       = "rate_limiting"
	NameCircuitBreaker     = "circuit_breaker"
	NameIdempotencyExtract = "idempotency_extraction"
	NameRequestValidation  = "request_validation"
)

var StandardOrder = []string{
	NamePanicRecovery,
	NameTracing,
	NameMetrics,
	NameLogging,
	NameAuthXORGuard,
	NameAuthentication,
	NameAuthorization,
	NameRateLimiting,
	NameCircuitBreaker,
	NameIdempotencyExtract,
	NameRequestValidation,
}

func Chain(h Handler, m ...Middleware) Handler {
	for i := len(m) - 1; i >= 0; i-- {
		h = m[i](h)
	}
	return h
}

func ValidateStandardOrder(order []string) error {
	if len(order) != len(StandardOrder) {
		return fmt.Errorf("middleware order length mismatch: got %d, want %d", len(order), len(StandardOrder))
	}
	for i := range StandardOrder {
		if order[i] != StandardOrder[i] {
			return fmt.Errorf("middleware order mismatch at index %d: got %q, want %q", i, order[i], StandardOrder[i])
		}
	}
	return nil
}

func ChainUnary(middlewares ...UnaryMiddleware) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		next := UnaryHandler(func(callCtx context.Context, callReq interface{}) (interface{}, error) {
			return handler(callCtx, callReq)
		})
		for i := len(middlewares) - 1; i >= 0; i-- {
			mw := middlewares[i]
			prev := next
			next = UnaryHandler(func(callCtx context.Context, callReq interface{}) (interface{}, error) {
				return mw(callCtx, callReq, info, prev)
			})
		}
		return next(ctx, req)
	}
}

func ChainInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		wrapped := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			current := interceptors[i]
			next := wrapped
			wrapped = func(callCtx context.Context, callReq interface{}) (interface{}, error) {
				return current(callCtx, callReq, info, next)
			}
		}
		return wrapped(ctx, req)
	}
}

func ChainHTTP(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		wrapped := next
		for i := len(middlewares) - 1; i >= 0; i-- {
			wrapped = middlewares[i](wrapped)
		}
		return wrapped
	}
}

func HTTPPanicRecoveryMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					_ = recovered
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(ErrorResponse{Code: "INTERNAL_ERROR", Type: "server", Message: "internal server error", Retryable: false})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func GRPCPanicRecoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		_ = info
		defer func() {
			if recovered := recover(); recovered != nil {
				_ = debug.Stack()
				_ = recovered
				err = status.Error(codes.Internal, "internal server error")
			}
		}()
		return handler(ctx, req)
	}
}

type CircuitBreaker interface {
	Allow(ctx context.Context, operation string) error
	Record(ctx context.Context, operation string, err error)
}

type NoopCircuitBreaker struct{}

func (NoopCircuitBreaker) Allow(context.Context, string) error {
	return nil
}

func (NoopCircuitBreaker) Record(context.Context, string, error) {
	// Intentionally a no-op: default breaker tracks no state and never blocks execution.
}

func HTTPCircuitBreakerMiddleware(cb CircuitBreaker, operation func(r *http.Request) string) func(http.Handler) http.Handler {
	if cb == nil {
		cb = NoopCircuitBreaker{}
	}
	if operation == nil {
		operation = func(r *http.Request) string { return r.URL.Path }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			op := operation(r)
			if err := cb.Allow(r.Context(), op); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(ErrorResponse{Code: "CIRCUIT_OPEN", Type: "server", Message: "dependency unavailable", Retryable: true})
				return
			}

			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			if rec.status >= http.StatusInternalServerError {
				cb.Record(r.Context(), op, status.Error(codes.Internal, "http upstream error"))
				return
			}
			cb.Record(r.Context(), op, nil)
		})
	}
}

func GRPCCircuitBreakerInterceptor(cb CircuitBreaker, operation func(info *grpc.UnaryServerInfo) string) grpc.UnaryServerInterceptor {
	if cb == nil {
		cb = NoopCircuitBreaker{}
	}
	if operation == nil {
		operation = func(info *grpc.UnaryServerInfo) string { return info.FullMethod }
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		op := operation(info)
		if err := cb.Allow(ctx, op); err != nil {
			return nil, status.Error(codes.Unavailable, "circuit open")
		}
		resp, err := handler(ctx, req)
		cb.Record(ctx, op, err)
		return resp, err
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(statusCode int) {
	w.status = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}
