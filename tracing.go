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

type TracingConfig struct {
	TraceHeader       string
	RequestHeader     string
	TraceparentHeader string
	TracePrefix       string
}

func DefaultTracingConfig() TracingConfig {
	return TracingConfig{
		TraceHeader:       "X-Trace-ID",
		RequestHeader:     "X-Request-ID",
		TraceparentHeader: "traceparent",
		TracePrefix:       "trace-",
	}
}

func HTTPTracingMiddleware(cfg TracingConfig) func(http.Handler) http.Handler {
	cfg = resolveTracingConfig(cfg)
	return httpTracingMiddleware(cfg)
}

// HTTPTracingMiddlewareStrict builds middleware without implicit defaults.
func HTTPTracingMiddlewareStrict(cfg TracingConfig) (func(http.Handler) http.Handler, error) {
	if err := ValidateTracingConfigStrict(cfg); err != nil {
		return nil, err
	}
	return httpTracingMiddlewareStrict(cfg), nil
}

func httpTracingMiddlewareStrict(cfg TracingConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := strings.TrimSpace(r.Header.Get(cfg.RequestHeader))
			if requestID == "" {
				writeValidationError(w, http.StatusBadRequest, validationErrorCode, requiredHeaderMessage(cfg.RequestHeader))
				return
			}

			traceID := resolveIncomingTraceID(r.Header.Get(cfg.TraceHeader), r.Header.Get(cfg.TraceparentHeader))
			if traceID == "" {
				writeValidationError(w, http.StatusBadRequest, validationErrorCode, strictTraceRequirementMessage(cfg))
				return
			}

			ctx := enrichTracingContext(r.Context(), traceID, requestID)
			setTracingResponseHeaders(w, cfg, ctx)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func httpTracingMiddleware(cfg TracingConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := strings.TrimSpace(r.Header.Get(cfg.RequestHeader))
			traceID := resolveTraceIDWithFallback(r.Header.Get(cfg.TraceHeader), r.Header.Get(cfg.TraceparentHeader), requestID, cfg.TracePrefix)

			ctx := enrichTracingContext(r.Context(), traceID, requestID)
			setTracingResponseHeaders(w, cfg, ctx)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GRPCTracingInterceptor(cfg TracingConfig) grpc.UnaryServerInterceptor {
	cfg = resolveTracingConfig(cfg)
	return grpcTracingInterceptor(cfg)
}

// GRPCTracingInterceptorStrict builds an interceptor without implicit defaults.
func GRPCTracingInterceptorStrict(cfg TracingConfig) (grpc.UnaryServerInterceptor, error) {
	if err := ValidateTracingConfigStrict(cfg); err != nil {
		return nil, err
	}
	return grpcTracingInterceptorStrict(cfg), nil
}

func grpcTracingInterceptorStrict(cfg TracingConfig) grpc.UnaryServerInterceptor {
	traceHeader := strings.ToLower(cfg.TraceHeader)
	requestHeader := strings.ToLower(cfg.RequestHeader)
	traceparentHeader := strings.ToLower(cfg.TraceparentHeader)

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		_ = info
		md, _ := metadata.FromIncomingContext(ctx)

		requestID := first(md.Get(requestHeader))
		if requestID == "" {
			requestID = Value(ctx, RequestIDKey)
		}
		if requestID == "" {
			return nil, status.Error(codes.InvalidArgument, requiredHeaderMessage(requestHeader))
		}

		traceID := resolveIncomingTraceID(first(md.Get(traceHeader)), first(md.Get(traceparentHeader)))
		if traceID == "" {
			traceID = Value(ctx, TraceIDKey)
		}
		if traceID == "" {
			return nil, status.Error(codes.InvalidArgument, strictTraceRequirementMessageLower(traceHeader, traceparentHeader))
		}

		ctx = enrichTracingContext(ctx, traceID, requestID)

		return handler(ctx, req)
	}
}

func grpcTracingInterceptor(cfg TracingConfig) grpc.UnaryServerInterceptor {
	traceHeader := strings.ToLower(cfg.TraceHeader)
	requestHeader := strings.ToLower(cfg.RequestHeader)
	traceparentHeader := strings.ToLower(cfg.TraceparentHeader)

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		requestID := first(md.Get(requestHeader))
		traceID := first(md.Get(traceHeader))
		if traceID == "" {
			traceID = parseTraceparentTraceID(first(md.Get(traceparentHeader)))
		}
		if traceID == "" {
			if requestID != "" {
				traceID = cfg.TracePrefix + requestID
			} else {
				traceID = cfg.TracePrefix + "anon"
			}
		}

		ctx = WithValueIfAbsent(ctx, TraceIDKey, traceID)
		if requestID != "" {
			ctx = WithValueIfAbsent(ctx, RequestIDKey, requestID)
		}
		ctx = WithValueIfAbsent(ctx, MiddlewareVersionKey, MiddlewareVersion)

		return handler(ctx, req)
	}
}

func resolveTracingConfig(cfg TracingConfig) TracingConfig {
	def := DefaultTracingConfig()
	if strings.TrimSpace(cfg.TraceHeader) == "" {
		cfg.TraceHeader = def.TraceHeader
	}
	if strings.TrimSpace(cfg.RequestHeader) == "" {
		cfg.RequestHeader = def.RequestHeader
	}
	if strings.TrimSpace(cfg.TraceparentHeader) == "" {
		cfg.TraceparentHeader = def.TraceparentHeader
	}
	if strings.TrimSpace(cfg.TracePrefix) == "" {
		cfg.TracePrefix = def.TracePrefix
	}
	return cfg
}

func resolveIncomingTraceID(traceHeaderValue string, traceparentValue string) string {
	traceID := strings.TrimSpace(traceHeaderValue)
	if traceID != "" {
		return traceID
	}
	return parseTraceparentTraceID(traceparentValue)
}

func resolveTraceIDWithFallback(traceHeaderValue string, traceparentValue string, requestID string, tracePrefix string) string {
	traceID := resolveIncomingTraceID(traceHeaderValue, traceparentValue)
	if traceID != "" {
		return traceID
	}
	if requestID != "" {
		return tracePrefix + requestID
	}
	return tracePrefix + "anon"
}

func enrichTracingContext(ctx context.Context, traceID string, requestID string) context.Context {
	ctx = WithValueIfAbsent(ctx, TraceIDKey, traceID)
	if requestID != "" {
		ctx = WithValueIfAbsent(ctx, RequestIDKey, requestID)
	}
	ctx = WithValueIfAbsent(ctx, MiddlewareVersionKey, MiddlewareVersion)
	return ctx
}

func setTracingResponseHeaders(w http.ResponseWriter, cfg TracingConfig, ctx context.Context) {
	if Value(ctx, TraceIDKey) != "" {
		w.Header().Set(cfg.TraceHeader, Value(ctx, TraceIDKey))
	}
	if Value(ctx, RequestIDKey) != "" {
		w.Header().Set(cfg.RequestHeader, Value(ctx, RequestIDKey))
	}
}

func strictTraceRequirementMessage(cfg TracingConfig) string {
	return strictTraceRequirementMessageLower(strings.ToLower(cfg.TraceHeader), strings.ToLower(cfg.TraceparentHeader))
}

func strictTraceRequirementMessageLower(traceHeader string, traceparentHeader string) string {
	return traceHeader + " or valid " + traceparentHeader + requiredMessageSuffix
}

func parseTraceparentTraceID(traceparent string) string {
	parts := strings.Split(strings.TrimSpace(traceparent), "-")
	if len(parts) < 4 {
		return ""
	}
	traceID := strings.TrimSpace(parts[1])
	if len(traceID) != 32 {
		return ""
	}
	return traceID
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}
