package middleware

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
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
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := strings.TrimSpace(r.Header.Get(cfg.RequestHeader))
			traceID := strings.TrimSpace(r.Header.Get(cfg.TraceHeader))
			if traceID == "" {
				traceID = parseTraceparentTraceID(r.Header.Get(cfg.TraceparentHeader))
			}
			if traceID == "" {
				if requestID != "" {
					traceID = cfg.TracePrefix + requestID
				} else {
					traceID = cfg.TracePrefix + "anon"
				}
			}

			ctx := r.Context()
			ctx = WithValueIfAbsent(ctx, TraceIDKey, traceID)
			if requestID != "" {
				ctx = WithValueIfAbsent(ctx, RequestIDKey, requestID)
			}
			ctx = WithValueIfAbsent(ctx, MiddlewareVersionKey, MiddlewareVersion)

			if Value(ctx, TraceIDKey) != "" {
				w.Header().Set(cfg.TraceHeader, Value(ctx, TraceIDKey))
			}
			if Value(ctx, RequestIDKey) != "" {
				w.Header().Set(cfg.RequestHeader, Value(ctx, RequestIDKey))
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GRPCTracingInterceptor(cfg TracingConfig) grpc.UnaryServerInterceptor {
	cfg = resolveTracingConfig(cfg)
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
