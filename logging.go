package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

type LogSink interface {
	Log(ctx context.Context, entry map[string]interface{})
}

type StdLogSink struct {
	logger *log.Logger
}

func NewStdLogSink(logger *log.Logger) *StdLogSink {
	if logger == nil {
		logger = log.Default()
	}
	return &StdLogSink{logger: logger}
}

func (s *StdLogSink) Log(_ context.Context, entry map[string]interface{}) {
	buf, err := json.Marshal(entry)
	if err != nil {
		s.logger.Printf("{\"level\":\"error\",\"message\":\"log marshal failed\"}")
		return
	}
	s.logger.Print(string(buf))
}

type LoggingConfig struct {
	ServiceName       string
	Environment       string
	Logger            LogSink
	Now               func() time.Time
	NormalizeEndpoint func(string) string
}

func HTTPLoggingMiddleware(cfg LoggingConfig) func(http.Handler) http.Handler {
	cfg = resolveLoggingConfig(cfg)
	return httpLoggingMiddleware(cfg)
}

// HTTPLoggingMiddlewareStrict builds middleware without implicit defaults.
func HTTPLoggingMiddlewareStrict(cfg LoggingConfig) (func(http.Handler) http.Handler, error) {
	if err := ValidateLoggingConfigStrict(cfg); err != nil {
		return nil, err
	}
	return httpLoggingMiddleware(cfg), nil
}

func httpLoggingMiddleware(cfg LoggingConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := cfg.Now()
			rec := &loggingStatusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			cfg.Logger.Log(r.Context(), map[string]interface{}{
				"timestamp":          cfg.Now().UTC().Format(time.RFC3339Nano),
				"level":              "info",
				"message":            "http request",
				"service_name":       cfg.ServiceName,
				"environment":        cfg.Environment,
				"trace_id":           Value(r.Context(), TraceIDKey),
				"request_id":         Value(r.Context(), RequestIDKey),
				"middleware_version": Value(r.Context(), MiddlewareVersionKey),
				"endpoint":           cfg.NormalizeEndpoint(r.URL.Path),
				"method":             r.Method,
				"status_code":        rec.status,
				"latency_ms":         cfg.Now().Sub(start).Milliseconds(),
			})
		})
	}
}

func GRPCLoggingInterceptor(cfg LoggingConfig) grpc.UnaryServerInterceptor {
	cfg = resolveLoggingConfig(cfg)
	return grpcLoggingInterceptor(cfg)
}

// GRPCLoggingInterceptorStrict builds an interceptor without implicit defaults.
func GRPCLoggingInterceptorStrict(cfg LoggingConfig) (grpc.UnaryServerInterceptor, error) {
	if err := ValidateLoggingConfigStrict(cfg); err != nil {
		return nil, err
	}
	return grpcLoggingInterceptor(cfg), nil
}

func grpcLoggingInterceptor(cfg LoggingConfig) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := cfg.Now()
		resp, err := handler(ctx, req)
		st := status.Convert(err)
		cfg.Logger.Log(ctx, map[string]interface{}{
			"timestamp":          cfg.Now().UTC().Format(time.RFC3339Nano),
			"level":              "info",
			"message":            "grpc request",
			"service_name":       cfg.ServiceName,
			"environment":        cfg.Environment,
			"trace_id":           Value(ctx, TraceIDKey),
			"request_id":         Value(ctx, RequestIDKey),
			"middleware_version": Value(ctx, MiddlewareVersionKey),
			"endpoint":           cfg.NormalizeEndpoint(info.FullMethod),
			"method":             "grpc",
			"status_code":        st.Code().String(),
			"latency_ms":         cfg.Now().Sub(start).Milliseconds(),
		})
		return resp, err
	}
}

type loggingStatusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *loggingStatusRecorder) WriteHeader(statusCode int) {
	w.status = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func resolveLoggingConfig(cfg LoggingConfig) LoggingConfig {
	if strings.TrimSpace(cfg.ServiceName) == "" {
		cfg.ServiceName = "unknown"
	}
	if strings.TrimSpace(cfg.Environment) == "" {
		cfg.Environment = "unknown"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = NewStdLogSink(nil)
	}
	if cfg.NormalizeEndpoint == nil {
		cfg.NormalizeEndpoint = normalizeEndpoint
	}
	return cfg
}

func normalizeEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "unknown"
	}
	parts := strings.Split(endpoint, "/")
	for i, p := range parts {
		if p == "" {
			continue
		}
		if looksLikeIdentifier(p) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func looksLikeIdentifier(value string) bool {
	if len(value) < 8 {
		return false
	}
	digits := 0
	for _, r := range value {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits >= 4
}
