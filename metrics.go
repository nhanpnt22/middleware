package middleware

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

type MetricLabels struct {
	ServiceName string
	Endpoint    string
	Method      string
	StatusCode  string
}

type MetricsRecorder interface {
	IncRequest(labels MetricLabels)
	IncError(labels MetricLabels)
	ObserveLatency(labels MetricLabels, milliseconds int64)
}

type InMemoryMetrics struct {
	mu             sync.Mutex
	RequestCount   map[MetricLabels]uint64
	ErrorCount     map[MetricLabels]uint64
	LatencySamples map[MetricLabels][]int64
}

func NewInMemoryMetrics() *InMemoryMetrics {
	return &InMemoryMetrics{
		RequestCount:   make(map[MetricLabels]uint64),
		ErrorCount:     make(map[MetricLabels]uint64),
		LatencySamples: make(map[MetricLabels][]int64),
	}
}

func (m *InMemoryMetrics) IncRequest(labels MetricLabels) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RequestCount[labels]++
}

func (m *InMemoryMetrics) IncError(labels MetricLabels) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ErrorCount[labels]++
}

func (m *InMemoryMetrics) ObserveLatency(labels MetricLabels, milliseconds int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.LatencySamples[labels] = append(m.LatencySamples[labels], milliseconds)
}

type MetricsConfig struct {
	ServiceName string
	Recorder    MetricsRecorder
	Now         func() time.Time
}

func HTTPMetricsMiddleware(cfg MetricsConfig) func(http.Handler) http.Handler {
	cfg = resolveMetricsConfig(cfg)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := cfg.Now()
			rec := &metricsStatusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			labels := MetricLabels{
				ServiceName: cfg.ServiceName,
				Endpoint:    normalizeEndpoint(r.URL.Path),
				Method:      r.Method,
				StatusCode:  strconv.Itoa(rec.status),
			}
			cfg.Recorder.IncRequest(labels)
			if rec.status >= http.StatusBadRequest {
				cfg.Recorder.IncError(labels)
			}
			cfg.Recorder.ObserveLatency(labels, cfg.Now().Sub(start).Milliseconds())
		})
	}
}

func GRPCMetricsInterceptor(cfg MetricsConfig) grpc.UnaryServerInterceptor {
	cfg = resolveMetricsConfig(cfg)
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := cfg.Now()
		resp, err := handler(ctx, req)
		code := status.Code(err).String()
		labels := MetricLabels{
			ServiceName: cfg.ServiceName,
			Endpoint:    normalizeEndpoint(info.FullMethod),
			Method:      "grpc",
			StatusCode:  code,
		}
		cfg.Recorder.IncRequest(labels)
		if code != "OK" {
			cfg.Recorder.IncError(labels)
		}
		cfg.Recorder.ObserveLatency(labels, cfg.Now().Sub(start).Milliseconds())
		return resp, err
	}
}

type metricsStatusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *metricsStatusRecorder) WriteHeader(statusCode int) {
	w.status = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func resolveMetricsConfig(cfg MetricsConfig) MetricsConfig {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "unknown"
	}
	if cfg.Recorder == nil {
		cfg.Recorder = NewInMemoryMetrics()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return cfg
}
