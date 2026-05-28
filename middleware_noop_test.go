package middleware

import (
	"context"
	"testing"
	"time"
)

func TestNoopLogSinkImplementsLogSink(t *testing.T) {
	var sink LogSink = NewNoopLogSink()
	sink.Log(context.Background(), map[string]interface{}{"message": "ignored"})
}

func TestNoopMetricsRecorderImplementsRecorder(t *testing.T) {
	var recorder MetricsRecorder = NewNoopMetricsRecorder()
	labels := MetricLabels{ServiceName: "svc", Endpoint: "/health", Method: "GET", StatusCode: "200"}
	recorder.IncRequest(labels)
	recorder.IncError(labels)
	recorder.ObserveLatency(labels, 5)
}

func TestStrictValidationAcceptsNoopImplementations(t *testing.T) {
	err := ValidateLoggingConfigStrict(LoggingConfig{
		ServiceName:       "middleware",
		Environment:       EnvironmentTesting,
		Logger:            NewNoopLogSink(),
		Now:               time.Now,
		NormalizeEndpoint: normalizeEndpoint,
	})
	if err != nil {
		t.Fatalf("expected noop logger strict config to be valid, got %v", err)
	}

	err = ValidateMetricsConfigStrict(MetricsConfig{
		ServiceName: "middleware",
		Recorder:    NewNoopMetricsRecorder(),
		Now:         time.Now,
	})
	if err != nil {
		t.Fatalf("expected noop metrics strict config to be valid, got %v", err)
	}
}
