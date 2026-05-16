package middleware

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type RateLimitDecision struct {
	Allowed     bool
	Limit       int
	Remaining   int
	ResetAt     time.Time
	RetryAfterS int64
}

type RateLimiter interface {
	Decide(ctx context.Context, key string, now time.Time) (RateLimitDecision, error)
}

type FixedWindowLimiter struct {
	limit  int
	window time.Duration
	mu     sync.Mutex
	now    func() time.Time
	slots  map[string]fixedWindowSlot
}

type fixedWindowSlot struct {
	windowStart time.Time
	count       int
}

func NewFixedWindowLimiter(limit int, window time.Duration, now func() time.Time) *FixedWindowLimiter {
	if limit <= 0 {
		limit = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	if now == nil {
		now = time.Now
	}
	return &FixedWindowLimiter{
		limit:  limit,
		window: window,
		now:    now,
		slots:  make(map[string]fixedWindowSlot),
	}
}

func (l *FixedWindowLimiter) Decide(_ context.Context, key string, now time.Time) (RateLimitDecision, error) {
	if strings.TrimSpace(key) == "" {
		key = "anonymous"
	}
	if now.IsZero() {
		now = l.now()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	slot := l.slots[key]
	if slot.windowStart.IsZero() || now.Sub(slot.windowStart) >= l.window {
		slot = fixedWindowSlot{windowStart: now, count: 0}
	}
	resetAt := slot.windowStart.Add(l.window)

	if slot.count >= l.limit {
		retry := int64(resetAt.Sub(now).Seconds())
		if retry < 1 {
			retry = 1
		}
		return RateLimitDecision{
			Allowed:     false,
			Limit:       l.limit,
			Remaining:   0,
			ResetAt:     resetAt,
			RetryAfterS: retry,
		}, nil
	}

	slot.count++
	l.slots[key] = slot
	remaining := l.limit - slot.count
	if remaining < 0 {
		remaining = 0
	}
	return RateLimitDecision{
		Allowed:     true,
		Limit:       l.limit,
		Remaining:   remaining,
		ResetAt:     resetAt,
		RetryAfterS: 0,
	}, nil
}

type HTTPRateLimitConfig struct {
	Limiter RateLimiter
	Now     func() time.Time
	KeyFunc func(r *http.Request) string
}

type GRPCRateLimitConfig struct {
	Limiter RateLimiter
	Now     func() time.Time
	KeyFunc func(ctx context.Context, method string) string
}

func HTTPRateLimitMiddleware(cfg HTTPRateLimitConfig) func(http.Handler) http.Handler {
	cfg = resolveHTTPRateLimitConfig(cfg)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := cfg.KeyFunc(r)
			decision, err := cfg.Limiter.Decide(r.Context(), key, cfg.Now())
			if err != nil {
				writeRateLimitFailure(w)
				return
			}
			setRateLimitHeaders(w, decision)
			if !decision.Allowed {
				w.Header().Set("Retry-After", strconv.FormatInt(decision.RetryAfterS, 10))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(ErrorResponse{Code: "RATE_LIMIT_EXCEEDED", Type: "client", Message: "too many requests", Retryable: true})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func GRPCRateLimitInterceptor(cfg GRPCRateLimitConfig) grpc.UnaryServerInterceptor {
	cfg = resolveGRPCRateLimitConfig(cfg)
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		key := cfg.KeyFunc(ctx, info.FullMethod)
		decision, err := cfg.Limiter.Decide(ctx, key, cfg.Now())
		if err != nil {
			return nil, status.Error(codes.ResourceExhausted, "rate limit backend failure")
		}
		if !decision.Allowed {
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(ctx, req)
	}
}

func resolveHTTPRateLimitConfig(cfg HTTPRateLimitConfig) HTTPRateLimitConfig {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Limiter == nil {
		cfg.Limiter = NewFixedWindowLimiter(1000, time.Minute, cfg.Now)
	}
	if cfg.KeyFunc == nil {
		cfg.KeyFunc = func(r *http.Request) string {
			identity := IdentityFromContext(r.Context())
			if identity.ID != "" {
				return strings.ToLower(identity.Level) + ":" + identity.ID
			}
			if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
				return "addr:" + host
			}
			if strings.TrimSpace(r.RemoteAddr) != "" {
				return "addr:" + strings.TrimSpace(r.RemoteAddr)
			}
			return "anonymous"
		}
	}
	return cfg
}

func resolveGRPCRateLimitConfig(cfg GRPCRateLimitConfig) GRPCRateLimitConfig {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Limiter == nil {
		cfg.Limiter = NewFixedWindowLimiter(1000, time.Minute, cfg.Now)
	}
	if cfg.KeyFunc == nil {
		cfg.KeyFunc = func(ctx context.Context, method string) string {
			identity := IdentityFromContext(ctx)
			if identity.ID != "" {
				return strings.ToLower(identity.Level) + ":" + identity.ID
			}
			return method
		}
	}
	return cfg
}

func setRateLimitHeaders(w http.ResponseWriter, decision RateLimitDecision) {
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(decision.Limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(decision.Remaining))
	if !decision.ResetAt.IsZero() {
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(decision.ResetAt.Unix(), 10))
	}
}

func writeRateLimitFailure(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Code: "RATE_LIMIT_BACKEND_FAILURE", Type: "server", Message: "rate limit backend failure", Retryable: true})
}
