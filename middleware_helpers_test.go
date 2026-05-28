package middleware

import (
	"context"
	"errors"
	"time"
)

type stubRateLimiter struct{}

func (stubRateLimiter) Decide(context.Context, string, time.Time) (RateLimitDecision, error) {
	return RateLimitDecision{Allowed: true, Limit: 1, Remaining: 0, ResetAt: time.Now().Add(time.Minute)}, nil
}

type stubClaimsVerifier struct {
	claims map[string]interface{}
	err    error
}

func (s stubClaimsVerifier) VerifyToken(context.Context, string) (map[string]interface{}, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.claims, nil
}

type stubSessionValidator struct{ err error }

func (s stubSessionValidator) ValidateSession(context.Context, string, string, string, string) error {
	return s.err
}

type stubIdentityValidator struct{ err error }

func (s stubIdentityValidator) ValidateIdentity(context.Context, string, string, string) error {
	return s.err
}

type failingBreaker struct{}

func (failingBreaker) Allow(context.Context, string) error   { return errors.New("open") }
func (failingBreaker) Record(context.Context, string, error) {}
