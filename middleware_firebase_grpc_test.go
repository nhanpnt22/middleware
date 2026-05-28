package middleware

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestGRPCFirebaseAuthInterceptor_SessionValidationFailure(t *testing.T) {
	now := time.Now().Add(5 * time.Minute).Unix()
	interceptor := GRPCFirebaseAuthInterceptor(FirebaseAuthMiddlewareConfig{
		Verifier: stubClaimsVerifier{claims: map[string]interface{}{
			"iss": "https://securetoken.google.com/p1",
			"aud": "p1",
			"uid": "u1",
			"exp": float64(now),
			"claims": map[string]interface{}{
				"role":        "user",
				"identity_id": "idn1",
				"platform":    "web",
				"device_id":   "dev1",
				"session_id":  "ses1",
				"provider":    "whatsapp",
			},
		}},
		ProjectID:         "p1",
		SessionValidator:  stubSessionValidator{err: errors.New("not active")},
		IdentityValidator: stubIdentityValidator{},
	})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer token"))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", status.Code(err))
	}
}

func TestGRPCFirebaseAuthInterceptor_IdentityValidationFailure(t *testing.T) {
	now := time.Now().Add(5 * time.Minute).Unix()
	interceptor := GRPCFirebaseAuthInterceptor(FirebaseAuthMiddlewareConfig{
		Verifier: stubClaimsVerifier{claims: map[string]interface{}{
			"iss": "https://securetoken.google.com/p1",
			"aud": "p1",
			"uid": "u1",
			"exp": float64(now),
			"claims": map[string]interface{}{
				"role":        "user",
				"identity_id": "idn1",
				"platform":    "web",
				"device_id":   "dev1",
				"session_id":  "ses1",
				"provider":    "whatsapp",
			},
		}},
		ProjectID:         "p1",
		SessionValidator:  stubSessionValidator{},
		IdentityValidator: stubIdentityValidator{err: errors.New("identity mismatch")},
	})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer token"))
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/svc/Method"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", status.Code(err))
	}
}
