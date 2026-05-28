package main

import (
	"context"
	"log"

	"github.com/nhanpnt22/middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func main() {
	authInterceptor, err := middleware.GRPCAuthenticationInterceptorStrict(middleware.GRPCAuthConfig{
		Authenticator: middleware.StaticTokenAuthenticator{
			ExpectedToken: "demo-token",
			Identity:      middleware.Identity{ID: "demo-client", Type: "client", Level: "L1"},
		},
		AllowAnonymous: func(string) bool { return false },
	})
	if err != nil {
		log.Fatalf("auth interceptor setup failed: %v", err)
	}

	validationInterceptor, err := middleware.GRPCValidationInterceptorStrict(middleware.GRPCValidationConfig{
		MaxRequestBytes:  1 << 20,
		RequireRequestID: true,
		RequestIDHeader:  "x-request-id",
	})
	if err != nil {
		log.Fatalf("validation interceptor setup failed: %v", err)
	}

	interceptor := middleware.ChainInterceptors(
		middleware.GRPCPanicRecoveryInterceptor(),
		middleware.GRPCTracingInterceptor(middleware.DefaultTracingConfig()),
		authInterceptor,
		validationInterceptor,
	)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer demo-token",
		"x-request-id", "req-1",
	))
	_, _ = interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/example.Demo/Ping"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	})
}
