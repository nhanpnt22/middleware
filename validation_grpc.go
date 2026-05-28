package middleware

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func GRPCValidationInterceptor(cfg GRPCValidationConfig) grpc.UnaryServerInterceptor {
	cfg = resolveGRPCValidationConfig(cfg)
	return grpcValidationInterceptor(cfg)
}

// GRPCValidationInterceptorStrict builds an interceptor without implicit defaults.
func GRPCValidationInterceptorStrict(cfg GRPCValidationConfig) (grpc.UnaryServerInterceptor, error) {
	if err := ValidateGRPCValidationConfigStrict(cfg); err != nil {
		return nil, err
	}
	return grpcValidationInterceptor(cfg), nil
}

func grpcValidationInterceptor(cfg GRPCValidationConfig) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		var err error
		ctx, err = validateGRPCMiddlewareContext(ctx, md, info.FullMethod, cfg)
		if err != nil {
			return nil, err
		}
		if err := validateGRPCRequestSize(req, cfg.MaxRequestBytes); err != nil {
			return nil, err
		}
		if cfg.ValidateRequest != nil {
			if err := cfg.ValidateRequest(ctx, info.FullMethod, req); err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
		}
		return handler(ctx, req)
	}
}

func validateGRPCMiddlewareContext(ctx context.Context, md metadata.MD, fullMethod string, cfg GRPCValidationConfig) (context.Context, error) {
	var err error

	if ctx, err = injectGRPCRequestID(ctx, md, cfg); err != nil {
		return nil, err
	}
	if ctx, err = injectGRPCAppID(ctx, md, cfg); err != nil {
		return nil, err
	}
	if ctx, err = injectGRPCSessionID(ctx, md, cfg); err != nil {
		return nil, err
	}
	if ctx, err = injectGRPCIdempotencyKey(ctx, md, fullMethod, cfg); err != nil {
		return nil, err
	}

	return ctx, nil
}

func injectGRPCRequestID(ctx context.Context, md metadata.MD, cfg GRPCValidationConfig) (context.Context, error) {
	if !cfg.RequireRequestID {
		return ctx, nil
	}

	requestIDHeader := strings.ToLower(strings.TrimSpace(cfg.RequestIDHeader))
	requestID := Value(ctx, RequestIDKey)
	if requestID == "" {
		requestID = first(md.Get(requestIDHeader))
	}
	if requestID == "" {
		return nil, status.Error(codes.InvalidArgument, requiredHeaderMessage(cfg.RequestIDHeader))
	}

	return WithValueIfAbsent(ctx, RequestIDKey, requestID), nil
}

func injectGRPCAppID(ctx context.Context, md metadata.MD, cfg GRPCValidationConfig) (context.Context, error) {
	if !cfg.RequireAppID {
		return ctx, nil
	}

	appID := Value(ctx, AppIDKey)
	if appID == "" {
		appID = first(md.Get(strings.ToLower(cfg.AppIDHeader)))
	}
	if appID == "" {
		return nil, status.Error(codes.InvalidArgument, requiredHeaderMessage(cfg.AppIDHeader))
	}

	return WithValueIfAbsent(ctx, AppIDKey, appID), nil
}

func injectGRPCSessionID(ctx context.Context, md metadata.MD, cfg GRPCValidationConfig) (context.Context, error) {
	if !cfg.RequireSessionID {
		return ctx, nil
	}

	sessionID := Value(ctx, SessionIDKey)
	if sessionID == "" {
		sessionID = first(md.Get(strings.ToLower(cfg.SessionHeader)))
	}
	if sessionID == "" {
		return nil, status.Error(codes.InvalidArgument, requiredHeaderMessage(cfg.SessionHeader))
	}

	return WithValueIfAbsent(ctx, SessionIDKey, sessionID), nil
}

func injectGRPCIdempotencyKey(ctx context.Context, md metadata.MD, fullMethod string, cfg GRPCValidationConfig) (context.Context, error) {
	if !cfg.RequireIdempotencyForMutations || !cfg.IsMutation(fullMethod) {
		return ctx, nil
	}

	primaryHeader := strings.ToLower(strings.TrimSpace(cfg.IdempotencyHeader))
	secondaryHeader := strings.ToLower(strings.TrimSpace(cfg.AltIdempotencyHeader))
	idempotencyKey := first(md.Get(primaryHeader))
	if idempotencyKey == "" {
		idempotencyKey = first(md.Get(secondaryHeader))
	}
	if idempotencyKey == "" {
		return nil, status.Error(codes.InvalidArgument, requiredHeaderMessage(cfg.IdempotencyHeader))
	}

	return WithValueIfAbsent(ctx, IdempotencyKeyKey, idempotencyKey), nil
}

func validateGRPCRequestSize(req interface{}, maxRequestBytes int) error {
	if maxRequestBytes <= 0 {
		return nil
	}

	message, ok := req.(proto.Message)
	if !ok {
		return nil
	}
	if proto.Size(message) > maxRequestBytes {
		return status.Error(codes.InvalidArgument, "request too large")
	}

	return nil
}

func resolveGRPCValidationConfig(cfg GRPCValidationConfig) GRPCValidationConfig {
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = 1 << 20
	}
	if strings.TrimSpace(cfg.RequestIDHeader) == "" {
		cfg.RequestIDHeader = grpcHeaderRequestID
	}
	if strings.TrimSpace(cfg.AppIDHeader) == "" {
		cfg.AppIDHeader = "x-app-id"
	}
	if strings.TrimSpace(cfg.SessionHeader) == "" {
		cfg.SessionHeader = "x-session-id"
	}
	if strings.TrimSpace(cfg.IdempotencyHeader) == "" {
		cfg.IdempotencyHeader = grpcHeaderIdempotencyKey
	}
	if strings.TrimSpace(cfg.AltIdempotencyHeader) == "" {
		cfg.AltIdempotencyHeader = grpcHeaderAltIdempotencyKey
	}
	if cfg.IsMutation == nil {
		cfg.IsMutation = defaultIsMutationMethod
	}
	return cfg
}
