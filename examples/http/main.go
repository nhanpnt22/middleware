package main

import (
	"log"
	"net/http"

	"github.com/nhanpnt22/middleware"
)

func main() {
	authMW, err := middleware.HTTPAuthenticationMiddlewareStrict(middleware.HTTPAuthConfig{
		Authenticator: middleware.StaticTokenAuthenticator{
			ExpectedToken: "demo-token",
			Identity:      middleware.Identity{ID: "demo-client", Type: "client", Level: "L1"},
		},
		AllowAnonymous: func(r *http.Request) bool { return r.URL.Path == "/healthz" },
	})
	if err != nil {
		log.Fatalf("auth middleware setup failed: %v", err)
	}

	validationMW, err := middleware.HTTPValidationMiddlewareStrict(middleware.HTTPValidationConfig{
		MaxBodyBytes:     1 << 20,
		RequireRequestID: true,
		RequestIDHeader:  "X-Request-ID",
	})
	if err != nil {
		log.Fatalf("validation middleware setup failed: %v", err)
	}

	handler := middleware.ChainHTTP(
		middleware.HTTPPanicRecoveryMiddleware(),
		middleware.HTTPTracingMiddleware(middleware.DefaultTracingConfig()),
		authMW,
		validationMW,
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	_ = handler
}
