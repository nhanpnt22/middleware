package aipfirebase

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

var ErrUnauthorized = errors.New("unauthorized")

type TokenClaimsVerifier interface {
	VerifyToken(ctx context.Context, bearerToken string) (map[string]interface{}, error)
}

type SessionBindingValidator interface {
	ValidateSession(ctx context.Context, sessionID, userID, deviceID, provider string) error
}

type IdentityBindingValidator interface {
	ValidateIdentity(ctx context.Context, identityID, userID, provider string) error
}

type Config struct {
	Verifier          TokenClaimsVerifier
	ProjectID         string
	SessionValidator  SessionBindingValidator
	IdentityValidator IdentityBindingValidator
	NowUnix           func() int64
	RequiredRole      string
	RequiredPlatform  string
	AllowedProviders  map[string]struct{}
}

type VerifiedIdentity struct {
	UID        string
	IdentityID string
	SessionID  string
	DeviceID   string
	Provider   string
}

type claimsEnvelope struct {
	IdentityID string
	SessionID  string
	DeviceID   string
	Provider   string
}

func VerifyIdentity(ctx context.Context, cfg Config, bearerToken string) (VerifiedIdentity, error) {
	cfg = resolveConfig(cfg)
	if cfg.Verifier == nil || strings.TrimSpace(cfg.ProjectID) == "" || cfg.SessionValidator == nil || cfg.IdentityValidator == nil {
		return VerifiedIdentity{}, ErrUnauthorized
	}

	claims, err := cfg.Verifier.VerifyToken(ctx, bearerToken)
	if err != nil {
		return VerifiedIdentity{}, ErrUnauthorized
	}

	uid := claimString(claims, "uid")
	if uid == "" {
		return VerifiedIdentity{}, ErrUnauthorized
	}

	expectedIss := "https://securetoken.google.com/" + strings.TrimSpace(cfg.ProjectID)
	if claimString(claims, "iss") != expectedIss || claimString(claims, "aud") != strings.TrimSpace(cfg.ProjectID) {
		return VerifiedIdentity{}, ErrUnauthorized
	}
	if !isExpValid(claims["exp"], currentUnix(cfg.NowUnix)) {
		return VerifiedIdentity{}, ErrUnauthorized
	}

	envelope, err := extractAndValidateClaims(claims, cfg)
	if err != nil {
		return VerifiedIdentity{}, ErrUnauthorized
	}

	if err := cfg.SessionValidator.ValidateSession(ctx, envelope.SessionID, uid, envelope.DeviceID, envelope.Provider); err != nil {
		return VerifiedIdentity{}, ErrUnauthorized
	}
	if err := cfg.IdentityValidator.ValidateIdentity(ctx, envelope.IdentityID, uid, envelope.Provider); err != nil {
		return VerifiedIdentity{}, ErrUnauthorized
	}

	return VerifiedIdentity{
		UID:        uid,
		IdentityID: envelope.IdentityID,
		SessionID:  envelope.SessionID,
		DeviceID:   envelope.DeviceID,
		Provider:   envelope.Provider,
	}, nil
}

func resolveConfig(cfg Config) Config {
	if strings.TrimSpace(cfg.RequiredRole) == "" {
		cfg.RequiredRole = "user"
	}
	if strings.TrimSpace(cfg.RequiredPlatform) == "" {
		cfg.RequiredPlatform = "web"
	}
	cfg.AllowedProviders = normalizeAllowlist(cfg.AllowedProviders)
	if len(cfg.AllowedProviders) == 0 {
		cfg.AllowedProviders = map[string]struct{}{
			"zalo":     {},
			"whatsapp": {},
		}
	}
	return cfg
}

func normalizeAllowlist(allowlist map[string]struct{}) map[string]struct{} {
	normalized := map[string]struct{}{}
	for provider := range allowlist {
		key := strings.ToLower(strings.TrimSpace(provider))
		if key == "" {
			continue
		}
		normalized[key] = struct{}{}
	}
	return normalized
}

func extractAndValidateClaims(claims map[string]interface{}, cfg Config) (claimsEnvelope, error) {
	customClaims, ok := claims["claims"].(map[string]interface{})
	if !ok {
		customClaims = map[string]interface{}{}
		for _, key := range []string{"role", "identity_id", "platform", "device_id", "session_id", "provider"} {
			if value, exists := claims[key]; exists {
				customClaims[key] = value
			}
		}
	}

	allowedKeys := map[string]struct{}{
		"role": {}, "identity_id": {}, "platform": {}, "device_id": {}, "session_id": {}, "provider": {},
	}
	for key := range customClaims {
		if _, allowed := allowedKeys[key]; !allowed {
			return claimsEnvelope{}, ErrUnauthorized
		}
	}

	role := claimString(customClaims, "role")
	platform := claimString(customClaims, "platform")
	identityID := claimString(customClaims, "identity_id")
	deviceID := claimString(customClaims, "device_id")
	sessionID := claimString(customClaims, "session_id")
	provider := strings.ToLower(claimString(customClaims, "provider"))
	if role != cfg.RequiredRole || platform != cfg.RequiredPlatform || identityID == "" || deviceID == "" || sessionID == "" || provider == "" {
		return claimsEnvelope{}, ErrUnauthorized
	}
	if _, ok := cfg.AllowedProviders[provider]; !ok {
		return claimsEnvelope{}, ErrUnauthorized
	}

	return claimsEnvelope{
		IdentityID: identityID,
		SessionID:  sessionID,
		DeviceID:   deviceID,
		Provider:   provider,
	}, nil
}

func claimString(claims map[string]interface{}, key string) string {
	value, _ := claims[key].(string)
	return strings.TrimSpace(value)
}

func isExpValid(raw interface{}, nowUnix int64) bool {
	switch value := raw.(type) {
	case int64:
		return value > nowUnix
	case int:
		return int64(value) > nowUnix
	case float64:
		return int64(value) > nowUnix
	case json.Number:
		number, err := value.Int64()
		return err == nil && number > nowUnix
	case string:
		number, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		return err == nil && number > nowUnix
	default:
		return false
	}
}

func currentUnix(nowUnix func() int64) int64 {
	if nowUnix == nil {
		return time.Now().Unix()
	}
	return nowUnix()
}
