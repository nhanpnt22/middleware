package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	bearerPrefix    = "Bearer "
	headerTypeName  = "Content-Type"
	jsonContentType = "application/json"
)

// parseBearerToken extracts the token value from an Authorization: Bearer <token> header.
func parseBearerToken(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}
	if len(header) < len(bearerPrefix) || !strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(bearerPrefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// writeHTTPAuthError writes a 401 response for invalid API-key or bearer-token authentication.
func writeHTTPAuthError(w http.ResponseWriter) {
	w.Header().Set(headerTypeName, jsonContentType)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Code: "AUTH_INVALID_TOKEN", Type: "client", Message: "authentication failed", Retryable: false})
}

// writeHTTPUnauthenticatedUser writes a 401 response for an unauthenticated user identity.
func writeHTTPUnauthenticatedUser(w http.ResponseWriter) {
	w.Header().Set(headerTypeName, jsonContentType)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Code: "UNAUTHENTICATED", Type: "user", Message: "unauthenticated", Retryable: false})
}

// writeHTTPForbidden writes a 403 response for an authenticated but unauthorized identity.
func writeHTTPForbidden(w http.ResponseWriter) {
	w.Header().Set(headerTypeName, jsonContentType)
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Code: "FORBIDDEN", Type: "user", Message: "forbidden", Retryable: false})
}

// levelRank maps an identity level string (L0–L4) to a comparable integer.
func levelRank(level string) int {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "L0":
		return 0
	case "L1":
		return 1
	case "L2":
		return 2
	case "L3":
		return 3
	case "L4":
		return 4
	default:
		return -1
	}
}

// stringClaim returns the trimmed string value of a top-level claims map entry.
func stringClaim(claims map[string]interface{}, key string) string {
	v, _ := claims[key].(string)
	return strings.TrimSpace(v)
}

// nestedStringClaim returns the trimmed string value at claims[parent][child].
func nestedStringClaim(claims map[string]interface{}, parent, child string) (string, bool) {
	raw, ok := claims[parent]
	if !ok {
		return "", false
	}
	obj, ok := raw.(map[string]interface{})
	if !ok {
		return "", false
	}
	v, ok := obj[child].(string)
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	return v, v != ""
}

// isExpValid returns true when the exp claim represents a Unix timestamp strictly after nowUnix.
func isExpValid(raw interface{}, nowUnix int64) bool {
	switch v := raw.(type) {
	case int64:
		return v > nowUnix
	case int:
		return int64(v) > nowUnix
	case float64:
		return int64(v) > nowUnix
	case json.Number:
		n, err := v.Int64()
		return err == nil && n > nowUnix
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return err == nil && n > nowUnix
	default:
		_ = fmt.Sprintf("%T", raw)
		return false
	}
}

// currentUnix resolves the injected clock or falls back to time.Now().Unix() (CODEX §XVIII).
func currentUnix(nowUnix func() int64) int64 {
	if nowUnix == nil {
		return time.Now().Unix()
	}
	return nowUnix()
}
