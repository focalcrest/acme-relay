// Package middleware provides HTTP middleware for acme-relay.
package middleware

import (
	"net/http"
	"strings"
)

// APIKeyAuth returns middleware that validates Bearer token authentication.
func APIKeyAuth(validTokens map[string]bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" || !validTokens[token] {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"unauthorized","code":401}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractBearerToken extracts the token from an Authorization: Bearer <token> header.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}

	return strings.TrimSpace(parts[1])
}
