package acme

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-jose/go-jose/v4"
)

// SupportedJWSSignatures defines the JWS algorithms accepted by this server.
var SupportedJWSSignatures = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.RS256, jose.PS256,
}

// JWSRequest holds parsed JWS verification results, stored in request context.
type JWSRequest struct {
	Header    jose.Header
	Payload   []byte
	KID       string
	JWK       *jose.JSONWebKey
	AccountID int64
}

type contextKey string

const jwsContextKey contextKey = "jws"

// JWSFromContext retrieves the JWS result from request context.
func JWSFromContext(r *http.Request) *JWSRequest {
	val := r.Context().Value(jwsContextKey)
	if val == nil {
		return nil
	}
	return val.(*JWSRequest)
}

// SetJWSInContext stores the JWS result in the request context.
func SetJWSInContext(r *http.Request, jws *JWSRequest) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), jwsContextKey, jws))
}

// AccountLookupFunc retrieves account JWK by account URL path (kid).
type AccountLookupFunc func(kid string) (*Account, error)

// VerifyJWS parses and verifies a JWS message from the request body.
func VerifyJWS(body []byte, requestURL string, nonceSvc *NonceService, accountLookup AccountLookupFunc) (*JWSRequest, error) {
	obj, err := jose.ParseSigned(string(body), SupportedJWSSignatures)
	if err != nil {
		return nil, &Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: fmt.Sprintf("failed to parse JWS: %v", err),
			Status: http.StatusBadRequest,
		}
	}

	if len(obj.Signatures) != 1 {
		return nil, &Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "JWS must have exactly one signature",
			Status: http.StatusBadRequest,
		}
	}

	sig := obj.Signatures[0]
	header := sig.Header

	// Validate nonce
	if header.Nonce == "" {
		return nil, &Problem{
			Type:   "urn:ietf:params:acme:error:badNonce",
			Detail: "missing Replay-Nonce in JWS protected header",
			Status: http.StatusBadRequest,
		}
	}
	if !nonceSvc.Validate(header.Nonce) {
		return nil, &Problem{
			Type:   "urn:ietf:params:acme:error:badNonce",
			Detail: "invalid or expired Replay-Nonce",
			Status: http.StatusBadRequest,
		}
	}

	// Validate URL matches request URL
	protectedURL, ok := header.ExtraHeaders["url"].(string)
	if !ok || protectedURL == "" {
		return nil, &Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "missing url in JWS protected header",
			Status: http.StatusBadRequest,
		}
	}
	if protectedURL != requestURL {
		return nil, &Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: fmt.Sprintf("JWS url %q does not match request url %q", protectedURL, requestURL),
			Status: http.StatusBadRequest,
		}
	}

	result := &JWSRequest{
		Header:  header,
		Payload: obj.UnsafePayloadWithoutVerification(),
	}

	if header.KeyID != "" {
		// kid-based: look up account
		result.KID = header.KeyID
		if accountLookup == nil {
			return nil, &Problem{
				Type:   "urn:ietf:params:acme:error:accountDoesNotExist",
				Detail: "account lookup not available",
				Status: http.StatusBadRequest,
			}
		}
		account, err := accountLookup(header.KeyID)
		if err != nil {
			return nil, &Problem{
				Type:   "urn:ietf:params:acme:error:accountDoesNotExist",
				Detail: "account not found",
				Status: http.StatusBadRequest,
			}
		}
		result.AccountID = account.ID

		if account.JWKJSON == "" {
			return nil, &Problem{
				Type:   "urn:ietf:params:acme:error:malformed",
				Detail: "account has no stored JWK",
				Status: http.StatusBadRequest,
			}
		}
		var jwk jose.JSONWebKey
		if err := json.Unmarshal([]byte(account.JWKJSON), &jwk); err != nil {
			return nil, &Problem{
				Type:   "urn:ietf:params:acme:error:malformed",
				Detail: "failed to parse account JWK",
				Status: http.StatusInternalServerError,
			}
		}
		if _, err := obj.Verify(&jwk); err != nil {
			return nil, &Problem{
				Type:   "urn:ietf:params:acme:error:malformed",
				Detail: "JWS signature verification failed",
				Status: http.StatusBadRequest,
			}
		}
		result.JWK = &jwk
	} else {
		// jwk-based: extract embedded JWK
		// go-jose may store it in header.JSONWebKey or header.ExtraHeaders["jwk"]
		var jwk *jose.JSONWebKey
		if header.JSONWebKey != nil {
			jwk = header.JSONWebKey
		} else if jwkData, ok := header.ExtraHeaders["jwk"].(json.RawMessage); ok {
			var parsed jose.JSONWebKey
			if err := json.Unmarshal(jwkData, &parsed); err != nil {
				return nil, &Problem{
					Type:   "urn:ietf:params:acme:error:malformed",
					Detail: "failed to parse JWK from protected header",
					Status: http.StatusBadRequest,
				}
			}
			jwk = &parsed
		}
		if jwk == nil {
			return nil, &Problem{
				Type:   "urn:ietf:params:acme:error:malformed",
				Detail: "JWS must contain either kid or jwk in protected header",
				Status: http.StatusBadRequest,
			}
		}
		if _, err := obj.Verify(jwk); err != nil {
			return nil, &Problem{
				Type:   "urn:ietf:params:acme:error:malformed",
				Detail: "JWS signature verification failed",
				Status: http.StatusBadRequest,
			}
		}
		result.JWK = jwk
	}

	return result, nil
}

// ComputeJWKThumbprint computes RFC 7638 JWK thumbprint.
func ComputeJWKThumbprint(jwk *jose.JSONWebKey) (string, error) {
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to compute JWK thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// JWSMiddleware validates JWS with kid-based auth (existing accounts).
func JWSMiddleware(nonceSvc *NonceService, accountLookup AccountLookupFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := readBody(r)
			if err != nil {
				writeProblem(w, &Problem{
					Type:   "urn:ietf:params:acme:error:malformed",
					Detail: "failed to read request body",
					Status: http.StatusBadRequest,
				})
				return
			}

			requestURL := getRequestURL(r)
			result, err := VerifyJWS(body, requestURL, nonceSvc, accountLookup)
			if err != nil {
				prob, ok := err.(*Problem)
				if !ok {
					prob = &Problem{
						Type:   "urn:ietf:params:acme:error:malformed",
						Detail: err.Error(),
						Status: http.StatusBadRequest,
					}
				}
				writeProblem(w, prob)
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), jwsContextKey, result)))
		})
	}
}

// JWSWithJWKMiddleware validates JWS with jwk-based auth (new-account only).
func JWSWithJWKMiddleware(nonceSvc *NonceService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := readBody(r)
			if err != nil {
				writeProblem(w, &Problem{
					Type:   "urn:ietf:params:acme:error:malformed",
					Detail: "failed to read request body",
					Status: http.StatusBadRequest,
				})
				return
			}

			requestURL := getRequestURL(r)
			result, err := VerifyJWS(body, requestURL, nonceSvc, nil)
			if err != nil {
				prob, ok := err.(*Problem)
				if !ok {
					prob = &Problem{
						Type:   "urn:ietf:params:acme:error:malformed",
						Detail: err.Error(),
						Status: http.StatusBadRequest,
					}
				}
				writeProblem(w, prob)
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), jwsContextKey, result)))
		})
	}
}

func readBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func getRequestURL(r *http.Request) string {
	if r.TLS != nil {
		return "https://" + r.Host + r.URL.Path
	}
	return "http://" + r.Host + r.URL.Path
}

func writeProblem(w http.ResponseWriter, p *Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	json.NewEncoder(w).Encode(p)
}
