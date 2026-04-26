package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// signJWS is a test helper that signs payload and returns compact JWS serialization.
func signJWS(t *testing.T, key *ecdsa.PrivateKey, headers map[jose.HeaderKey]interface{}) []byte {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		&jose.SignerOptions{ExtraHeaders: headers},
	)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	payload, _ := json.Marshal(map[string]string{"test": "data"})
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	serialized, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("failed to serialize JWS: %v", err)
	}
	return []byte(serialized)
}

func TestComputeJWKThumbprint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	jwk := jose.JSONWebKey{Key: key.Public()}

	tp, err := ComputeJWKThumbprint(&jwk)
	if err != nil {
		t.Fatalf("ComputeJWKThumbprint() error: %v", err)
	}
	if tp == "" {
		t.Fatal("thumbprint should not be empty")
	}

	tp2, err := ComputeJWKThumbprint(&jwk)
	if err != nil {
		t.Fatalf("second ComputeJWKThumbprint() error: %v", err)
	}
	if tp != tp2 {
		t.Errorf("thumbprints differ: %s vs %s", tp, tp2)
	}
}

func TestVerifyJWS_MissingNonce(t *testing.T) {
	nonceSvc := NewNonceService()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwsBody := signJWS(t, key, map[jose.HeaderKey]interface{}{
		"url": "http://example.com/acme/test",
	})

	_, err := VerifyJWS(jwsBody, "http://example.com/acme/test", nonceSvc, nil)
	if err == nil {
		t.Fatal("expected error for missing nonce")
	}
	prob, ok := err.(*Problem)
	if !ok {
		t.Fatalf("expected *Problem, got %T", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:badNonce" {
		t.Errorf("error type = %s, want badNonce", prob.Type)
	}
}

func TestVerifyJWS_InvalidNonce(t *testing.T) {
	nonceSvc := NewNonceService()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwsBody := signJWS(t, key, map[jose.HeaderKey]interface{}{
		"url":   "http://example.com/acme/test",
		"nonce": "invalid-nonce",
	})

	_, err := VerifyJWS(jwsBody, "http://example.com/acme/test", nonceSvc, nil)
	if err == nil {
		t.Fatal("expected error for invalid nonce")
	}
}

func TestVerifyJWS_URLMismatch(t *testing.T) {
	nonceSvc := NewNonceService()
	nonce, _ := nonceSvc.Generate()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwsBody := signJWS(t, key, map[jose.HeaderKey]interface{}{
		"url":   "http://example.com/acme/wrong",
		"nonce": nonce,
	})

	_, err := VerifyJWS(jwsBody, "http://example.com/acme/test", nonceSvc, nil)
	if err == nil {
		t.Fatal("expected error for URL mismatch")
	}
}

func TestVerifyJWS_ValidJWKAuth(t *testing.T) {
	nonceSvc := NewNonceService()
	nonce, _ := nonceSvc.Generate()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		&jose.SignerOptions{
			EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url":   "http://example.com/acme/new-account",
				"nonce": nonce,
			},
		},
	)
	payload, _ := json.Marshal(map[string]interface{}{"termsOfServiceAgreed": true})
	jwsObj, _ := signer.Sign(payload)
	serialized, _ := jwsObj.CompactSerialize()

	result, err := VerifyJWS([]byte(serialized), "http://example.com/acme/new-account", nonceSvc, nil)
	if err != nil {
		t.Fatalf("VerifyJWS() error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if result.JWK == nil {
		t.Fatal("JWK should be populated")
	}
}

func TestJWSMiddleware_KIDAuth(t *testing.T) {
	nonceSvc := NewNonceService()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwk := jose.JSONWebKey{Key: key.Public()}
	jwkJSON, _ := jwk.MarshalJSON()

	account := &Account{
		ID:      1,
		Status:  AccountStatusValid,
		JWKJSON: string(jwkJSON),
	}

	lookup := func(kid string) (*Account, error) {
		if kid == "http://example.com/acme/acct/1" {
			return account, nil
		}
		return nil, fmt.Errorf("not found")
	}

	called := false
	handler := JWSMiddleware(nonceSvc, lookup)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		jws := JWSFromContext(r)
		if jws == nil {
			t.Error("JWS should be in context")
		}
		if jws.AccountID != 1 {
			t.Errorf("AccountID = %d, want 1", jws.AccountID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	nonce, _ := nonceSvc.Generate()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url":   "http://example.com/acme/acct/1",
				"nonce": nonce,
				"kid":   "http://example.com/acme/acct/1",
			},
		},
	)
	payload, _ := json.Marshal(map[string]interface{}{})
	jws, _ := signer.Sign(payload)
	serialized, _ := jws.CompactSerialize()

	req := httptest.NewRequest("POST", "/acme/acct/1", io.NopCloser(bytes.NewReader([]byte(serialized))))
	req.Host = "example.com"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("next handler should have been called")
	}
}

func TestJWSFromContext_Nil(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if jws := JWSFromContext(req); jws != nil {
		t.Error("should return nil for request without JWS context")
	}
}
