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

func TestJWSWithJWKMiddleware(t *testing.T) {
	nonceSvc := NewNonceService()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		jws := JWSFromContext(r)
		if jws == nil {
			t.Error("JWS should be in context")
		}
		if jws.JWK == nil {
			t.Error("JWK should be populated")
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := JWSWithJWKMiddleware(nonceSvc)(next)

	nonce, _ := nonceSvc.Generate()
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
	payload, _ := json.Marshal(map[string]interface{}{"test": true})
	jwsObj, _ := signer.Sign(payload)
	serialized, _ := jwsObj.CompactSerialize()

	req := httptest.NewRequest("POST", "/acme/new-account", io.NopCloser(bytes.NewReader([]byte(serialized))))
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("next handler should have been called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestJWSWithJWKMiddleware_InvalidBody(t *testing.T) {
	nonceSvc := NewNonceService()

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := JWSWithJWKMiddleware(nonceSvc)(next)

	req := httptest.NewRequest("POST", "/acme/new-account", io.NopCloser(bytes.NewReader([]byte("not-jws"))))
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should not have been called")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestJWSMiddleware_InvalidBody(t *testing.T) {
	nonceSvc := NewNonceService()

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := JWSMiddleware(nonceSvc, nil)(next)

	req := httptest.NewRequest("POST", "/acme/test", io.NopCloser(bytes.NewReader([]byte("not-jws"))))
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should not have been called")
	}
}

func TestSetJWSInContext(t *testing.T) {
	jws := &JWSRequest{AccountID: 42}
	req := httptest.NewRequest("GET", "/", nil)
	req = SetJWSInContext(req, jws)

	got := JWSFromContext(req)
	if got == nil {
		t.Fatal("JWSFromContext should return non-nil")
	}
	if got.AccountID != 42 {
		t.Errorf("AccountID = %d, want 42", got.AccountID)
	}
}

func TestVerifyJWS_KIDLookupFailure(t *testing.T) {
	nonceSvc := NewNonceService()
	nonce, _ := nonceSvc.Generate()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url":   "http://example.com/acme/test",
				"nonce": nonce,
				"kid":   "http://example.com/acme/acct/999",
			},
		},
	)
	payload, _ := json.Marshal(map[string]string{"test": "data"})
	jwsObj, _ := signer.Sign(payload)
	serialized, _ := jwsObj.CompactSerialize()

	lookup := func(kid string) (*Account, error) {
		return nil, fmt.Errorf("account not found")
	}

	_, err := VerifyJWS([]byte(serialized), "http://example.com/acme/test", nonceSvc, lookup)
	if err == nil {
		t.Fatal("expected error for KID lookup failure")
	}
	prob, ok := err.(*Problem)
	if !ok {
		t.Fatalf("expected *Problem, got %T", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:accountDoesNotExist" {
		t.Errorf("error type = %s, want accountDoesNotExist", prob.Type)
	}
}

func TestVerifyJWS_AccountNoJWK(t *testing.T) {
	nonceSvc := NewNonceService()
	nonce, _ := nonceSvc.Generate()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url":   "http://example.com/acme/test",
				"nonce": nonce,
				"kid":   "http://example.com/acme/acct/1",
			},
		},
	)
	payload, _ := json.Marshal(map[string]string{"test": "data"})
	jwsObj, _ := signer.Sign(payload)
	serialized, _ := jwsObj.CompactSerialize()

	account := &Account{ID: 1, Status: AccountStatusValid, JWKJSON: ""}
	lookup := func(kid string) (*Account, error) {
		return account, nil
	}

	_, err := VerifyJWS([]byte(serialized), "http://example.com/acme/test", nonceSvc, lookup)
	if err == nil {
		t.Fatal("expected error for account with no JWK")
	}
}

func TestVerifyJWS_AccountInvalidJWK(t *testing.T) {
	nonceSvc := NewNonceService()
	nonce, _ := nonceSvc.Generate()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url":   "http://example.com/acme/test",
				"nonce": nonce,
				"kid":   "http://example.com/acme/acct/1",
			},
		},
	)
	payload, _ := json.Marshal(map[string]string{"test": "data"})
	jwsObj, _ := signer.Sign(payload)
	serialized, _ := jwsObj.CompactSerialize()

	account := &Account{ID: 1, Status: AccountStatusValid, JWKJSON: "not-valid-json"}
	lookup := func(kid string) (*Account, error) {
		return account, nil
	}

	_, err := VerifyJWS([]byte(serialized), "http://example.com/acme/test", nonceSvc, lookup)
	if err == nil {
		t.Fatal("expected error for invalid JWK")
	}
}

func TestVerifyJWS_NoKIDNoJWK(t *testing.T) {
	nonceSvc := NewNonceService()
	nonce, _ := nonceSvc.Generate()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url":   "http://example.com/acme/test",
				"nonce": nonce,
			},
		},
	)
	payload, _ := json.Marshal(map[string]string{"test": "data"})
	jwsObj, _ := signer.Sign(payload)
	serialized, _ := jwsObj.CompactSerialize()

	_, err := VerifyJWS([]byte(serialized), "http://example.com/acme/test", nonceSvc, nil)
	if err == nil {
		t.Fatal("expected error - no kid and no jwk (EmbedJWK defaults to false)")
	}
}
