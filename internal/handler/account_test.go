package handler

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/focalcrest/acme-relay/internal/acme"
)

func TestNewAccount(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jose.JSONWebKey{Key: key.Public()}

	// Sign a new-account request with embedded JWK
	nonce, _ := h.nonceSvc.Generate()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		&jose.SignerOptions{
			EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url":   "https://acme.example.com/acme/new-account",
				"nonce": nonce,
			},
		},
	)

	payload, _ := json.Marshal(map[string]interface{}{
		"termsOfServiceAgreed": true,
		"email":                "test@example.com",
	})
	jwsObj, _ := signer.Sign(payload)
	jwsBody, _ := jwsObj.CompactSerialize()

	// Parse JWS to get context
	jwsReq, err := acme.VerifyJWS([]byte(jwsBody), "https://acme.example.com/acme/new-account", h.nonceSvc, nil)
	if err != nil {
		t.Fatalf("VerifyJWS failed: %v", err)
	}

	req := httptest.NewRequest("POST", "/acme/new-account", bytes.NewReader([]byte(jwsBody)))
	req = acme.SetJWSInContext(req, jwsReq)

	rec := httptest.NewRecorder()
	h.NewAccount(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	if location == "" {
		t.Error("Location header should be set")
	}

	var resp accountResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Status != acme.AccountStatusValid {
		t.Errorf("status = %q, want %q", resp.Status, acme.AccountStatusValid)
	}

	// Verify account was stored
	thumbprint, _ := acme.ComputeJWKThumbprint(&jwk)
	stored, err := store.GetAccountByJWK(thumbprint)
	if err != nil {
		t.Fatalf("account not found by JWK: %v", err)
	}
	if stored.Email != "test@example.com" {
		t.Errorf("email = %q, want test@example.com", stored.Email)
	}
}

func TestNewAccount_ExistingKey(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jose.JSONWebKey{Key: key.Public()}
	jwkJSON, _ := jwk.MarshalJSON()
	thumbprint, _ := acme.ComputeJWKThumbprint(&jwk)

	// Pre-create account
	existing := &acme.Account{
		ID:        h.idGen.Next(),
		Status:    acme.AccountStatusValid,
		PublicKey: thumbprint,
		JWKJSON:   string(jwkJSON),
		Email:     "existing@example.com",
		CreatedAt: time.Now(),
	}
	store.SaveAccount(existing)

	// Try to create account with same key
	nonce, _ := h.nonceSvc.Generate()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		&jose.SignerOptions{
			EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url":   "https://acme.example.com/acme/new-account",
				"nonce": nonce,
			},
		},
	)

	payload, _ := json.Marshal(map[string]interface{}{
		"termsOfServiceAgreed": true,
	})
	jwsObj, _ := signer.Sign(payload)
	jwsBody, _ := jwsObj.CompactSerialize()

	jwsReq, _ := acme.VerifyJWS([]byte(jwsBody), "https://acme.example.com/acme/new-account", h.nonceSvc, nil)

	req := httptest.NewRequest("POST", "/acme/new-account", nil)
	req = acme.SetJWSInContext(req, jwsReq)
	rec := httptest.NewRecorder()

	h.NewAccount(rec, req)

	// Should return 200 with existing account
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	if location == "" {
		t.Error("Location header should be set for existing account")
	}
}

func TestNewAccount_TermsNotAgreed(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	nonce, _ := h.nonceSvc.Generate()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		&jose.SignerOptions{
			EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url":   "https://acme.example.com/acme/new-account",
				"nonce": nonce,
			},
		},
	)

	payload, _ := json.Marshal(map[string]interface{}{
		"termsOfServiceAgreed": false,
	})
	jwsObj, _ := signer.Sign(payload)
	jwsBody, _ := jwsObj.CompactSerialize()

	jwsReq, _ := acme.VerifyJWS([]byte(jwsBody), "https://acme.example.com/acme/new-account", h.nonceSvc, nil)

	req := httptest.NewRequest("POST", "/acme/new-account", nil)
	req = acme.SetJWSInContext(req, jwsReq)
	rec := httptest.NewRecorder()

	h.NewAccount(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
