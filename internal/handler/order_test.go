package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"

	"github.com/focalcrest/acme-relay/internal/acme"
)

func TestNewOrder(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jose.JSONWebKey{Key: key.Public()}
	jwkJSON, _ := jwk.MarshalJSON()
	thumbprint, _ := acme.ComputeJWKThumbprint(&jwk)

	account := &acme.Account{
		ID:        h.idGen.Next(),
		Status:    acme.AccountStatusValid,
		PublicKey: thumbprint,
		JWKJSON:   string(jwkJSON),
		CreatedAt: time.Now(),
	}
	store.SaveAccount(account)

	orderPayload, _ := json.Marshal(acme.OrderCreateRequest{
		Identifiers: []acme.Identifier{
			{Type: "dns", Value: "example.com"},
		},
	})

	nonce, _ := h.nonceSvc.Generate()
	signer, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url":   "https://acme.example.com/acme/new-order",
				"nonce": nonce,
				"kid":   "https://acme.example.com/acme/acct/" + itoa(account.ID),
			},
		},
	)
	jwsObj, _ := signer.Sign(orderPayload)
	jwsBody, _ := jwsObj.CompactSerialize()

	jwsReq, err := acme.VerifyJWS([]byte(jwsBody), "https://acme.example.com/acme/new-order", h.nonceSvc, store.GetAccountByKIDURL)
	if err != nil {
		t.Fatalf("VerifyJWS failed: %v", err)
	}

	req := httptest.NewRequest("POST", "/acme/new-order", nil)
	req = acme.SetJWSInContext(req, jwsReq)

	rec := httptest.NewRecorder()
	h.NewOrder(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp orderResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Status != acme.OrderStatusPending {
		t.Errorf("status = %q, want %q", resp.Status, acme.OrderStatusPending)
	}
	if len(resp.Identifiers) != 1 || resp.Identifiers[0].Value != "example.com" {
		t.Errorf("identifiers = %v, want [{dns example.com}]", resp.Identifiers)
	}
	if len(resp.Authorizations) != 1 {
		t.Errorf("expected 1 authorization URL, got %d", len(resp.Authorizations))
	}
	if resp.Finalize == "" {
		t.Error("finalize URL should be set")
	}
}

func TestGetOrder(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	order := &acme.Order{
		ID:        h.idGen.Next(),
		Status:    acme.OrderStatusPending,
		Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
		Authorizations: []string{"https://acme.example.com/acme/authz/1"},
		Finalize:  "https://acme.example.com/acme/order/" + itoa(1) + "/finalize",
		CreatedAt: time.Now(),
		AccountID: 1,
	}
	store.SaveOrder(order)

	// Use chi router to get URL params
	r := chi.NewRouter()
	r.Post("/acme/order/{id}", h.GetOrder)

	req := httptest.NewRequest("POST", "/acme/order/"+itoa(order.ID), nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 1})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp orderResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Status != acme.OrderStatusPending {
		t.Errorf("status = %q, want %q", resp.Status, acme.OrderStatusPending)
	}
}

func TestGetOrder_NotFound(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	r := chi.NewRouter()
	r.Post("/acme/order/{id}", h.GetOrder)

	req := httptest.NewRequest("POST", "/acme/order/999", nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 1})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestDomainsMatch(t *testing.T) {
	tests := []struct {
		name        string
		identifiers []acme.Identifier
		domains     []string
		want        bool
	}{
		{
			name:        "exact match",
			identifiers: []acme.Identifier{{Type: "dns", Value: "a.com"}},
			domains:     []string{"a.com"},
			want:        true,
		},
		{
			name:        "multiple match",
			identifiers: []acme.Identifier{{Type: "dns", Value: "a.com"}, {Type: "dns", Value: "b.com"}},
			domains:     []string{"a.com", "b.com"},
			want:        true,
		},
		{
			name:        "extra domain in CSR",
			identifiers: []acme.Identifier{{Type: "dns", Value: "a.com"}},
			domains:     []string{"a.com", "extra.com"},
			want:        false,
		},
		{
			name:        "missing domain in CSR",
			identifiers: []acme.Identifier{{Type: "dns", Value: "a.com"}, {Type: "dns", Value: "b.com"}},
			domains:     []string{"a.com"},
			want:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := domainsMatch(tt.identifiers, tt.domains); got != tt.want {
				t.Errorf("domainsMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}
