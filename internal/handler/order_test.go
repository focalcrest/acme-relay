package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"

	"github.com/focalcrest/acme-relay/internal/acme"
	"github.com/focalcrest/acme-relay/internal/storage"
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

// newOrderForIdentifiers drives NewOrder end-to-end for the given
// identifiers and returns the parsed order response.
func newOrderForIdentifiers(t *testing.T, h *ACMEHandler, store *storage.FilesystemStorage, identifiers []acme.Identifier) orderResp {
	t.Helper()

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

	orderPayload, _ := json.Marshal(acme.OrderCreateRequest{Identifiers: identifiers})

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
	return resp
}

func TestNewOrder_RegularDomainGetsHTTP01AndDNS01(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	resp := newOrderForIdentifiers(t, h, store, []acme.Identifier{{Type: "dns", Value: "example.com"}})
	if len(resp.Authorizations) != 1 {
		t.Fatalf("expected 1 authorization URL, got %d", len(resp.Authorizations))
	}

	authzID, err := strconv.ParseInt(resp.Authorizations[0][strings.LastIndex(resp.Authorizations[0], "/")+1:], 10, 64)
	if err != nil {
		t.Fatalf("failed to parse authz ID from %q: %v", resp.Authorizations[0], err)
	}

	authz, err := store.GetAuthorization(authzID)
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}

	if authz.Wildcard {
		t.Error("authz.Wildcard = true, want false for non-wildcard identifier")
	}
	if authz.Identifier.Value != "example.com" {
		t.Errorf("authz.Identifier.Value = %q, want example.com", authz.Identifier.Value)
	}
	if len(authz.Challenges) != 2 {
		t.Fatalf("len(authz.Challenges) = %d, want 2", len(authz.Challenges))
	}

	var sawHTTP01, sawDNS01 bool
	for i, c := range authz.Challenges {
		switch c.Type {
		case acme.ChallengeTypeHTTP01:
			sawHTTP01 = true
		case acme.ChallengeTypeDNS01:
			sawDNS01 = true
		default:
			t.Errorf("unexpected challenge type %q", c.Type)
		}
		wantURL := "https://acme.example.com/acme/challenge/" + itoa(authzID) + "/" + itoa(int64(i))
		if c.URL != wantURL {
			t.Errorf("challenge[%d].URL = %q, want %q", i, c.URL, wantURL)
		}
	}
	if !sawHTTP01 || !sawDNS01 {
		t.Errorf("expected both http-01 and dns-01 challenges, got %+v", authz.Challenges)
	}
	// Each challenge must carry its own token, not a shared one.
	if authz.Challenges[0].Token == authz.Challenges[1].Token {
		t.Error("http-01 and dns-01 challenges should not share a token")
	}
}

func TestNewOrder_WildcardDomainGetsDNS01Only(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	resp := newOrderForIdentifiers(t, h, store, []acme.Identifier{{Type: "dns", Value: "*.example.com"}})
	if len(resp.Identifiers) != 1 || resp.Identifiers[0].Value != "*.example.com" {
		t.Errorf("order identifiers = %v, want [{dns *.example.com}]", resp.Identifiers)
	}

	authzID, err := strconv.ParseInt(resp.Authorizations[0][strings.LastIndex(resp.Authorizations[0], "/")+1:], 10, 64)
	if err != nil {
		t.Fatalf("failed to parse authz ID from %q: %v", resp.Authorizations[0], err)
	}

	authz, err := store.GetAuthorization(authzID)
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}

	if !authz.Wildcard {
		t.Error("authz.Wildcard = false, want true for wildcard identifier")
	}
	// Per RFC 8555 §7.1.3 the authz identifier drops the "*." label.
	if authz.Identifier.Value != "example.com" {
		t.Errorf("authz.Identifier.Value = %q, want example.com", authz.Identifier.Value)
	}
	if len(authz.Challenges) != 1 || authz.Challenges[0].Type != acme.ChallengeTypeDNS01 {
		t.Fatalf("challenges = %+v, want exactly one dns-01 challenge", authz.Challenges)
	}
}

func TestGetOrder(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	order := &acme.Order{
		ID:             h.idGen.Next(),
		Status:         acme.OrderStatusPending,
		Identifiers:    []acme.Identifier{{Type: "dns", Value: "example.com"}},
		Authorizations: []string{"https://acme.example.com/acme/authz/1"},
		Finalize:       "https://acme.example.com/acme/order/" + itoa(1) + "/finalize",
		CreatedAt:      time.Now(),
		AccountID:      1,
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
