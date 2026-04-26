package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"acme-relay/internal/acme"
)

func TestCheckOrderReady(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	// Create account
	account := &acme.Account{
		ID:        h.idGen.Next(),
		Status:    acme.AccountStatusValid,
		PublicKey: "thumb",
		JWKJSON:   `{"kty":"EC"}`,
		CreatedAt: time.Now(),
	}
	store.SaveAccount(account)

	// Create authorization (valid)
	token, _ := acme.GenerateToken()
	authz := &acme.Authorization{
		ID:         h.idGen.Next(),
		Status:     acme.AuthzStatusValid,
		Identifier: acme.Identifier{Type: "dns", Value: "example.com"},
		Challenges: []acme.Challenge{
			{Type: acme.ChallengeTypeHTTP01, Token: token, Status: acme.ChallengeStatusValid, Validated: time.Now()},
		},
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		AccountID: account.ID,
	}
	store.SaveAuthorization(authz)

	// Create pending order referencing the authz
	order := &acme.Order{
		ID:            h.idGen.Next(),
		Status:        acme.OrderStatusPending,
		Identifiers:   []acme.Identifier{{Type: "dns", Value: "example.com"}},
		Authorizations: []string{"https://acme.example.com/acme/authz/" + itoa(authz.ID)},
		Finalize:      "https://acme.example.com/acme/order/" + itoa(1) + "/finalize",
		CreatedAt:     time.Now(),
		AccountID:     account.ID,
	}
	store.SaveOrder(order)

	// Run checkOrderReady
	h.checkOrderReady(account.ID)

	// Verify order is now ready
	updated, _ := store.GetOrder(order.ID)
	if updated.Status != acme.OrderStatusReady {
		t.Errorf("order status = %q, want ready", updated.Status)
	}
}

func TestCheckOrderReady_NotAllValid(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	account := &acme.Account{
		ID:        h.idGen.Next(),
		Status:    acme.AccountStatusValid,
		CreatedAt: time.Now(),
	}
	store.SaveAccount(account)

	// Create authorization still pending
	authz := &acme.Authorization{
		ID:         h.idGen.Next(),
		Status:     acme.AuthzStatusPending,
		Identifier: acme.Identifier{Type: "dns", Value: "example.com"},
		Challenges: []acme.Challenge{{Type: acme.ChallengeTypeHTTP01, Token: "tok", Status: acme.ChallengeStatusPending}},
		ExpiresAt:  time.Now().Add(7 * 24 * time.Hour),
		AccountID:  account.ID,
	}
	store.SaveAuthorization(authz)

	order := &acme.Order{
		ID:            h.idGen.Next(),
		Status:        acme.OrderStatusPending,
		Identifiers:   []acme.Identifier{{Type: "dns", Value: "example.com"}},
		Authorizations: []string{"https://acme.example.com/acme/authz/" + itoa(authz.ID)},
		CreatedAt:     time.Now(),
		AccountID:     account.ID,
	}
	store.SaveOrder(order)

	h.checkOrderReady(account.ID)

	updated, _ := store.GetOrder(order.ID)
	if updated.Status != acme.OrderStatusPending {
		t.Errorf("order should still be pending, got %q", updated.Status)
	}
}

func TestFinalizeOrder_InvalidOrderID(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	r := chi.NewRouter()
	r.Post("/acme/order/{id}/finalize", h.FinalizeOrder)

	req := httptest.NewRequest("POST", "/acme/order/notanumber/finalize", nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 1})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestFinalizeOrder_BadCSR(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	account := &acme.Account{
		ID:        h.idGen.Next(),
		Status:    acme.AccountStatusValid,
		CreatedAt: time.Now(),
	}
	store.SaveAccount(account)

	order := &acme.Order{
		ID:            h.idGen.Next(),
		Status:        acme.OrderStatusReady,
		Identifiers:   []acme.Identifier{{Type: "dns", Value: "example.com"}},
		CreatedAt:     time.Now(),
		AccountID:     account.ID,
	}
	store.SaveOrder(order)

	payload, _ := json.Marshal(acme.FinalizeRequest{
		CSR: "!!!invalid-base64!!!",
	})

	r := chi.NewRouter()
	r.Post("/acme/order/{id}/finalize", h.FinalizeOrder)

	req := httptest.NewRequest("POST", "/acme/order/"+itoa(order.ID)+"/finalize", bytes.NewReader([]byte{}))
	req = acme.SetJWSInContext(req, &acme.JWSRequest{
		AccountID: account.ID,
		Payload:   payload,
	})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	// Should fail with bad CSR
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCertificateHandler_HealthCheck(t *testing.T) {
	h := NewCertificateHandler(nil)
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	h.HealthCheck(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestCertificateHandler_RequestCertificate_NoDomains(t *testing.T) {
	h := NewCertificateHandler(nil)

	body, _ := json.Marshal(map[string]interface{}{
		"domains": []string{},
		"csr":     "test",
	})
	req := httptest.NewRequest("POST", "/certificate", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.RequestCertificate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCertificateHandler_RequestCertificate_NoCSR(t *testing.T) {
	h := NewCertificateHandler(nil)

	body, _ := json.Marshal(map[string]interface{}{
		"domains": []string{"example.com"},
	})
	req := httptest.NewRequest("POST", "/certificate", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.RequestCertificate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCertificateHandler_GetCertificate_NoDomain(t *testing.T) {
	h := NewCertificateHandler(nil)

	r := chi.NewRouter()
	r.Get("/certificate/{domain}", h.GetCertificate)

	req := httptest.NewRequest("GET", "/certificate/", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	// chi won't match without domain param, returns 404 from router
	if rec.Code == http.StatusOK {
		t.Error("expected non-200 status")
	}
}

func TestCertificateHandler_RenewCertificate_NoDomain(t *testing.T) {
	h := NewCertificateHandler(nil)

	r := chi.NewRouter()
	r.Post("/renew/{domain}", h.RenewCertificate)

	req := httptest.NewRequest("POST", "/renew/", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Error("expected non-200 status")
	}
}
