package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"acme-relay/internal/acme"
)

func TestFinalizeOrder_NotReady(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	order := &acme.Order{
		ID:            h.idGen.Next(),
		Status:        acme.OrderStatusPending,
		Identifiers:   []acme.Identifier{{Type: "dns", Value: "example.com"}},
		Authorizations: []string{"https://acme.example.com/acme/authz/1"},
		Finalize:      "https://acme.example.com/acme/order/" + itoa(1) + "/finalize",
		CreatedAt:     time.Now(),
		AccountID:     1,
	}
	store.SaveOrder(order)

	r := chi.NewRouter()
	r.Post("/acme/order/{id}/finalize", h.FinalizeOrder)

	req := httptest.NewRequest("POST", "/acme/order/"+itoa(order.ID)+"/finalize", nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 1})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestFinalizeOrder_WrongAccount(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	order := &acme.Order{
		ID:            h.idGen.Next(),
		Status:        acme.OrderStatusReady,
		Identifiers:   []acme.Identifier{{Type: "dns", Value: "example.com"}},
		Authorizations: []string{"https://acme.example.com/acme/authz/1"},
		Finalize:      "https://acme.example.com/acme/order/" + itoa(1) + "/finalize",
		CreatedAt:     time.Now(),
		AccountID:     99,
	}
	store.SaveOrder(order)

	r := chi.NewRouter()
	r.Post("/acme/order/{id}/finalize", h.FinalizeOrder)

	req := httptest.NewRequest("POST", "/acme/order/"+itoa(order.ID)+"/finalize", nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 1})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestFinalizeOrder_NotFound(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	r := chi.NewRouter()
	r.Post("/acme/order/{id}/finalize", h.FinalizeOrder)

	req := httptest.NewRequest("POST", "/acme/order/999/finalize", nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 1})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestGetCertificate_NotValid(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	order := &acme.Order{
		ID:            h.idGen.Next(),
		Status:        acme.OrderStatusPending,
		Identifiers:   []acme.Identifier{{Type: "dns", Value: "example.com"}},
		CreatedAt:     time.Now(),
		AccountID:     1,
	}
	store.SaveOrder(order)

	r := chi.NewRouter()
	r.Post("/acme/certificate/{orderID}", h.GetCertificate)

	req := httptest.NewRequest("POST", "/acme/certificate/"+itoa(order.ID), nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 1})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestGetCertificate_Valid(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	fakeCert := "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----"
	order := &acme.Order{
		ID:          h.idGen.Next(),
		Status:      acme.OrderStatusValid,
		Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
		Certificate: fakeCert,
		CreatedAt:   time.Now(),
		AccountID:   1,
	}
	store.SaveOrder(order)

	r := chi.NewRouter()
	r.Post("/acme/certificate/{orderID}", h.GetCertificate)

	req := httptest.NewRequest("POST", "/acme/certificate/"+itoa(order.ID), nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 1})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/pem-certificate-chain" {
		t.Errorf("content-type = %q, want application/pem-certificate-chain", ct)
	}

	body := rec.Body.String()
	if body != fakeCert {
		t.Errorf("body mismatch: got %q", body)
	}
}

func TestGetCertificate_WrongAccount(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	order := &acme.Order{
		ID:          h.idGen.Next(),
		Status:      acme.OrderStatusValid,
		Identifiers: []acme.Identifier{{Type: "dns", Value: "example.com"}},
		Certificate: "fake-cert",
		CreatedAt:   time.Now(),
		AccountID:   99,
	}
	store.SaveOrder(order)

	r := chi.NewRouter()
	r.Post("/acme/certificate/{orderID}", h.GetCertificate)

	req := httptest.NewRequest("POST", "/acme/certificate/"+itoa(order.ID), nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 1})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
