package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"acme-relay/pkg/types"
)

func TestHealthCheck(t *testing.T) {
	handler := &CertificateHandler{}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler.HealthCheck(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp types.HealthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("expected status 'ok', got '%s'", resp.Status)
	}
}

func TestRequestCertificate_InvalidBody(t *testing.T) {
	handler := &CertificateHandler{}

	req := httptest.NewRequest(http.MethodPost, "/certificate", strings.NewReader("invalid json"))
	w := httptest.NewRecorder()

	handler.RequestCertificate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestRequestCertificate_EmptyDomains(t *testing.T) {
	handler := &CertificateHandler{}

	body := `{"domains": [], "csr": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/certificate", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.RequestCertificate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestRequestCertificate_EmptyCSR(t *testing.T) {
	handler := &CertificateHandler{}

	body := `{"domains": ["example.com"], "csr": ""}`
	req := httptest.NewRequest(http.MethodPost, "/certificate", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.RequestCertificate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestGetCertificate_EmptyDomain(t *testing.T) {
	handler := &CertificateHandler{}

	req := httptest.NewRequest(http.MethodGet, "/certificate/", nil)
	w := httptest.NewRecorder()

	handler.GetCertificate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestRenewCertificate_EmptyDomain(t *testing.T) {
	handler := &CertificateHandler{}

	req := httptest.NewRequest(http.MethodPost, "/renew/", nil)
	w := httptest.NewRecorder()

	handler.RenewCertificate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}
