package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/focalcrest/acme-relay/pkg/types"
)

// mockTXTManager implements dns.TXTRecordManager for testing.
type mockTXTManager struct {
	addErr    error
	removeErr error
	records   map[string]string
}

func newMockTXTManager() *mockTXTManager {
	return &mockTXTManager{
		records: make(map[string]string),
	}
}

func (m *mockTXTManager) AddTXTRecord(fqdn, value string) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.records[fqdn] = value
	return nil
}

func (m *mockTXTManager) RemoveTXTRecord(fqdn, value string) error {
	if m.removeErr != nil {
		return m.removeErr
	}
	delete(m.records, fqdn)
	return nil
}

func TestAddTXT_Success(t *testing.T) {
	mock := newMockTXTManager()
	handler := NewDNSAPIHandler(mock, []string{"example.com"})

	body := `{"fqdn":"_acme-challenge.example.com","value":"test-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/txt/add", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.AddTXT(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	if mock.records["_acme-challenge.example.com"] != "test-token" {
		t.Errorf("record not added, got %v", mock.records)
	}
}

func TestAddTXT_InvalidJSON(t *testing.T) {
	mock := newMockTXTManager()
	handler := NewDNSAPIHandler(mock, []string{"example.com"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/txt/add", strings.NewReader("not json"))
	w := httptest.NewRecorder()

	handler.AddTXT(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestAddTXT_EmptyFQDN(t *testing.T) {
	mock := newMockTXTManager()
	handler := NewDNSAPIHandler(mock, []string{"example.com"})

	body := `{"fqdn":"","value":"test-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/txt/add", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.AddTXT(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestAddTXT_EmptyValue(t *testing.T) {
	mock := newMockTXTManager()
	handler := NewDNSAPIHandler(mock, []string{"example.com"})

	body := `{"fqdn":"_acme-challenge.example.com","value":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/txt/add", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.AddTXT(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestAddTXT_ManagerError(t *testing.T) {
	mock := &mockTXTManager{
		addErr: errors.New("aliDNS error"),
	}
	handler := NewDNSAPIHandler(mock, []string{"example.com"})

	body := `{"fqdn":"_acme-challenge.example.com","value":"test-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/txt/add", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.AddTXT(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}

	var resp types.ErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != "failed to add TXT record" {
		t.Errorf("unexpected error message: %s", resp.Error)
	}
}

func TestAddTXT_Policy(t *testing.T) {
	tests := []struct {
		name     string
		zones    []string
		fqdn     string
		value    string
		wantCode int
	}{
		{"missing challenge prefix", []string{"example.com"}, "www.example.com", "test-token", http.StatusBadRequest},
		{"outside allowed zones", []string{"example.com"}, "_acme-challenge.evil.org", "test-token", http.StatusForbidden},
		{"zone suffix but different domain", []string{"example.com"}, "_acme-challenge.notexample.com", "test-token", http.StatusForbidden},
		{"no zones configured", nil, "_acme-challenge.example.com", "test-token", http.StatusForbidden},
		{"invalid TXT value", []string{"example.com"}, "_acme-challenge.example.com", `"; DROP`, http.StatusBadRequest},
		{"apex of allowed zone", []string{"example.com"}, "_acme-challenge.example.com", "test-token", http.StatusOK},
		{"subdomain of allowed zone", []string{"example.com"}, "_acme-challenge.portal.example.com", "test-token", http.StatusOK},
		{"trailing dot and mixed case", []string{"Example.COM."}, "_ACME-Challenge.Example.Com.", "test-token", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockTXTManager()
			handler := NewDNSAPIHandler(mock, tt.zones)

			payload, _ := json.Marshal(dnsTXTRequest{FQDN: tt.fqdn, Value: tt.value})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/txt/add", strings.NewReader(string(payload)))
			w := httptest.NewRecorder()

			handler.AddTXT(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d (body: %s)", tt.wantCode, w.Code, w.Body.String())
			}
			if tt.wantCode != http.StatusOK && len(mock.records) != 0 {
				t.Errorf("rejected request must not touch DNS, got %v", mock.records)
			}
		})
	}
}

func TestRemoveTXT_PolicyRejected(t *testing.T) {
	mock := newMockTXTManager()
	mock.records["_acme-challenge.evil.org"] = "test-token"
	handler := NewDNSAPIHandler(mock, []string{"example.com"})

	body := `{"fqdn":"_acme-challenge.evil.org","value":"test-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/txt/remove", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.RemoveTXT(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}
	if _, exists := mock.records["_acme-challenge.evil.org"]; !exists {
		t.Error("rejected request must not touch DNS")
	}
}

func TestRemoveTXT_Success(t *testing.T) {
	mock := newMockTXTManager()
	mock.records["_acme-challenge.example.com"] = "test-token"
	handler := NewDNSAPIHandler(mock, []string{"example.com"})

	body := `{"fqdn":"_acme-challenge.example.com","value":"test-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/txt/remove", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.RemoveTXT(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	if _, exists := mock.records["_acme-challenge.example.com"]; exists {
		t.Error("record should have been removed")
	}
}

func TestRemoveTXT_InvalidJSON(t *testing.T) {
	mock := newMockTXTManager()
	handler := NewDNSAPIHandler(mock, []string{"example.com"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/txt/remove", strings.NewReader("not json"))
	w := httptest.NewRecorder()

	handler.RemoveTXT(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestRemoveTXT_EmptyFQDN(t *testing.T) {
	mock := newMockTXTManager()
	handler := NewDNSAPIHandler(mock, []string{"example.com"})

	body := `{"fqdn":"","value":"test-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/txt/remove", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.RemoveTXT(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestRemoveTXT_ManagerError(t *testing.T) {
	mock := &mockTXTManager{
		removeErr: errors.New("aliDNS error"),
	}
	handler := NewDNSAPIHandler(mock, []string{"example.com"})

	body := `{"fqdn":"_acme-challenge.example.com","value":"test-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/txt/remove", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.RemoveTXT(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}
}
