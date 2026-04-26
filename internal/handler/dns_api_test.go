package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"acme-relay/pkg/types"
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
	handler := NewDNSAPIHandler(mock)

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
	handler := NewDNSAPIHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/txt/add", strings.NewReader("not json"))
	w := httptest.NewRecorder()

	handler.AddTXT(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestAddTXT_EmptyFQDN(t *testing.T) {
	mock := newMockTXTManager()
	handler := NewDNSAPIHandler(mock)

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
	handler := NewDNSAPIHandler(mock)

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
	handler := NewDNSAPIHandler(mock)

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

func TestRemoveTXT_Success(t *testing.T) {
	mock := newMockTXTManager()
	mock.records["_acme-challenge.example.com"] = "test-token"
	handler := NewDNSAPIHandler(mock)

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
	handler := NewDNSAPIHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/txt/remove", strings.NewReader("not json"))
	w := httptest.NewRecorder()

	handler.RemoveTXT(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestRemoveTXT_EmptyFQDN(t *testing.T) {
	mock := newMockTXTManager()
	handler := NewDNSAPIHandler(mock)

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
	handler := NewDNSAPIHandler(mock)

	body := `{"fqdn":"_acme-challenge.example.com","value":"test-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/txt/remove", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.RemoveTXT(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}
}
