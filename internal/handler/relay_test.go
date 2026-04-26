package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"acme-relay/internal/acme"
	"acme-relay/internal/storage"
	"acme-relay/pkg/types"
)

// mockRelay implements acme.RelayClient for testing.
type mockRelay struct {
	certResp  *types.CertificateResponse
	certErr   error
	verifyErr error
}

func (m *mockRelay) CompleteCertificateRequest(_ context.Context, _ []string, _ string) (*types.CertificateResponse, error) {
	return m.certResp, m.certErr
}

func (m *mockRelay) VerifyHTTP01Challenge(_ context.Context, _, _, _ string) error {
	return m.verifyErr
}

func (m *mockRelay) RequestCertificate(_ context.Context, _ []string, _ string) (*types.CertificateResponse, error) {
	return m.certResp, m.certErr
}

func (m *mockRelay) GetCertificate(_ string) (*types.CertificateResponse, error) {
	return m.certResp, m.certErr
}

func (m *mockRelay) RenewCertificate(_ context.Context, _ string) (*types.CertificateResponse, error) {
	return m.certResp, m.certErr
}

func setupTestACMEHandlerWithRelay(t *testing.T, relay acme.RelayClient) (*ACMEHandler, *storage.FilesystemStorage) {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewFilesystemStorage(dir)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	nonceSvc := acme.NewNonceService()
	idGen := acme.NewIDGenerator(0)
	h := NewACMEHandler(store, relay, nonceSvc, idGen, "https://acme.example.com")
	return h, store
}

// ── FinalizeOrder with mock relay ──

func TestFinalizeOrder_Success(t *testing.T) {
	relay := &mockRelay{
		certResp: &types.CertificateResponse{
			Certificate: "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----",
		},
	}
	h, store := setupTestACMEHandlerWithRelay(t, relay)

	account := &acme.Account{
		ID:        h.idGen.Next(),
		Status:    acme.AccountStatusValid,
		PublicKey: "thumbprint",
		JWKJSON:   `{"kty":"EC"}`,
		CreatedAt: time.Now(),
	}
	store.SaveAccount(account)

	authzID := h.idGen.Next()
	token, _ := acme.GenerateToken()
	authz := &acme.Authorization{
		ID:         authzID,
		Status:     acme.AuthzStatusValid,
		Identifier: acme.Identifier{Type: "dns", Value: "test.example.com"},
		Challenges: []acme.Challenge{{
			Type:   acme.ChallengeTypeHTTP01,
			URL:    "https://acme.example.com/acme/challenge/" + itoa(authzID) + "/0",
			Token:  token,
			Status: acme.ChallengeStatusValid,
		}},
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		AccountID: account.ID,
	}
	store.SaveAuthorization(authz)

	order := &acme.Order{
		ID:            h.idGen.Next(),
		Status:        acme.OrderStatusReady,
		Identifiers:   []acme.Identifier{{Type: "dns", Value: "test.example.com"}},
		Authorizations: []string{"https://acme.example.com/acme/authz/" + itoa(authzID)},
		Finalize:      "https://acme.example.com/acme/order/1/finalize",
		CreatedAt:     time.Now(),
		AccountID:     account.ID,
	}
	store.SaveOrder(order)

	// Generate a real CSR matching the order domain
	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test.example.com"},
		DNSNames: []string{"test.example.com"},
	}, csrKey)
	csrB64 := base64.RawURLEncoding.EncodeToString(csrDER)

	r := chi.NewRouter()
	r.Post("/acme/order/{id}/finalize", h.FinalizeOrder)

	req := httptest.NewRequest("POST", "/acme/order/"+itoa(order.ID)+"/finalize", strings.NewReader(`{"csr":"`+csrB64+`"}`))
	req.Header.Set("Content-Type", "application/jose+json")
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: account.ID, Payload: json.RawMessage(`{"csr":"` + csrB64 + `"}`)})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, body)
	}

	// Verify order became valid
	saved, _ := store.GetOrder(order.ID)
	if saved.Status != acme.OrderStatusValid {
		t.Errorf("order status = %q, want valid", saved.Status)
	}
	if saved.Certificate == "" {
		t.Error("order certificate should be set")
	}
}

func TestFinalizeOrder_RelayError(t *testing.T) {
	relay := &mockRelay{
		certErr: io.EOF,
	}
	h, store := setupTestACMEHandlerWithRelay(t, relay)

	account := &acme.Account{
		ID:        h.idGen.Next(),
		Status:    acme.AccountStatusValid,
		PublicKey: "thumbprint",
		JWKJSON:   `{"kty":"EC"}`,
		CreatedAt: time.Now(),
	}
	store.SaveAccount(account)

	authzID := h.idGen.Next()
	token, _ := acme.GenerateToken()
	authz := &acme.Authorization{
		ID:         authzID,
		Status:     acme.AuthzStatusValid,
		Identifier: acme.Identifier{Type: "dns", Value: "test.example.com"},
		Challenges: []acme.Challenge{{
			Type:   acme.ChallengeTypeHTTP01,
			URL:    "https://acme.example.com/acme/challenge/" + itoa(authzID) + "/0",
			Token:  token,
			Status: acme.ChallengeStatusValid,
		}},
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		AccountID: account.ID,
	}
	store.SaveAuthorization(authz)

	order := &acme.Order{
		ID:            h.idGen.Next(),
		Status:        acme.OrderStatusReady,
		Identifiers:   []acme.Identifier{{Type: "dns", Value: "test.example.com"}},
		Authorizations: []string{"https://acme.example.com/acme/authz/" + itoa(authzID)},
		Finalize:      "https://acme.example.com/acme/order/1/finalize",
		CreatedAt:     time.Now(),
		AccountID:     account.ID,
	}
	store.SaveOrder(order)

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test.example.com"},
		DNSNames: []string{"test.example.com"},
	}, csrKey)
	csrB64 := base64.RawURLEncoding.EncodeToString(csrDER)

	r := chi.NewRouter()
	r.Post("/acme/order/{id}/finalize", h.FinalizeOrder)

	req := httptest.NewRequest("POST", "/acme/order/"+itoa(order.ID)+"/finalize", strings.NewReader(`{"csr":"`+csrB64+`"}`))
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: account.ID, Payload: json.RawMessage(`{"csr":"` + csrB64 + `"}`)})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	// Order should be invalid after relay failure
	saved, _ := store.GetOrder(order.ID)
	if saved.Status != acme.OrderStatusInvalid {
		t.Errorf("order status = %q, want invalid", saved.Status)
	}
}

// ── verifyChallenge with mock relay ──

func TestVerifyChallenge_Success(t *testing.T) {
	relay := &mockRelay{} // verifyErr == nil means success
	h, store := setupTestACMEHandlerWithRelay(t, relay)

	account := &acme.Account{
		ID:        h.idGen.Next(),
		Status:    acme.AccountStatusValid,
		PublicKey: "thumbprint",
		JWKJSON:   `{"kty":"EC"}`,
		CreatedAt: time.Now(),
	}
	store.SaveAccount(account)

	token, _ := acme.GenerateToken()
	authzID := h.idGen.Next()
	authz := &acme.Authorization{
		ID:         authzID,
		Status:     acme.AuthzStatusPending,
		Identifier: acme.Identifier{Type: "dns", Value: "verify.example.com"},
		Challenges: []acme.Challenge{{
			Type:   acme.ChallengeTypeHTTP01,
			URL:    "https://acme.example.com/acme/challenge/" + itoa(authzID) + "/0",
			Token:  token,
			Status: acme.ChallengeStatusPending,
		}},
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		AccountID: account.ID,
	}
	store.SaveAuthorization(authz)

	// Call verifyChallenge directly (unexported, same package)
	h.verifyChallenge(authz, 0, token+".thumbprint")

	updated, _ := store.GetAuthorization(authzID)
	if updated.Status != acme.AuthzStatusValid {
		t.Errorf("authz status = %q, want valid", updated.Status)
	}
	if updated.Challenges[0].Status != acme.ChallengeStatusValid {
		t.Errorf("challenge status = %q, want valid", updated.Challenges[0].Status)
	}
}

func TestVerifyChallenge_Failure(t *testing.T) {
	relay := &mockRelay{
		verifyErr: io.EOF,
	}
	h, store := setupTestACMEHandlerWithRelay(t, relay)

	token, _ := acme.GenerateToken()
	authzID := h.idGen.Next()
	authz := &acme.Authorization{
		ID:         authzID,
		Status:     acme.AuthzStatusPending,
		Identifier: acme.Identifier{Type: "dns", Value: "fail.example.com"},
		Challenges: []acme.Challenge{{
			Type:   acme.ChallengeTypeHTTP01,
			URL:    "https://acme.example.com/acme/challenge/" + itoa(authzID) + "/0",
			Token:  token,
			Status: acme.ChallengeStatusPending,
		}},
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	store.SaveAuthorization(authz)

	h.verifyChallenge(authz, 0, token+".thumbprint")

	updated, _ := store.GetAuthorization(authzID)
	if updated.Status != acme.AuthzStatusInvalid {
		t.Errorf("authz status = %q, want invalid", updated.Status)
	}
	if updated.Challenges[0].Status != acme.ChallengeStatusInvalid {
		t.Errorf("challenge status = %q, want invalid", updated.Challenges[0].Status)
	}
}

func TestVerifyChallenge_OrderBecomesReady(t *testing.T) {
	relay := &mockRelay{}
	h, store := setupTestACMEHandlerWithRelay(t, relay)

	account := &acme.Account{
		ID:        h.idGen.Next(),
		Status:    acme.AccountStatusValid,
		PublicKey: "thumbprint",
		JWKJSON:   `{"kty":"EC"}`,
		CreatedAt: time.Now(),
	}
	store.SaveAccount(account)

	token, _ := acme.GenerateToken()
	authzID := h.idGen.Next()
	authz := &acme.Authorization{
		ID:         authzID,
		Status:     acme.AuthzStatusPending,
		Identifier: acme.Identifier{Type: "dns", Value: "ready.example.com"},
		Challenges: []acme.Challenge{{
			Type:   acme.ChallengeTypeHTTP01,
			URL:    "https://acme.example.com/acme/challenge/" + itoa(authzID) + "/0",
			Token:  token,
			Status: acme.ChallengeStatusPending,
		}},
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		AccountID: account.ID,
	}
	store.SaveAuthorization(authz)

	order := &acme.Order{
		ID:            h.idGen.Next(),
		Status:        acme.OrderStatusPending,
		Identifiers:   []acme.Identifier{{Type: "dns", Value: "ready.example.com"}},
		Authorizations: []string{"https://acme.example.com/acme/authz/" + itoa(authzID)},
		Finalize:      "https://acme.example.com/acme/order/1/finalize",
		CreatedAt:     time.Now(),
		AccountID:     account.ID,
	}
	store.SaveOrder(order)

	h.verifyChallenge(authz, 0, token+".thumbprint")

	// Order should transition to ready
	saved, _ := store.GetOrder(order.ID)
	if saved.Status != acme.OrderStatusReady {
		t.Errorf("order status = %q, want ready", saved.Status)
	}
}

// ── CertificateHandler with mock relay ──

func TestCertificateHandler_RequestCertificate(t *testing.T) {
	relay := &mockRelay{
		certResp: &types.CertificateResponse{
			Certificate: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			Expires:     time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		},
	}
	h := NewCertificateHandler(relay)

	r := chi.NewRouter()
	r.Post("/certificate", h.RequestCertificate)

	body := `{"domains":["test.example.com"],"csr":"dGVzdA=="}`
	req := httptest.NewRequest("POST", "/certificate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
}

func TestCertificateHandler_RequestCertificate_RelayError(t *testing.T) {
	relay := &mockRelay{certErr: io.EOF}
	h := NewCertificateHandler(relay)

	r := chi.NewRouter()
	r.Post("/certificate", h.RequestCertificate)

	req := httptest.NewRequest("POST", "/certificate", strings.NewReader(`{"domains":["test.example.com"],"csr":"dGVzdA=="}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestCertificateHandler_GetCertificate(t *testing.T) {
	relay := &mockRelay{
		certResp: &types.CertificateResponse{
			Certificate: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		},
	}
	h := NewCertificateHandler(relay)

	r := chi.NewRouter()
	r.Get("/certificate/{domain}", h.GetCertificate)

	req := httptest.NewRequest("GET", "/certificate/test.example.com", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestCertificateHandler_GetCertificate_NotFound(t *testing.T) {
	relay := &mockRelay{certErr: io.EOF}
	h := NewCertificateHandler(relay)

	r := chi.NewRouter()
	r.Get("/certificate/{domain}", h.GetCertificate)

	req := httptest.NewRequest("GET", "/certificate/missing.example.com", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestCertificateHandler_RenewCertificate(t *testing.T) {
	relay := &mockRelay{
		certResp: &types.CertificateResponse{
			Certificate: "-----BEGIN CERTIFICATE-----\nrenewed\n-----END CERTIFICATE-----",
		},
	}
	h := NewCertificateHandler(relay)

	r := chi.NewRouter()
	r.Post("/renew/{domain}", h.RenewCertificate)

	req := httptest.NewRequest("POST", "/renew/test.example.com", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestCertificateHandler_RenewCertificate_Error(t *testing.T) {
	relay := &mockRelay{certErr: io.EOF}
	h := NewCertificateHandler(relay)

	r := chi.NewRouter()
	r.Post("/renew/{domain}", h.RenewCertificate)

	req := httptest.NewRequest("POST", "/renew/test.example.com", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}
