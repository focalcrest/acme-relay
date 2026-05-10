package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/focalcrest/acme-relay/internal/acme"
)

func TestGetAccount(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	account := &acme.Account{
		ID:        h.idGen.Next(),
		Status:    acme.AccountStatusValid,
		Email:     "test@example.com",
		PublicKey: "thumbprint",
		JWKJSON:   `{"kty":"EC"}`,
		CreatedAt: time.Now(),
	}
	store.SaveAccount(account)

	req := httptest.NewRequest("POST", "/acme/acct/"+itoa(account.ID), nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: account.ID})
	rec := httptest.NewRecorder()

	h.GetAccount(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp accountResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Status != acme.AccountStatusValid {
		t.Errorf("status = %q, want valid", resp.Status)
	}
}

func TestGetAccount_NotFound(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	req := httptest.NewRequest("POST", "/acme/acct/999", nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 999})
	rec := httptest.NewRecorder()

	h.GetAccount(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestExtractIDFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want int64
	}{
		{"https://acme.example.com/acme/authz/42", 42},
		{"https://acme.example.com/acme/authz/1", 1},
		{"/acme/authz/99", 99},
		{"invalid", 0},
		{"https://acme.example.com/acme/authz/notanumber", 0},
	}
	for _, tt := range tests {
		got := extractIDFromURL(tt.url)
		if got != tt.want {
			t.Errorf("extractIDFromURL(%q) = %d, want %d", tt.url, got, tt.want)
		}
	}
}

func TestNewAccount_MissingJWS(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	req := httptest.NewRequest("POST", "/acme/new-account", nil)
	rec := httptest.NewRecorder()

	h.NewAccount(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestGetAccount_MissingJWS(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	req := httptest.NewRequest("POST", "/acme/acct/1", nil)
	rec := httptest.NewRecorder()

	h.GetAccount(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestNewOrder_MissingJWS(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	req := httptest.NewRequest("POST", "/acme/new-order", nil)
	rec := httptest.NewRecorder()

	h.NewOrder(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleChallenge_MissingJWS(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	r := chi.NewRouter()
	r.Post("/acme/challenge/{authzID}/{chalID}", h.HandleChallenge)

	req := httptest.NewRequest("POST", "/acme/challenge/1/0", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestFinalizeOrder_MissingJWS(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	req := httptest.NewRequest("POST", "/acme/order/1/finalize", nil)
	rec := httptest.NewRecorder()

	h.FinalizeOrder(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestGetCertificate_MissingJWS(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	req := httptest.NewRequest("POST", "/acme/certificate/1", nil)
	rec := httptest.NewRecorder()

	h.GetCertificate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestAddNonce(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	rec := httptest.NewRecorder()
	h.addNonce(rec)

	nonce := rec.Header().Get("Replay-Nonce")
	if nonce == "" {
		t.Error("Replay-Nonce header should be set")
	}
}

func TestWriteProblem(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	rec := httptest.NewRecorder()
	h.writeProblem(rec, &acme.Problem{
		Type:   "urn:ietf:params:acme:error:malformed",
		Detail: "test error",
		Status: http.StatusBadRequest,
	})

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("content-type = %q, want application/problem+json", ct)
	}
}

func TestNewOrder_InvalidIdentifier(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	payload, _ := json.Marshal(acme.OrderCreateRequest{
		Identifiers: []acme.Identifier{
			{Type: "ip", Value: "1.2.3.4"},
		},
	})

	req := httptest.NewRequest("POST", "/acme/new-order", nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{
		AccountID: 1,
		Payload:   payload,
	})
	rec := httptest.NewRecorder()

	h.NewOrder(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestNewOrder_EmptyIdentifiers(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	payload, _ := json.Marshal(acme.OrderCreateRequest{
		Identifiers: []acme.Identifier{},
	})

	req := httptest.NewRequest("POST", "/acme/new-order", nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{
		AccountID: 1,
		Payload:   payload,
	})
	rec := httptest.NewRecorder()

	h.NewOrder(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleChallenge_InvalidAuthzID(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	r := chi.NewRouter()
	r.Post("/acme/challenge/{authzID}/{chalID}", h.HandleChallenge)

	req := httptest.NewRequest("POST", "/acme/challenge/notanumber/0", nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 1})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleChallenge_AccountNotFound(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	token, _ := acme.GenerateToken()
	authzID := h.idGen.Next()
	authz := &acme.Authorization{
		ID:     authzID,
		Status: acme.AuthzStatusPending,
		Identifier: acme.Identifier{Type: "dns", Value: "example.com"},
		Challenges: []acme.Challenge{
			{
				Type:   acme.ChallengeTypeHTTP01,
				URL:    "https://acme.example.com/acme/challenge/" + itoa(authzID) + "/0",
				Token:  token,
				Status: acme.ChallengeStatusPending,
			},
		},
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		AccountID: 999, // Non-existent account
	}
	store.SaveAuthorization(authz)

	r := chi.NewRouter()
	r.Post("/acme/challenge/{authzID}/{chalID}", h.HandleChallenge)

	req := httptest.NewRequest("POST", "/acme/challenge/"+itoa(authzID)+"/0", nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 999})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
