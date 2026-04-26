package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"acme-relay/internal/acme"
)

func TestHandleChallenge(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	// Create account
	jwkJSON := `{"kty":"EC","crv":"P-256","x":"test","y":"test"}`
	account := &acme.Account{
		ID:        h.idGen.Next(),
		Status:    acme.AccountStatusValid,
		PublicKey: "fake-thumbprint",
		JWKJSON:   jwkJSON,
		CreatedAt: time.Now(),
	}
	store.SaveAccount(account)

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
		AccountID: account.ID,
	}
	store.SaveAuthorization(authz)

	r := chi.NewRouter()
	r.Post("/acme/challenge/{authzID}/{chalID}", h.HandleChallenge)

	req := httptest.NewRequest("POST", "/acme/challenge/"+itoa(authzID)+"/0", nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: account.ID})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp challengeResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Status != acme.ChallengeStatusProcessing {
		t.Errorf("status = %q, want %q", resp.Status, acme.ChallengeStatusProcessing)
	}
	if resp.Token != token {
		t.Errorf("token mismatch")
	}
	if resp.KeyAuthorization == "" {
		t.Error("keyAuthorization should be set")
	}
}

func TestHandleChallenge_NotFound(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	r := chi.NewRouter()
	r.Post("/acme/challenge/{authzID}/{chalID}", h.HandleChallenge)

	req := httptest.NewRequest("POST", "/acme/challenge/999/0", nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 1})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
