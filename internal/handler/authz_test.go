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

func TestGetAuthorization(t *testing.T) {
	h, store := setupTestACMEHandler(t)

	token, _ := acme.GenerateToken()
	authz := &acme.Authorization{
		ID:     h.idGen.Next(),
		Status: acme.AuthzStatusPending,
		Identifier: acme.Identifier{Type: "dns", Value: "example.com"},
		Challenges: []acme.Challenge{
			{
				Type:   acme.ChallengeTypeHTTP01,
				URL:    "https://acme.example.com/acme/challenge/" + itoa(1) + "/0",
				Token:  token,
				Status: acme.ChallengeStatusPending,
			},
		},
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		AccountID: 1,
	}
	store.SaveAuthorization(authz)

	r := chi.NewRouter()
	r.Post("/acme/authz/{id}", h.GetAuthorization)

	req := httptest.NewRequest("POST", "/acme/authz/"+itoa(authz.ID), nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 1})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp authzResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Status != acme.AuthzStatusPending {
		t.Errorf("status = %q, want %q", resp.Status, acme.AuthzStatusPending)
	}
	if resp.Identifier.Value != "example.com" {
		t.Errorf("identifier = %q, want example.com", resp.Identifier.Value)
	}
	if len(resp.Challenges) != 1 {
		t.Fatalf("challenges = %d, want 1", len(resp.Challenges))
	}
	if resp.Challenges[0].Type != acme.ChallengeTypeHTTP01 {
		t.Errorf("challenge type = %q, want %q", resp.Challenges[0].Type, acme.ChallengeTypeHTTP01)
	}
	if resp.Challenges[0].Token != token {
		t.Errorf("challenge token mismatch")
	}
}

func TestGetAuthorization_NotFound(t *testing.T) {
	h, _ := setupTestACMEHandler(t)

	r := chi.NewRouter()
	r.Post("/acme/authz/{id}", h.GetAuthorization)

	req := httptest.NewRequest("POST", "/acme/authz/999", nil)
	req = acme.SetJWSInContext(req, &acme.JWSRequest{AccountID: 1})
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
