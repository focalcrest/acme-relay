package handler

import (
	"encoding/json"
	"net/http"

	"github.com/focalcrest/acme-relay/internal/acme"
)

// NewAccount handles POST /acme/new-account (JWSWithJWKMiddleware)
func (h *ACMEHandler) NewAccount(w http.ResponseWriter, r *http.Request) {
	jwsReq := h.jwsFromContext(r)
	if jwsReq == nil || jwsReq.JWK == nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "missing JWK in JWS",
			Status: http.StatusBadRequest,
		})
		return
	}

	var req acme.AccountCreateRequest
	if err := json.Unmarshal(jwsReq.Payload, &req); err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "failed to parse new-account request",
			Status: http.StatusBadRequest,
		})
		return
	}

	if !req.TermsOfServiceAgreed {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:userActionRequired",
			Detail: "must agree to terms of service",
			Status: http.StatusBadRequest,
		})
		return
	}

	// Compute JWK thumbprint for dedup
	thumbprint, err := acme.ComputeJWKThumbprint(jwsReq.JWK)
	if err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:serverInternal",
			Detail: "failed to compute JWK thumbprint",
			Status: http.StatusInternalServerError,
		})
		return
	}

	// Check for existing account with same key
	existing, _ := h.store.GetAccountByJWK(thumbprint)
	if existing != nil {
		w.Header().Set("Location", h.baseURL+"/acme/acct/"+itoa(existing.ID))
		h.writeJSON(w, http.StatusOK, accountResponse(existing, h.baseURL))
		return
	}

	// Serialize JWK for storage
	jwkJSON, err := json.Marshal(jwsReq.JWK)
	if err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:serverInternal",
			Detail: "failed to serialize JWK",
			Status: http.StatusInternalServerError,
		})
		return
	}

	accountID := h.idGen.Next()
	account := &acme.Account{
		ID:        accountID,
		Status:    acme.AccountStatusValid,
		Email:     req.Email,
		PublicKey: thumbprint,
		JWKJSON:   string(jwkJSON),
		OrdersURL: h.baseURL + "/acme/acct/" + itoa(accountID) + "/orders",
		CreatedAt: now(),
	}

	if err := h.store.SaveAccount(account); err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:serverInternal",
			Detail: "failed to save account",
			Status: http.StatusInternalServerError,
		})
		return
	}

	w.Header().Set("Location", h.baseURL+"/acme/acct/"+itoa(account.ID))
	h.writeJSON(w, http.StatusCreated, accountResponse(account, h.baseURL))
}

// GetAccount handles POST /acme/acct/{id} (POST-as-GET)
func (h *ACMEHandler) GetAccount(w http.ResponseWriter, r *http.Request) {
	jwsReq := h.jwsFromContext(r)
	if jwsReq == nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "missing JWS context",
			Status: http.StatusBadRequest,
		})
		return
	}

	account, err := h.store.GetAccount(jwsReq.AccountID)
	if err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:accountDoesNotExist",
			Detail: "account not found",
			Status: http.StatusBadRequest,
		})
		return
	}

	h.writeJSON(w, http.StatusOK, accountResponse(account, h.baseURL))
}

type accountResp struct {
	Status             string   `json:"status"`
	Email              string   `json:"contact,omitempty"`
	Location           string   `json:"location"`
	Orders             string   `json:"orders"`
	TermsOfServiceAgreed bool   `json:"termsOfServiceAgreed"`
}

func accountResponse(a *acme.Account, baseURL string) accountResp {
	var email string
	if a.Email != "" {
		email = "mailto:" + a.Email
	}
	return accountResp{
		Status:               a.Status,
		Email:                email,
		Location:             baseURL + "/acme/acct/" + itoa(a.ID),
		Orders:               a.OrdersURL,
		TermsOfServiceAgreed: true,
	}
}
