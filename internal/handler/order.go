package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/focalcrest/acme-relay/internal/acme"
)

// NewOrder handles POST /acme/new-order
func (h *ACMEHandler) NewOrder(w http.ResponseWriter, r *http.Request) {
	jwsReq := h.jwsFromContext(r)
	if jwsReq == nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "missing JWS context",
			Status: http.StatusBadRequest,
		})
		return
	}

	var req acme.OrderCreateRequest
	if err := json.Unmarshal(jwsReq.Payload, &req); err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "failed to parse new-order request",
			Status: http.StatusBadRequest,
		})
		return
	}

	identifiers, err := acme.ParseIdentifiers(req.Identifiers)
	if err != nil {
		h.writeProblem(w, err.(*acme.Problem))
		return
	}

	if len(identifiers) == 0 {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "at least one identifier is required",
			Status: http.StatusBadRequest,
		})
		return
	}

	orderID := h.idGen.Next()
	var authzURLs []string
	var authzs []*acme.Authorization

	for _, id := range identifiers {
		authzID := h.idGen.Next()
		isWildcard := acme.IsWildcardIdentifier(id.Value)

		var challenges []acme.Challenge
		if !isWildcard {
			token, _ := acme.GenerateToken()
			challenges = append(challenges, acme.Challenge{
				Type:   acme.ChallengeTypeHTTP01,
				URL:    h.baseURL + "/acme/challenge/" + itoa(authzID) + "/" + itoa(int64(len(challenges))),
				Token:  token,
				Status: acme.ChallengeStatusPending,
			})
		}
		dnsToken, _ := acme.GenerateToken()
		challenges = append(challenges, acme.Challenge{
			Type:   acme.ChallengeTypeDNS01,
			URL:    h.baseURL + "/acme/challenge/" + itoa(authzID) + "/" + itoa(int64(len(challenges))),
			Token:  dnsToken,
			Status: acme.ChallengeStatusPending,
		})

		// Per RFC 8555 §7.1.3, a wildcard authorization's identifier drops
		// the "*." label and carries wildcard:true instead.
		authzIdentifier := id
		if isWildcard {
			authzIdentifier.Value = strings.TrimPrefix(id.Value, "*.")
		}

		authz := &acme.Authorization{
			ID:         authzID,
			Status:     acme.AuthzStatusPending,
			Identifier: authzIdentifier,
			Challenges: challenges,
			Wildcard:   isWildcard,
			ExpiresAt:  time.Now().Add(7 * 24 * time.Hour),
			AccountID:  jwsReq.AccountID,
		}

		authzs = append(authzs, authz)
		authzURLs = append(authzURLs, h.baseURL+"/acme/authz/"+itoa(authzID))

		if err := h.store.SaveAuthorization(authz); err != nil {
			h.writeProblem(w, &acme.Problem{
				Type:   "urn:ietf:params:acme:error:serverInternal",
				Detail: "failed to save authorization",
				Status: http.StatusInternalServerError,
			})
			return
		}
	}

	order := &acme.Order{
		ID:             orderID,
		Status:         acme.OrderStatusPending,
		Identifiers:    identifiers,
		Authorizations: authzURLs,
		Finalize:       h.baseURL + "/acme/order/" + itoa(orderID) + "/finalize",
		CreatedAt:      time.Now(),
		AccountID:      jwsReq.AccountID,
	}

	if err := h.store.SaveOrder(order); err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:serverInternal",
			Detail: "failed to save order",
			Status: http.StatusInternalServerError,
		})
		return
	}

	h.writeJSON(w, http.StatusCreated, orderResponse(order, h.baseURL))
}

// GetOrder handles POST /acme/order/{id}
func (h *ACMEHandler) GetOrder(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "invalid order ID",
			Status: http.StatusBadRequest,
		})
		return
	}

	order, err := h.store.GetOrder(id)
	if err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:orderNotReady",
			Detail: "order not found",
			Status: http.StatusNotFound,
		})
		return
	}

	h.writeJSON(w, http.StatusOK, orderResponse(order, h.baseURL))
}

type orderResp struct {
	Status         string            `json:"status"`
	Expires        string            `json:"expires,omitempty"`
	Identifiers    []acme.Identifier `json:"identifiers"`
	Authorizations []string          `json:"authorizations"`
	Finalize       string            `json:"finalize"`
	Certificate    string            `json:"certificate,omitempty"`
}

func orderResponse(o *acme.Order, baseURL string) orderResp {
	resp := orderResp{
		Status:         o.Status,
		Expires:        o.NotAfter.Format(time.RFC3339),
		Identifiers:    o.Identifiers,
		Authorizations: o.Authorizations,
		Finalize:       o.Finalize,
	}
	if o.Certificate != "" {
		resp.Certificate = baseURL + "/acme/certificate/" + itoa(o.ID)
	}
	return resp
}
