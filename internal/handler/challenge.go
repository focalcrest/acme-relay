package handler

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/focalcrest/acme-relay/internal/acme"
)

// HandleChallenge handles POST /acme/challenge/{authzID}/{chalID}
func (h *ACMEHandler) HandleChallenge(w http.ResponseWriter, r *http.Request) {
	jwsReq := h.jwsFromContext(r)
	if jwsReq == nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "missing JWS context",
			Status: http.StatusBadRequest,
		})
		return
	}

	authzID, err := strconv.ParseInt(chi.URLParam(r, "authzID"), 10, 64)
	if err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "invalid authorization ID",
			Status: http.StatusBadRequest,
		})
		return
	}

	authz, err := h.store.GetAuthorization(authzID)
	if err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: "authorization not found",
			Status: http.StatusNotFound,
		})
		return
	}

	chalIdx, _ := strconv.Atoi(chi.URLParam(r, "chalID"))
	if chalIdx < 0 || chalIdx >= len(authz.Challenges) {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "challenge not found",
			Status: http.StatusNotFound,
		})
		return
	}

	challenge := &authz.Challenges[chalIdx]

	// Get account for keyAuthorization computation
	account, err := h.store.GetAccount(jwsReq.AccountID)
	if err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:accountDoesNotExist",
			Detail: "account not found",
			Status: http.StatusBadRequest,
		})
		return
	}

	// Compute keyAuthorization
	thumbprint := account.PublicKey
	keyAuth := acme.ComputeKeyAuthorization(challenge.Token, thumbprint)
	challenge.KeyAuth = keyAuth

	// Return challenge in "processing" state
	challenge.Status = acme.ChallengeStatusProcessing
	if err := h.store.SaveAuthorization(authz); err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:serverInternal",
			Detail: "failed to save authorization",
			Status: http.StatusInternalServerError,
		})
		return
	}

	// Start async verification
	go h.verifyChallenge(authz, chalIdx, keyAuth)

	h.writeJSON(w, http.StatusOK, challengeResp{
		Type:             challenge.Type,
		URL:              challenge.URL,
		Token:            challenge.Token,
		Status:           challenge.Status,
		KeyAuthorization: challenge.KeyAuth,
	})
}

func (h *ACMEHandler) verifyChallenge(authz *acme.Authorization, chalIdx int, keyAuth string) {
	if h.relay == nil {
		log.Printf("No relay configured, skipping challenge verification")
		return
	}
	challenge := &authz.Challenges[chalIdx]
	domain := authz.Identifier.Value

	// Verify HTTP-01 challenge
	ctx, cancel := contextWithTimeout(30 * time.Second)
	defer cancel()

	err := h.relay.VerifyHTTP01Challenge(ctx, domain, challenge.Token, keyAuth)

	if err != nil {
		log.Printf("Challenge verification failed for %s: %v", domain, err)
		challenge.Status = acme.ChallengeStatusInvalid
		authz.Status = acme.AuthzStatusInvalid
	} else {
		log.Printf("Challenge verified for %s", domain)
		now := time.Now()
		challenge.Status = acme.ChallengeStatusValid
		challenge.Validated = now
		authz.Status = acme.AuthzStatusValid
	}

	if err := h.store.SaveAuthorization(authz); err != nil {
		log.Printf("Failed to save authorization after verification: %v", err)
		return
	}

	// If authorization is valid, check if all authorizations for the order are valid
	if authz.Status == acme.AuthzStatusValid {
		h.checkOrderReady(authz.AccountID)
	}
}

func (h *ACMEHandler) checkOrderReady(accountID int64) {
	// Find orders for this account that might be ready
	// We need to iterate stored orders - for simplicity, check all pending orders
	// In production, you'd have an index
	maxOrder, _, _ := h.store.MaxIDs()
	for id := int64(1); id <= maxOrder; id++ {
		order, err := h.store.GetOrder(id)
		if err != nil || order.AccountID != accountID || order.Status != acme.OrderStatusPending {
			continue
		}

		// Check all authorizations are valid
		allValid := true
		for _, authzURL := range order.Authorizations {
			authzID := extractIDFromURL(authzURL)
			if authzID == 0 {
				allValid = false
				break
			}
			authz, err := h.store.GetAuthorization(authzID)
			if err != nil || authz.Status != acme.AuthzStatusValid {
				allValid = false
				break
			}
		}

		if allValid {
			order.Status = acme.OrderStatusReady
			if err := h.store.SaveOrder(order); err != nil {
				log.Printf("Failed to update order %d to ready: %v", order.ID, err)
			}
		}
	}
}

func extractIDFromURL(url string) int64 {
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == '/' {
			id, err := strconv.ParseInt(url[i+1:], 10, 64)
			if err == nil {
				return id
			}
			return 0
		}
	}
	return 0
}
