package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/focalcrest/acme-relay/internal/acme"
)

// FinalizeOrder handles POST /acme/order/{id}/finalize
func (h *ACMEHandler) FinalizeOrder(w http.ResponseWriter, r *http.Request) {
	jwsReq := h.jwsFromContext(r)
	if jwsReq == nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "missing JWS context",
			Status: http.StatusBadRequest,
		})
		return
	}

	orderID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "invalid order ID",
			Status: http.StatusBadRequest,
		})
		return
	}

	order, err := h.store.GetOrder(orderID)
	if err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:orderNotReady",
			Detail: "order not found",
			Status: http.StatusNotFound,
		})
		return
	}

	if order.AccountID != jwsReq.AccountID {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: "order does not belong to this account",
			Status: http.StatusUnauthorized,
		})
		return
	}

	if order.Status != acme.OrderStatusReady {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:orderNotReady",
			Detail: "order is not ready for finalization (status: " + order.Status + ")",
			Status: http.StatusForbidden,
		})
		return
	}

	var req acme.FinalizeRequest
	if err := json.Unmarshal(jwsReq.Payload, &req); err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "failed to parse finalize request",
			Status: http.StatusBadRequest,
		})
		return
	}

	// Decode CSR
	csrBase64 := req.CSR
	// ACME spec says CSR is base64url-encoded (without padding)
	csrBytes, err := base64.RawURLEncoding.DecodeString(csrBase64)
	if err != nil {
		// Try standard base64 as fallback
		csrBytes, err = base64.StdEncoding.DecodeString(csrBase64)
		if err != nil {
			h.writeProblem(w, &acme.Problem{
				Type:   "urn:ietf:params:acme:error:badCSR",
				Detail: "failed to decode CSR",
				Status: http.StatusBadRequest,
			})
			return
		}
	}

	// Extract domains from CSR and verify they match order identifiers
	domains, err := acme.GetDomainsFromCSR(base64.StdEncoding.EncodeToString(csrBytes))
	if err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:badCSR",
			Detail: "failed to parse CSR: " + err.Error(),
			Status: http.StatusBadRequest,
		})
		return
	}

	if !domainsMatch(order.Identifiers, domains) {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:badCSR",
			Detail: "CSR domains do not match order identifiers",
			Status: http.StatusBadRequest,
		})
		return
	}

	// Mark order as processing
	order.Status = acme.OrderStatusProcessing
	order.CSR = csrBase64
	if err := h.store.SaveOrder(order); err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:serverInternal",
			Detail: "failed to update order",
			Status: http.StatusInternalServerError,
		})
		return
	}

	// Guard: relay must be configured to obtain certificates
	if h.relay == nil {
		order.Status = acme.OrderStatusInvalid
		h.store.SaveOrder(order)
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:serverInternal",
			Detail: "certificate relay not configured",
			Status: http.StatusInternalServerError,
		})
		return
	}

	// Use relay to obtain certificate via DNS-01 upstream
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	csrBase64Std := base64.StdEncoding.EncodeToString(csrBytes)
	resp, err := h.relay.CompleteCertificateRequest(ctx, domains, csrBase64Std)
	if err != nil {
		order.Status = acme.OrderStatusInvalid
		h.store.SaveOrder(order)
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:serverInternal",
			Detail: "failed to obtain certificate: " + err.Error(),
			Status: http.StatusInternalServerError,
		})
		return
	}

	// Store full certificate chain (leaf + intermediate) per RFC 8555 §7.4.2
	order.Status = acme.OrderStatusValid
	if resp.Chain != "" {
		order.Certificate = resp.Certificate + resp.Chain
	} else {
		order.Certificate = resp.Certificate
	}
	if err := h.store.SaveOrder(order); err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:serverInternal",
			Detail: "failed to save order",
			Status: http.StatusInternalServerError,
		})
		return
	}

	h.writeJSON(w, http.StatusOK, orderResponse(order, h.baseURL))
}

func domainsMatch(identifiers []acme.Identifier, csrDomains []string) bool {
	orderDomains := make(map[string]bool)
	for _, id := range identifiers {
		orderDomains[id.Value] = false
	}
	for _, d := range csrDomains {
		if _, ok := orderDomains[d]; !ok {
			return false
		}
		orderDomains[d] = true
	}
	for _, matched := range orderDomains {
		if !matched {
			return false
		}
	}
	return true
}
