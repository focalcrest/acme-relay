package handler

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/focalcrest/acme-relay/internal/acme"
)

// GetCertificate handles GET-like POST /acme/certificate/{orderID}
func (h *ACMEHandler) GetCertificate(w http.ResponseWriter, r *http.Request) {
	jwsReq := h.jwsFromContext(r)
	if jwsReq == nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "missing JWS context",
			Status: http.StatusBadRequest,
		})
		return
	}

	orderID, err := strconv.ParseInt(chi.URLParam(r, "orderID"), 10, 64)
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
			Type:   "urn:ietf:params:acme:error:unauthorized",
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

	if order.Status != acme.OrderStatusValid || order.Certificate == "" {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:orderNotReady",
			Detail: "certificate not available",
			Status: http.StatusForbidden,
		})
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	h.addNonce(w)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(order.Certificate))
}
