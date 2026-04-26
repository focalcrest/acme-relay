// Package handler provides HTTP handlers for the acme-relay API.
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"acme-relay/internal/acme"
	"acme-relay/pkg/types"
)

// CertificateHandler handles HTTP requests for certificate operations.
type CertificateHandler struct {
	relay acme.RelayClient
}

// NewCertificateHandler creates a new certificate handler.
func NewCertificateHandler(relay acme.RelayClient) *CertificateHandler {
	return &CertificateHandler{relay: relay}
}

// RequestCertificate handles POST /certificate
func (h *CertificateHandler) RequestCertificate(w http.ResponseWriter, r *http.Request) {
	var req types.CertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}

	// Validate request
	if len(req.Domains) == 0 {
		h.writeError(w, http.StatusBadRequest, "domains are required", "")
		return
	}
	if req.CSR == "" {
		h.writeError(w, http.StatusBadRequest, "CSR is required", "")
		return
	}

	// Normalize domains
	for i, domain := range req.Domains {
		req.Domains[i] = acme.NormalizeDomain(domain)
	}

	// Request certificate
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	response, err := h.relay.RequestCertificate(ctx, req.Domains, req.CSR)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to obtain certificate", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// GetCertificate handles GET /certificate/:domain
func (h *CertificateHandler) GetCertificate(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		h.writeError(w, http.StatusBadRequest, "domain is required", "")
		return
	}

	domain = acme.NormalizeDomain(domain)

	cert, err := h.relay.GetCertificate(domain)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "certificate not found", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, cert)
}

// RenewCertificate handles POST /renew/:domain
func (h *CertificateHandler) RenewCertificate(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		h.writeError(w, http.StatusBadRequest, "domain is required", "")
		return
	}

	domain = acme.NormalizeDomain(domain)

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	response, err := h.relay.RenewCertificate(ctx, domain)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to renew certificate", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// HealthCheck handles GET /health
func (h *CertificateHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, http.StatusOK, types.HealthResponse{
		Status:    "ok",
		Timestamp: time.Now().Unix(),
	})
}

func (h *CertificateHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *CertificateHandler) writeError(w http.ResponseWriter, status int, message, details string) {
	h.writeJSON(w, status, types.ErrorResponse{
		Error:   message,
		Code:    status,
		Details: details,
	})
}
