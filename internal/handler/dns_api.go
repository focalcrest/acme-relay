package handler

import (
	"encoding/json"
	"net/http"

	"github.com/focalcrest/acme-relay/internal/dns"
	"github.com/focalcrest/acme-relay/pkg/types"
)

// DNSAPIHandler handles DNS TXT record API requests.
type DNSAPIHandler struct {
	txtManager dns.TXTRecordManager
}

// NewDNSAPIHandler creates a new DNS API handler.
func NewDNSAPIHandler(txtManager dns.TXTRecordManager) *DNSAPIHandler {
	return &DNSAPIHandler{txtManager: txtManager}
}

// dnsTXTRequest is the request body for add/remove TXT record endpoints.
type dnsTXTRequest struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

// AddTXT handles POST /api/v1/dns/txt/add
func (h *DNSAPIHandler) AddTXT(w http.ResponseWriter, r *http.Request) {
	var req dnsTXTRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeDNSAPIError(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}

	if req.FQDN == "" {
		h.writeDNSAPIError(w, http.StatusBadRequest, "fqdn is required", "")
		return
	}
	if req.Value == "" {
		h.writeDNSAPIError(w, http.StatusBadRequest, "value is required", "")
		return
	}

	if err := h.txtManager.AddTXTRecord(req.FQDN, req.Value); err != nil {
		h.writeDNSAPIError(w, http.StatusInternalServerError, "failed to add TXT record", err.Error())
		return
	}

	h.writeDNSAPIJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// RemoveTXT handles POST /api/v1/dns/txt/remove
func (h *DNSAPIHandler) RemoveTXT(w http.ResponseWriter, r *http.Request) {
	var req dnsTXTRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeDNSAPIError(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}

	if req.FQDN == "" {
		h.writeDNSAPIError(w, http.StatusBadRequest, "fqdn is required", "")
		return
	}
	if req.Value == "" {
		h.writeDNSAPIError(w, http.StatusBadRequest, "value is required", "")
		return
	}

	if err := h.txtManager.RemoveTXTRecord(req.FQDN, req.Value); err != nil {
		h.writeDNSAPIError(w, http.StatusInternalServerError, "failed to remove TXT record", err.Error())
		return
	}

	h.writeDNSAPIJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *DNSAPIHandler) writeDNSAPIJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *DNSAPIHandler) writeDNSAPIError(w http.ResponseWriter, status int, message, details string) {
	h.writeDNSAPIJSON(w, status, types.ErrorResponse{
		Error:   message,
		Code:    status,
		Details: details,
	})
}
