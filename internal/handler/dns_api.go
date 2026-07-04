package handler

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/focalcrest/acme-relay/internal/dns"
	"github.com/focalcrest/acme-relay/pkg/types"
)

// DNSAPIHandler handles DNS TXT record API requests.
type DNSAPIHandler struct {
	txtManager   dns.TXTRecordManager
	allowedZones []string
}

// NewDNSAPIHandler creates a new DNS API handler. allowedZones limits which
// DNS zones the API may write into; an empty list rejects every request.
func NewDNSAPIHandler(txtManager dns.TXTRecordManager, allowedZones []string) *DNSAPIHandler {
	return &DNSAPIHandler{txtManager: txtManager, allowedZones: allowedZones}
}

// dnsTXTRequest is the request body for add/remove TXT record endpoints.
type dnsTXTRequest struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

// challengePrefix is the only record name prefix the API will touch. Holders
// of an API key can publish DNS-01 proofs but cannot write arbitrary records.
const challengePrefix = "_acme-challenge."

// txtValuePattern matches base64url key-authorization digests as sent by
// ACME clients for DNS-01 challenges.
var txtValuePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)

// checkPolicy validates a TXT request against the write policy shared by the
// add and remove endpoints. It writes the error response itself and reports
// whether the request may proceed.
func (h *DNSAPIHandler) checkPolicy(w http.ResponseWriter, req dnsTXTRequest) bool {
	if req.FQDN == "" {
		h.writeDNSAPIError(w, http.StatusBadRequest, "fqdn is required", "")
		return false
	}
	if req.Value == "" {
		h.writeDNSAPIError(w, http.StatusBadRequest, "value is required", "")
		return false
	}
	if !txtValuePattern.MatchString(req.Value) {
		h.writeDNSAPIError(w, http.StatusBadRequest, "invalid TXT value", "value must be a base64url key-authorization digest")
		return false
	}

	name := strings.ToLower(strings.TrimSuffix(req.FQDN, "."))
	rest, ok := strings.CutPrefix(name, challengePrefix)
	if !ok {
		h.writeDNSAPIError(w, http.StatusBadRequest, "invalid fqdn", "fqdn must start with "+challengePrefix)
		return false
	}
	for _, zone := range h.allowedZones {
		zone = strings.ToLower(strings.TrimSuffix(zone, "."))
		if zone != "" && (rest == zone || strings.HasSuffix(rest, "."+zone)) {
			return true
		}
	}
	h.writeDNSAPIError(w, http.StatusForbidden, "fqdn not allowed", "fqdn is outside the allowed zones")
	return false
}

// AddTXT handles POST /api/v1/dns/txt/add
func (h *DNSAPIHandler) AddTXT(w http.ResponseWriter, r *http.Request) {
	var req dnsTXTRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeDNSAPIError(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}

	if !h.checkPolicy(w, req) {
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

	if !h.checkPolicy(w, req) {
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
