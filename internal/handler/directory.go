package handler

import (
	"net/http"

	"github.com/focalcrest/acme-relay/internal/acme"
)

// Directory handles GET /acme/directory
func (h *ACMEHandler) Directory(w http.ResponseWriter, r *http.Request) {
	dir := map[string]string{
		"newNonce":   h.baseURL + "/acme/new-nonce",
		"newAccount": h.baseURL + "/acme/new-account",
		"newOrder":   h.baseURL + "/acme/new-order",
		"revokeCert": h.baseURL + "/acme/revoke-cert",
		"keyChange":  h.baseURL + "/acme/key-change",
	}
	h.writeJSON(w, http.StatusOK, dir)
}

// NewNonce handles HEAD/GET /acme/new-nonce
func (h *ACMEHandler) NewNonce(w http.ResponseWriter, r *http.Request) {
	nonce, err := h.nonceSvc.Generate()
	if err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:serverInternal",
			Detail: "failed to generate nonce",
			Status: http.StatusInternalServerError,
		})
		return
	}
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// HEAD request
	w.WriteHeader(http.StatusNoContent)
}
