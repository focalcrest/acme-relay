package handler

import (
	"encoding/json"
	"net/http"

	"github.com/focalcrest/acme-relay/internal/acme"
	"github.com/focalcrest/acme-relay/internal/storage"
)

// ACMEHandler handles RFC 8555 ACME protocol endpoints.
type ACMEHandler struct {
	store    *storage.FilesystemStorage
	relay    acme.RelayClient
	nonceSvc *acme.NonceService
	idGen    *acme.IDGenerator
	baseURL  string
}

// NewACMEHandler creates a new ACME handler.
func NewACMEHandler(store *storage.FilesystemStorage, relay acme.RelayClient, nonceSvc *acme.NonceService, idGen *acme.IDGenerator, baseURL string) *ACMEHandler {
	return &ACMEHandler{
		store:    store,
		relay:    relay,
		nonceSvc: nonceSvc,
		idGen:    idGen,
		baseURL:  baseURL,
	}
}

func (h *ACMEHandler) addNonce(w http.ResponseWriter) {
	nonce, err := h.nonceSvc.Generate()
	if err != nil {
		return
	}
	w.Header().Set("Replay-Nonce", nonce)
}

func (h *ACMEHandler) writeProblem(w http.ResponseWriter, p *acme.Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	json.NewEncoder(w).Encode(p)
}

func (h *ACMEHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	h.addNonce(w)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *ACMEHandler) jwsFromContext(r *http.Request) *acme.JWSRequest {
	return acme.JWSFromContext(r)
}
