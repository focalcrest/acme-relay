package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"acme-relay/internal/acme"
)

// GetAuthorization handles POST /acme/authz/{id}
func (h *ACMEHandler) GetAuthorization(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "invalid authorization ID",
			Status: http.StatusBadRequest,
		})
		return
	}

	authz, err := h.store.GetAuthorization(id)
	if err != nil {
		h.writeProblem(w, &acme.Problem{
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: "authorization not found",
			Status: http.StatusNotFound,
		})
		return
	}

	h.writeJSON(w, http.StatusOK, authzResponse(authz))
}

type authzResp struct {
	Status     string            `json:"status"`
	Expires    string            `json:"expires"`
	Identifier acme.Identifier   `json:"identifier"`
	Challenges []challengeResp   `json:"challenges"`
	Wildcard   bool              `json:"wildcard,omitempty"`
}

type challengeResp struct {
	Type             string     `json:"type"`
	URL              string     `json:"url"`
	Token            string     `json:"token"`
	Status           string     `json:"status"`
	Validated        string     `json:"validated,omitempty"`
	Error            *acme.Problem `json:"error,omitempty"`
	KeyAuthorization string     `json:"keyAuthorization,omitempty"`
}

func authzResponse(a *acme.Authorization) authzResp {
	challenges := make([]challengeResp, len(a.Challenges))
	for i, c := range a.Challenges {
		challenges[i] = challengeResp{
			Type:      c.Type,
			URL:       c.URL,
			Token:     c.Token,
			Status:    c.Status,
			Validated: c.Validated.Format(time.RFC3339),
		}
	}
	return authzResp{
		Status:     a.Status,
		Expires:    a.ExpiresAt.Format(time.RFC3339),
		Identifier: a.Identifier,
		Challenges: challenges,
		Wildcard:   a.Wildcard,
	}
}
