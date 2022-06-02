package identity

import (
	"github.com/julienschmidt/httprouter"
	"github.com/ory/herodot"
	"github.com/ory/kratos/x"
	"github.com/pkg/errors"
	"net/http"
)

const (
	RouteGatekeeper = "/gatekeeper"

	GetOneByIdRoute = RouteGatekeeper + "/GetOneById" + "/:id"
)

// User Gatekeeper struct
type User struct {
	Id string `json:"id"`
	Email string `json:"email"`
	FirstName string `json:"first_name"`
	LastName string `json:"last_name"`
	PhoneNumber string `json:"phone_number"`
}

// GetOneById gatekeeper implementation
func (h *Handler) GetOneById(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(ps.ByName("id")))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	if declassify := r.URL.Query().Get("include_credential"); declassify == "oidc" {
		emit, err := i.WithDeclassifiedCredentialsOIDC(r.Context(), h.r)
		if err != nil {
			h.r.Writer().WriteError(w, r, err)
			return
		}
		h.r.Writer().Write(w, r, WithCredentialsAndAdminMetadataInJSON(*emit))
		return
	} else if len(declassify) > 0 {
		h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrBadRequest.WithReasonf("Invalid value `%s` for parameter `include_credential`.", declassify)))
		return

	}

	h.r.Writer().Write(w, r, WithCredentialsMetadataAndAdminMetadataInJSON(*i))
}
