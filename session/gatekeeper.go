package session

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/kratos/gatekeeperschema"
	"github.com/ory/kratos/identity"
	"github.com/pkg/errors"
	"net/http"
	"time"
)

const (
	RouteGatekeeper = "/gatekeeper"

	GetTokenRoute         = RouteGatekeeper + "/GetToken" + "/:username"
)

type GetTokenRequest struct {
	Username string `json:"username"`
}


// GetToken gatekeeper implementation
func (h *Handler) GetToken(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var p GetTokenRequest
	p.Username = ps.ByName("username")

	var filter = identity.AdminFilterIdentityBody{
		Filters: []*identity.FilterIdentityBody{
			{
				Key:        "traits.username",
				Comparison: "eq",
				Value:      p.Username,
			},
		},
	}
	i, err := h.r.IdentityPool().DetailIdentitiesFiltered(r.Context(), filter)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	ses, err := h.r.SessionPersister().GetSessionByIdentity(r.Context(), i.ID)
	if err != nil {
		h.r.Writer().WriteError(w, r, errors.New("token not found"))
		return
	}

	// if session is expired then reactivate
	if !ses.IsActive() {
		// if we want to throw error when session is expired then comment this code
		if err := ses.Activate(i, h.r.Config(r.Context()), time.Now().UTC()); err != nil {
			h.r.Writer().WriteError(w, r, err)
			return
		}
	}

	oryDefaultSessionLifetime := h.r.Config(r.Context()).SessionLifespan()

	uTraits := new(gatekeeperschema.UserTraits)
	json.Unmarshal(i.Traits, uTraits)
	// create jwt claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, gatekeeperschema.Token{
		Email: uTraits.Email,
		Phone: uTraits.Phone,
		Source: uTraits.Source,
		HumanId: uTraits.HumanId,
		IsStaff: uTraits.IsStaff,
		Username: uTraits.Username,
		IsActive: uTraits.IsActive,
		LastName: uTraits.LastName,
		SocialId: uTraits.SocialId,
		FirstName: uTraits.FirstName,
		LastLogin: uTraits.LastLogin,
		UpdatedAt: uTraits.UpdatedAt,
		DateJoined: uTraits.DateJoined,
		IsVerified: uTraits.IsVerified,
		SocialType: uTraits.SocialType,
		IsSuperUser: uTraits.IsSuperuser,
		PhoneNumber: uTraits.PhoneNumber,
		OrganizationId: uTraits.OrganizationId,
		UserId: i.NID.String(),
		SessionId: ses.ID.String(),
		SessionToken: ses.Token,
		TokenType: "access",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().UTC().Add(oryDefaultSessionLifetime).Unix(),
			Issuer:    GetIssuer(),
		},
	})
	refresh := jwt.NewWithClaims(jwt.SigningMethodHS256, gatekeeperschema.Token{
		Email: uTraits.Email,
		Phone: uTraits.Phone,
		Source: uTraits.Source,
		HumanId: uTraits.HumanId,
		IsStaff: uTraits.IsStaff,
		Username: uTraits.Username,
		IsActive: uTraits.IsActive,
		LastName: uTraits.LastName,
		SocialId: uTraits.SocialId,
		FirstName: uTraits.FirstName,
		LastLogin: uTraits.LastLogin,
		UpdatedAt: uTraits.UpdatedAt,
		DateJoined: uTraits.DateJoined,
		IsVerified: uTraits.IsVerified,
		SocialType: uTraits.SocialType,
		IsSuperUser: uTraits.IsSuperuser,
		PhoneNumber: uTraits.PhoneNumber,
		OrganizationId: uTraits.OrganizationId,
		UserId: i.NID.String(),
		SessionId: ses.ID.String(),
		SessionToken: ses.Token,
		TokenType: "refresh",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().UTC().Add(oryDefaultSessionLifetime * 2).Unix(),
			Issuer:    GetIssuer(),
		},
	})

	var wrapResponse = make(map[string]interface{})
	wrapResponse["access"], _ = token.SignedString([]byte(GetJwtSecret()))
	wrapResponse["refresh"], _ = refresh.SignedString([]byte(GetJwtSecret()))

	h.r.Writer().Write(w, r, wrapResponse)
}
