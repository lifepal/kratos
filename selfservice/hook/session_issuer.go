package hook

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/selfservice/flow/login"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
)

var (
	_ registration.PostHookPostPersistExecutor = new(SessionIssuer)
)

type (
	sessionIssuerDependencies interface {
		config.Provider
		session.ManagementProvider
		session.PersistenceProvider
		x.WriterProvider
	}
	SessionIssuerProvider interface {
		HookSessionIssuer() *SessionIssuer
	}
	SessionIssuer struct {
		r sessionIssuerDependencies
	}
)

func NewSessionIssuer(r sessionIssuerDependencies) *SessionIssuer {
	return &SessionIssuer{r: r}
}

func (e *SessionIssuer) ExecutePostRegistrationPostPersistHook(w http.ResponseWriter, r *http.Request, a *registration.Flow, s *session.Session) error {
	s.AuthenticatedAt = time.Now().UTC()
	if err := e.r.SessionPersister().UpsertSession(r.Context(), s); err != nil {
		return err
	}

	if a.Type == flow.TypeAPI {
		oryDefaultSessionLifetime := e.r.Config(r.Context()).SessionLifespan()
		uTraits := new(login.UserTraits)
		json.Unmarshal(s.Identity.Traits, uTraits)
		// create jwt claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, login.Token{
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
			IsSuperUser: uTraits.IsSuperUser,
			PhoneNumber: uTraits.PhoneNumber,
			OrganizationId: uTraits.OrganizationId,
			UserId: s.NID.String(),
			SessionId: s.ID.String(),
			SessionToken: s.Token,
			TokenType: "access",
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().UTC().Add(oryDefaultSessionLifetime).Unix(),
				Issuer:    login.GetIssuer(),
			},
		})
		refresh := jwt.NewWithClaims(jwt.SigningMethodHS256, login.Token{
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
			IsSuperUser: uTraits.IsSuperUser,
			PhoneNumber: uTraits.PhoneNumber,
			OrganizationId: uTraits.OrganizationId,
			UserId: s.NID.String(),
			SessionId: s.ID.String(),
			SessionToken: s.Token,
			TokenType: "refresh",
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().UTC().Add(oryDefaultSessionLifetime * 2).Unix(),
				Issuer:    login.GetIssuer(),
			},
		})

		var wrapResponse = new(login.ResponseLogin)
		wrapResponse.Access, _ = token.SignedString([]byte(login.GetJwtSecret()))
		wrapResponse.Refresh, _ = refresh.SignedString([]byte(login.GetJwtSecret()))
		e.r.Writer().Write(w, r, wrapResponse)
		return errors.WithStack(registration.ErrHookAbortFlow)
	}

	// cookie is issued both for browser and for SPA flows
	if err := e.r.SessionManager().IssueCookie(r.Context(), w, r, s); err != nil {
		return err
	}

	// SPA flows additionally send the session
	if x.IsJSONRequest(r) {
		e.r.Writer().Write(w, r, &registration.APIFlowResponse{
			Session:  s,
			Identity: s.Identity,
		})
		return errors.WithStack(registration.ErrHookAbortFlow)
	}

	return nil
}
