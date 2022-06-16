package login

import (
	"encoding/json"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/gatekeeperschema"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/session"
	"net/http"
)

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"

	"github.com/dgrijalva/jwt-go"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/x"
)

type (
	PreHookExecutor interface {
		ExecuteLoginPreHook(w http.ResponseWriter, r *http.Request, a *Flow) error
	}

	PostHookExecutor interface {
		ExecuteLoginPostHook(w http.ResponseWriter, r *http.Request, a *Flow, s *session.Session) error
	}

	HooksProvider interface {
		PreLoginHooks(ctx context.Context) []PreHookExecutor
		PostLoginHooks(ctx context.Context, credentialsType identity.CredentialsType) []PostHookExecutor
	}
)

type (
	executorDependencies interface {
		config.Provider
		session.ManagementProvider
		session.PersistenceProvider
		x.WriterProvider
		x.LoggingProvider

		HooksProvider
	}
	HookExecutor struct {
		d executorDependencies
	}
	HookExecutorProvider interface {
		LoginHookExecutor() *HookExecutor
	}
)

type ResponseLogin struct {
	Access string `json:"access,omitempty"`
	Refresh string `json:"refresh,omitempty"`
}

func PostHookExecutorNames(e []PostHookExecutor) []string {
	names := make([]string, len(e))
	for k, ee := range e {
		names[k] = fmt.Sprintf("%T", ee)
	}
	return names
}

func NewHookExecutor(d executorDependencies) *HookExecutor {
	return &HookExecutor{d: d}
}

func (e *HookExecutor) requiresAAL2(r *http.Request, s *session.Session, a *Flow) (*session.ErrAALNotSatisfied, bool) {
	var aalErr *session.ErrAALNotSatisfied
	err := e.d.SessionManager().DoesSessionSatisfy(r, s, e.d.Config(r.Context()).SessionWhoAmIAAL())
	if ok := errors.As(err, &aalErr); !ok {
		return nil, false
	}

	if err := aalErr.PassReturnToParameter(a.RequestURL); err != nil {
		return nil, false
	}

	return aalErr, true
}

func (e *HookExecutor) PostLoginHook(w http.ResponseWriter, r *http.Request, a *Flow, i *identity.Identity, s *session.Session) error {
	if err := s.Activate(i, e.d.Config(r.Context()), time.Now().UTC()); err != nil {
		return err
	}

	// Verify the redirect URL before we do any other processing.
	c := e.d.Config(r.Context())
	returnTo, err := x.SecureRedirectTo(r, c.SelfServiceBrowserDefaultReturnTo(),
		x.SecureRedirectUseSourceURL(a.RequestURL),
		x.SecureRedirectAllowURLs(c.SelfServiceBrowserAllowedReturnToDomains()),
		x.SecureRedirectAllowSelfServiceURLs(c.SelfPublicURL()),
		x.SecureRedirectOverrideDefaultReturnTo(e.d.Config(r.Context()).SelfServiceFlowLoginReturnTo(a.Active.String())),
	)
	if err != nil {
		return err
	}

	s = s.Declassify()

	e.d.Logger().
		WithRequest(r).
		WithField("identity_id", i.ID).
		WithField("flow_method", a.Active).
		Debug("Running ExecuteLoginPostHook.")
	for k, executor := range e.d.PostLoginHooks(r.Context(), a.Active) {
		if err := executor.ExecuteLoginPostHook(w, r, a, s); err != nil {
			if errors.Is(err, ErrHookAbortFlow) {
				e.d.Logger().
					WithRequest(r).
					WithField("executor", fmt.Sprintf("%T", executor)).
					WithField("executor_position", k).
					WithField("executors", PostHookExecutorNames(e.d.PostLoginHooks(r.Context(), a.Active))).
					WithField("identity_id", i.ID).
					WithField("flow_method", a.Active).
					Debug("A ExecuteLoginPostHook hook aborted early.")
				return nil
			}
			return err
		}

		e.d.Logger().
			WithRequest(r).
			WithField("executor", fmt.Sprintf("%T", executor)).
			WithField("executor_position", k).
			WithField("executors", PostHookExecutorNames(e.d.PostLoginHooks(r.Context(), a.Active))).
			WithField("identity_id", i.ID).
			WithField("flow_method", a.Active).
			Debug("ExecuteLoginPostHook completed successfully.")
	}

	if a.Type == flow.TypeAPI {
		if err := e.d.SessionPersister().UpsertSession(r.Context(), s); err != nil {
			return errors.WithStack(err)
		}
		e.d.Audit().
			WithRequest(r).
			WithField("session_id", s.ID).
			WithField("identity_id", i.ID).
			Info("Identity authenticated successfully and was issued an Ory Kratos Session Token.")

		response := &APIFlowResponse{Session: s, Token: s.Token}
		if _, required := e.requiresAAL2(r, s, a); required {
			// If AAL is not satisfied, we omit the identity to preserve the user's privacy in case of a phishing attack.
			response.Session.Identity = nil
		}

		e.d.Writer().Write(w, r, response)
		return nil
	}

	if err := e.d.SessionManager().UpsertAndIssueCookie(r.Context(), w, r, s); err != nil {
		return errors.WithStack(err)
	}

	e.d.Audit().
		WithRequest(r).
		WithField("identity_id", i.ID).
		WithField("session_id", s.ID).
		Info("Identity authenticated successfully and was issued an Ory Kratos Session Cookie.")

	if x.IsJSONRequest(r) {
		// Browser flows rely on cookies. Adding tokens in the mix will confuse consumers.
		s.Token = ""

		response := &APIFlowResponse{Session: s}
		if _, required := e.requiresAAL2(r, s, a); required {
			// If AAL is not satisfied, we omit the identity to preserve the user's privacy in case of a phishing attack.
			response.Session.Identity = nil
		}
		e.d.Writer().Write(w, r, response)
		return nil
	}

	// If we detect that whoami would require a higher AAL, we redirect!
	if aalErr, required := e.requiresAAL2(r, s, a); required {
		http.Redirect(w, r, aalErr.RedirectTo, http.StatusSeeOther)
		return nil
	}

	x.ContentNegotiationRedirection(w, r, s.Declassify(), e.d.Writer(), returnTo.String())
	return nil
}

func (e *HookExecutor) LifepallOauthPostLoginHook(w http.ResponseWriter, r *http.Request, a *Flow, i *identity.Identity, s *session.Session) error {
	// create token
	if err := s.Activate(i, e.d.Config(r.Context()), time.Now().UTC()); err != nil {
		return err
	}

	oryDefaultSessionLifetime := e.d.Config(r.Context()).SessionLifespan()

	uTraits := new(gatekeeperschema.UserTraits)
	json.Unmarshal(i.Traits, uTraits)
	// create jwt claims
	access := jwt.NewWithClaims(jwt.SigningMethodHS256, gatekeeperschema.Token{
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
		SessionId: s.ID.String(),
		SessionToken: s.Token,
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
		SessionId: s.ID.String(),
		SessionToken: s.Token,
		TokenType: "refresh",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().UTC().Add(oryDefaultSessionLifetime * 2).Unix(),
			Issuer:    GetIssuer(),
		},
	})

	if err := e.d.SessionPersister().UpsertSession(r.Context(), s); err != nil {
		return errors.WithStack(err)
	}
	e.d.Audit().
		WithRequest(r).
		WithField("session_id", s.ID).
		WithField("identity_id", i.ID).
		Info("Identity authenticated successfully and was issued an Ory Kratos Session Token.")

	response := &APIFlowResponse{Session: s, Token: s.Token}
	if _, required := e.requiresAAL2(r, s, a); required {
		// If AAL is not satisfied, we omit the identity to preserve the user's privacy in case of a phishing attack.
		response.Session.Identity = nil
	}

	var wrapResponse = new(ResponseLogin)
	wrapResponse.Access, _ = access.SignedString([]byte(GetJwtSecret()))
	wrapResponse.Refresh, _ = refresh.SignedString([]byte(GetJwtSecret()))

	e.d.Writer().Write(w, r, wrapResponse)
	return nil
}

func (e *HookExecutor) LifepallPostLoginHook(w http.ResponseWriter, r *http.Request, a *Flow, i *identity.Identity, s *session.Session) error {
	// create token
	if err := s.Activate(i, e.d.Config(r.Context()), time.Now().UTC()); err != nil {
		return err
	}

	oryDefaultSessionLifetime := e.d.Config(r.Context()).SessionLifespan()

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
		SessionId: s.ID.String(),
		SessionToken: s.Token,
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
		SessionId: s.ID.String(),
		SessionToken: s.Token,
		TokenType: "refresh",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().UTC().Add(oryDefaultSessionLifetime * 2).Unix(),
			Issuer:    GetIssuer(),
		},
	})

	if err := e.d.SessionPersister().UpsertSession(r.Context(), s); err != nil {
		return errors.WithStack(err)
	}
	e.d.Audit().
		WithRequest(r).
		WithField("session_id", s.ID).
		WithField("identity_id", i.ID).
		Info("Identity authenticated successfully and was issued an Ory Kratos Session Token.")

	response := &APIFlowResponse{Session: s, Token: s.Token}
	if _, required := e.requiresAAL2(r, s, a); required {
		// If AAL is not satisfied, we omit the identity to preserve the user's privacy in case of a phishing attack.
		response.Session.Identity = nil
	}

	var wrapResponse = new(ResponseLogin)
	wrapResponse.Access, _ = token.SignedString([]byte(GetJwtSecret()))
	wrapResponse.Refresh, _ = refresh.SignedString([]byte(GetJwtSecret()))

	e.d.Writer().Write(w, r, wrapResponse)
	return nil
}

func (e *HookExecutor) PreLoginHook(w http.ResponseWriter, r *http.Request, a *Flow) error {
	for _, executor := range e.d.PreLoginHooks(r.Context()) {
		if err := executor.ExecuteLoginPreHook(w, r, a); err != nil {
			return err
		}
	}

	return nil
}
