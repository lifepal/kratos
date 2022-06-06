package identity

import (
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/herodot"
	"github.com/ory/kratos/x"
	"github.com/ory/x/jsonx"
	"github.com/ory/x/sqlxx"
	"github.com/pkg/errors"
	"net/http"
	"time"
)

const (
	DefaultSchemaId = "lifepal"
	RouteGatekeeper = "/gatekeeper"

	GetOneByIdRoute                  = RouteGatekeeper + "/GetOneById" + "/:id"
	GetOneByEmailRoute               = RouteGatekeeper + "/GetOneByEmail"
	GetOneByEmailPhoneRoute          = RouteGatekeeper + "/GetOneByEmailPhone"
	CreateWithoutPasswordRoute       = RouteGatekeeper + "/CreateWithoutPassword"
	CreateWithPasswordRoute          = RouteGatekeeper + "/CreateWithPassword"
	CreateOrganizationUserRoute      = RouteGatekeeper + "/CreateOrganizationUser"
	ChangePasswordRoute              = RouteGatekeeper + "/ChangePassword"
	SoftDeleteRoute                  = RouteGatekeeper + "/SoftDelete"
	ActivateUserRoute                = RouteGatekeeper + "/ActivateUser"
	ConfirmPasswordRoute             = RouteGatekeeper + "/ConfirmPassword"
	ChangeUserInfoRoute              = RouteGatekeeper + "/ChangeUserInfo"
	GetUserWithOrganizationByIdRoute = RouteGatekeeper + "/GetUserWithOrganizationById" + "/:id"
	GetOrganizationByIdRoute         = RouteGatekeeper + "/GetOrganizationById" + "/:id"
	GetUserByGroupsRoute             = RouteGatekeeper + "/GetUserByGroups"
	CreateOrganizationRoute          = RouteGatekeeper + "/CreateOrganization"
	UpdateOrganizationUserRoute      = RouteGatekeeper + "/UpdateOrganizationUser"
	UpdateUserOrganizationRoute      = RouteGatekeeper + "/UpdateUserOrganization"
	UpsertZendeskUserIdRoute         = RouteGatekeeper + "/UpsertZendeskUserId"
)

type UserTraits struct {
	LastLogin      string `json:"last_login"`
	IsSuperuser    bool   `json:"is_superuser"`
	Phone          string `json:"phone"`
	Username       string `json:"username"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	Email          string `json:"email"`
	IsStaff        bool   `json:"is_staff"`
	IsActive       bool   `json:"is_active"`
	DateJoined     string `json:"date_joined"`
	SocialId       int64  `json:"social_id"`
	SocialType     int64  `json:"social_type"`
	Source         int64  `json:"source"`
	HumanId        int64  `json:"human_id"`
	IsVerified     bool   `json:"is_verified"`
	PhoneNumber    string `json:"phone_number"`
	UpdatedAt      string `json:"updated_at"`
	OrganizationId string `json:"organization_id"`
	ZendeskUserid  string `json:"zendesk_userid"`
}

type OrganizationGatekeeper struct {
	Id                       string `json:"id"`
	Name                     string `json:"name"`
	LeadsOwner               string `json:"leads_owner"`
	ShowCommission           bool   `json:"show_commision"`
	EnableQa                 bool   `json:"enable_qa"`
	ShowLevelInDashboard     bool   `json:"show_level_in_dashboard"`
	ShowShortcutsInDashboard bool   `json:"show_shortcuts_in_dashboard"`
	UseSimpleLeadStatus      bool   `json:"use_simple_lead_status"`
}

// User Gatekeeper struct
type User struct {
	Id           string                  `json:"id"`
	Email        string                  `json:"email"`
	FirstName    string                  `json:"first_name"`
	LastName     string                  `json:"last_name"`
	PhoneNumber  string                  `json:"phone_number"`
	Organization *OrganizationGatekeeper `json:"organization,omitempty"`
}

// GetOneById gatekeeper implementation
func (h *Handler) GetOneById(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(ps.ByName("id")))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(User)
	if err = json.Unmarshal(i.Traits, userTraits); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
		return
	}
	resp := &User{
		Id:          i.ID.String(),
		Email:       userTraits.Email,
		FirstName:   userTraits.FirstName,
		LastName:    userTraits.LastName,
		PhoneNumber: userTraits.PhoneNumber,
	}
	h.r.Writer().Write(w, r, resp)
}

// GetOneByEmail gatekeeper implementation
func (h *Handler) GetOneByEmail(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p AdminFilterIdentityBody
	if err := jsonx.NewStrictDecoder(r.Body).Decode(&p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	is, err := h.r.IdentityPool().DetailIdentitiesFiltered(r.Context(), p)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(User)
	if err = json.Unmarshal(is.Traits, userTraits); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
		return
	}
	resp := &User{
		Id:          is.ID.String(),
		Email:       userTraits.Email,
		FirstName:   userTraits.FirstName,
		LastName:    userTraits.LastName,
		PhoneNumber: userTraits.PhoneNumber,
	}
	h.r.Writer().Write(w, r, resp)
}

// GetOneByEmailPhone gatekeeper implementation
func (h *Handler) GetOneByEmailPhone(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p AdminFilterIdentityBody
	if err := jsonx.NewStrictDecoder(r.Body).Decode(&p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	is, err := h.r.IdentityPool().DetailIdentitiesFiltered(r.Context(), p)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(User)
	if err = json.Unmarshal(is.Traits, userTraits); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
		return
	}
	resp := &User{
		Id:          is.ID.String(),
		Email:       userTraits.Email,
		FirstName:   userTraits.FirstName,
		LastName:    userTraits.LastName,
		PhoneNumber: userTraits.PhoneNumber,
	}
	h.r.Writer().Write(w, r, resp)
}

// CreateWithoutPasswordRequest ...
type CreateWithoutPasswordRequest struct {
	Email       string `json:"email"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	PhoneNumber string `json:"phone_number"`
}

// CreateWithoutPassword gatekeeper implementation
func (h *Handler) CreateWithoutPassword(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(CreateWithoutPasswordRequest)
	if err := jsonx.NewStrictDecoder(r.Body).Decode(p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	// create default payload for this request
	var cr = new(AdminCreateIdentityBody)
	cr.SchemaID = DefaultSchemaId
	cr.Traits, _ = json.Marshal(&UserTraits{
		Email:       p.Email,
		FirstName:   p.FirstName,
		LastName:    p.LastName,
		PhoneNumber: p.PhoneNumber,
		Phone:       p.PhoneNumber,
		IsActive:    true,
	})
	cr.VerifiableAddresses = []VerifiableAddress{
		{Value: p.Email, Verified: true, Via: VerifiableAddressTypeEmail, Status: VerifiableAddressStatusCompleted},
	}

	stateChangedAt := sqlxx.NullTime(time.Now())
	state := StateActive
	if cr.State != "" {
		if err := cr.State.IsValid(); err != nil {
			h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err).WithWrap(err)))
			return
		}
		state = cr.State
	}

	i := &Identity{
		SchemaID:            cr.SchemaID,
		Traits:              []byte(cr.Traits),
		State:               state,
		StateChangedAt:      &stateChangedAt,
		VerifiableAddresses: cr.VerifiableAddresses,
		RecoveryAddresses:   cr.RecoveryAddresses,
		MetadataAdmin:       []byte(cr.MetadataAdmin),
		MetadataPublic:      []byte(cr.MetadataPublic),
	}
	if err := h.r.IdentityManager().Create(r.Context(), i); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	resp := &User{
		Id:          i.ID.String(),
		Email:       p.Email,
		FirstName:   p.FirstName,
		LastName:    p.LastName,
		PhoneNumber: p.PhoneNumber,
	}
	h.r.Writer().Write(w, r, resp)
}

// CreateWithPasswordRequest ...
type CreateWithPasswordRequest struct {
	Password    string `json:"password"`
	Email       string `json:"email"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	PhoneNumber string `json:"phone_number"`
}

// CreateWithPassword gatekeeper implementation
func (h *Handler) CreateWithPassword(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(CreateWithPasswordRequest)
	if err := jsonx.NewStrictDecoder(r.Body).Decode(p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	// create default payload for this request
	var cr = new(AdminCreateIdentityBody)
	cr.Credentials = &AdminIdentityImportCredentials{
		Password: &AdminIdentityImportCredentialsPassword{
			Config: AdminIdentityImportCredentialsPasswordConfig{
				Password: p.Password,
			},
		},
	}
	cr.SchemaID = DefaultSchemaId
	cr.Traits, _ = json.Marshal(&UserTraits{
		Email:       p.Email,
		FirstName:   p.FirstName,
		LastName:    p.LastName,
		PhoneNumber: p.PhoneNumber,
		Phone:       p.PhoneNumber,
		IsActive:    true,
	})
	cr.VerifiableAddresses = []VerifiableAddress{
		{Value: p.Email, Verified: true, Via: VerifiableAddressTypeEmail, Status: VerifiableAddressStatusCompleted},
	}

	stateChangedAt := sqlxx.NullTime(time.Now())
	state := StateActive
	if cr.State != "" {
		if err := cr.State.IsValid(); err != nil {
			h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err).WithWrap(err)))
			return
		}
		state = cr.State
	}
	i := &Identity{
		SchemaID:            cr.SchemaID,
		Traits:              []byte(cr.Traits),
		State:               state,
		StateChangedAt:      &stateChangedAt,
		VerifiableAddresses: cr.VerifiableAddresses,
		RecoveryAddresses:   cr.RecoveryAddresses,
		MetadataAdmin:       []byte(cr.MetadataAdmin),
		MetadataPublic:      []byte(cr.MetadataPublic),
	}
	if err := h.importCredentials(r.Context(), i, cr.Credentials); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	if err := h.r.IdentityManager().Create(r.Context(), i); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	resp := &User{
		Id:          i.ID.String(),
		Email:       p.Email,
		FirstName:   p.FirstName,
		LastName:    p.LastName,
		PhoneNumber: p.PhoneNumber,
	}
	h.r.Writer().Write(w, r, resp)
}
