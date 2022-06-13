package identity

import (
	"bytes"
	"encoding/json"
	"github.com/gofrs/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/herodot"
	"github.com/ory/kratos/hash"
	"github.com/ory/kratos/x"
	"github.com/ory/x/jsonx"
	"github.com/ory/x/sqlxx"
	"github.com/pkg/errors"
	"net/http"
	"strings"
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
	GroupId        string `json:"group_id"`
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

// CreateOrganizationUserRequest ...
type CreateOrganizationUserRequest struct {
	Email          string `json:"email"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	Password       string `json:"password"`
	PhoneNumber    string `json:"phone_number"`
	OrganizationId string `json:"organization_id"`
}

// CreateOrganizationUser gatekeeper implementation
func (h *Handler) CreateOrganizationUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(CreateOrganizationUserRequest)
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
		Email:          p.Email,
		FirstName:      p.FirstName,
		LastName:       p.LastName,
		PhoneNumber:    p.PhoneNumber,
		Phone:          p.PhoneNumber,
		OrganizationId: p.OrganizationId,
		IsActive:       true,
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

// ChangePasswordRequest ...
type ChangePasswordRequest struct {
	Id          string `json:"id"`
	NewPassword string `json:"new_password"`
}

// ChangePassword gatekeeper implementation
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(ChangePasswordRequest)
	if err := jsonx.NewStrictDecoder(r.Body).Decode(p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(p.Id))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(UserTraits)
	if err = json.Unmarshal(i.Traits, userTraits); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
		return
	}

	// create default payload for this request
	var cr = new(AdminCreateIdentityBody)
	cr.Credentials = &AdminIdentityImportCredentials{
		Password: &AdminIdentityImportCredentialsPassword{
			Config: AdminIdentityImportCredentialsPasswordConfig{
				Password: p.NewPassword,
			},
		},
	}
	cr.SchemaID = i.SchemaID
	cr.Traits = json.RawMessage(i.Traits)

	stateChangedAt := sqlxx.NullTime(time.Now())
	state := StateActive
	if cr.State != "" {
		if err := cr.State.IsValid(); err != nil {
			h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err).WithWrap(err)))
			return
		}
		state = cr.State
	}
	i = &Identity{
		ID:                  i.ID,
		SchemaID:            cr.SchemaID,
		Traits:              []byte(cr.Traits),
		State:               state,
		StateChangedAt:      &stateChangedAt,
		VerifiableAddresses: i.VerifiableAddresses,
		RecoveryAddresses:   i.RecoveryAddresses,
		MetadataAdmin:       i.MetadataAdmin,
		MetadataPublic:      i.MetadataPublic,
	}
	if err := h.importCredentials(r.Context(), i, cr.Credentials); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	if err := h.r.IdentityManager().UpdateWithPassword(r.Context(), i); err != nil {
		h.r.Writer().WriteError(w, r, err)
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

// SoftDeleteRequest ...
type SoftDeleteRequest struct {
	Id string `json:"id"`
}

// SoftDelete gatekeeper implementation
func (h *Handler) SoftDelete(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(SoftDeleteRequest)
	if err := jsonx.NewStrictDecoder(r.Body).Decode(p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(p.Id))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(UserTraits)
	if err = json.Unmarshal(i.Traits, userTraits); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
		return
	}

	// create default payload for this request
	var cr = new(AdminCreateIdentityBody)
	cr.SchemaID = i.SchemaID
	cr.Traits = json.RawMessage(i.Traits)

	stateChangedAt := sqlxx.NullTime(time.Now())
	state := StateInactive
	if cr.State != "" {
		if err := cr.State.IsValid(); err != nil {
			h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err).WithWrap(err)))
			return
		}
		state = cr.State
	}

	i = &Identity{
		Credentials:         i.Credentials,
		ID:                  i.ID,
		SchemaID:            cr.SchemaID,
		Traits:              []byte(cr.Traits),
		State:               state,
		StateChangedAt:      &stateChangedAt,
		VerifiableAddresses: i.VerifiableAddresses,
		RecoveryAddresses:   i.RecoveryAddresses,
		MetadataAdmin:       i.MetadataAdmin,
		MetadataPublic:      i.MetadataPublic,
	}

	if err := h.r.IdentityManager().UpdateWithoutPrivileges(r.Context(), i); err != nil {
		h.r.Writer().WriteError(w, r, err)
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

// ActivateUserRequest ...
type ActivateUserRequest struct {
	Id          string `json:"id"`
	NewPassword string `json:"new_password"`
}

// ActivateUser gatekeeper implementation
func (h *Handler) ActivateUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(ActivateUserRequest)
	if err := jsonx.NewStrictDecoder(r.Body).Decode(p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(p.Id))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(UserTraits)
	if err = json.Unmarshal(i.Traits, userTraits); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
		return
	}

	// create default payload for this request
	var cr = new(AdminCreateIdentityBody)
	cr.Credentials = &AdminIdentityImportCredentials{
		Password: &AdminIdentityImportCredentialsPassword{
			Config: AdminIdentityImportCredentialsPasswordConfig{
				Password: p.NewPassword,
			},
		},
	}
	cr.SchemaID = i.SchemaID
	cr.Traits = json.RawMessage(i.Traits)

	stateChangedAt := sqlxx.NullTime(time.Now())
	state := StateActive
	if cr.State != "" {
		if err := cr.State.IsValid(); err != nil {
			h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err).WithWrap(err)))
			return
		}
		state = cr.State
	}
	i = &Identity{
		ID:                  i.ID,
		SchemaID:            cr.SchemaID,
		Traits:              []byte(cr.Traits),
		State:               state,
		StateChangedAt:      &stateChangedAt,
		VerifiableAddresses: i.VerifiableAddresses,
		RecoveryAddresses:   i.RecoveryAddresses,
		MetadataAdmin:       i.MetadataAdmin,
		MetadataPublic:      i.MetadataPublic,
	}
	if err := h.importCredentials(r.Context(), i, cr.Credentials); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	if err := h.r.IdentityManager().UpdateWithPassword(r.Context(), i); err != nil {
		h.r.Writer().WriteError(w, r, err)
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

// ConfirmPasswordRequest ...
type ConfirmPasswordRequest struct {
	Id              string `json:"id"`
	OldPassword     string `json:"old_password"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

// ConfirmPassword gatekeeper implementation
func (h *Handler) ConfirmPassword(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(ConfirmPasswordRequest)
	if err := jsonx.NewStrictDecoder(r.Body).Decode(p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(p.Id))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	// if user is inactive cannot change password
	if i.State == StateInactive {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("user is inactive")))
		return
	}

	var userTraits = new(UserTraits)
	if err = json.Unmarshal(i.Traits, userTraits); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
		return
	}

	// get user credential
	cred, _ := i.GetCredentials(CredentialsTypePassword)

	var o CredentialsPassword
	d := json.NewDecoder(bytes.NewBuffer(cred.Config))
	if err := d.Decode(&o); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("unable to get credential")))
		return
	}

	if err := hash.Compare(r.Context(), []byte(p.OldPassword), []byte(o.HashedPassword)); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid credential old password")))
		return
	}

	// check if password and confirm password is not same
	if p.Password != p.ConfirmPassword {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("password and old password is not matched")))
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
	cr.SchemaID = i.SchemaID
	cr.Traits = json.RawMessage(i.Traits)

	stateChangedAt := sqlxx.NullTime(time.Now())
	state := StateActive
	if cr.State != "" {
		if err := cr.State.IsValid(); err != nil {
			h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err).WithWrap(err)))
			return
		}
		state = cr.State
	}
	i = &Identity{
		ID:                  i.ID,
		SchemaID:            cr.SchemaID,
		Traits:              []byte(cr.Traits),
		State:               state,
		StateChangedAt:      &stateChangedAt,
		VerifiableAddresses: i.VerifiableAddresses,
		RecoveryAddresses:   i.RecoveryAddresses,
		MetadataAdmin:       i.MetadataAdmin,
		MetadataPublic:      i.MetadataPublic,
	}
	if err := h.importCredentials(r.Context(), i, cr.Credentials); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	if err := h.r.IdentityManager().UpdateWithPassword(r.Context(), i); err != nil {
		h.r.Writer().WriteError(w, r, err)
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

// ChangeUserInfoRequest ...
type ChangeUserInfoRequest struct {
	Id          string `json:"id"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number"`
	FullName    string `json:"full_name"`
}

// ChangeUserInfo gatekeeper implementation
func (h *Handler) ChangeUserInfo(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(ChangeUserInfoRequest)
	if err := jsonx.NewStrictDecoder(r.Body).Decode(p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(p.Id))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(UserTraits)
	if err = json.Unmarshal(i.Traits, userTraits); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
		return
	}

	// assign update to this user
	userTraits.Email = p.Email
	userTraits.Phone = p.PhoneNumber
	userTraits.PhoneNumber = p.PhoneNumber
	if t := strings.Split(p.FullName, " "); len(t) > 0 {
		userTraits.FirstName = t[0]
		userTraits.LastName = strings.Join(t[1:], " ")
	} else {
		userTraits.FirstName = p.FullName
		userTraits.LastName = ""
	}

	i.Traits, _ = json.Marshal(userTraits)
	if err := h.r.IdentityManager().UpdateTraits(r.Context(), i.ID, i.Traits, ManagerAllowWriteProtectedTraits); err != nil {
		h.r.Writer().WriteError(w, r, err)
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

// GetUserWithOrganizationByIdRequest ...
type GetUserWithOrganizationByIdRequest struct {
	Id string `json:"id"`
}

// GetUserWithOrganizationById gatekeeper implementation
func (h *Handler) GetUserWithOrganizationById(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var p = new(GetUserWithOrganizationByIdRequest)
	p.Id = ps.ByName("id")

	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(p.Id))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(UserTraits)
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

	org, err := h.r.PrivilegedIdentityPool().GetOrganizationDetail(r.Context(), x.ParseUUID(userTraits.OrganizationId))
	if err != nil || org == nil {
		h.r.Writer().Write(w, r, resp)
		return
	}

	resp.Organization = &OrganizationGatekeeper{
		Id:                       org.ID.String(),
		Name:                     org.Name,
		LeadsOwner:               org.LeadsOwner,
		ShowCommission:           org.ShowCommission,
		EnableQa:                 org.EnableQa,
		ShowLevelInDashboard:     org.ShowLevelInDashboard,
		ShowShortcutsInDashboard: org.ShowShortcutsInDashboard,
		UseSimpleLeadStatus:      org.UseSimpleLeadStatus,
	}
	h.r.Writer().Write(w, r, resp)
}

// GetOrganizationByIdRequest ...
type GetOrganizationByIdRequest struct {
	Id string `json:"id"`
}

// GetOrganizationById gatekeeper implementation
func (h *Handler) GetOrganizationById(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var p = new(GetOrganizationByIdRequest)
	p.Id = ps.ByName("id")

	org, err := h.r.PrivilegedIdentityPool().GetOrganizationDetail(r.Context(), x.ParseUUID(p.Id))
	if err != nil || org == nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	resp := &OrganizationGatekeeper{
		Id:                       org.ID.String(),
		Name:                     org.Name,
		LeadsOwner:               org.LeadsOwner,
		ShowCommission:           org.ShowCommission,
		EnableQa:                 org.EnableQa,
		ShowLevelInDashboard:     org.ShowLevelInDashboard,
		ShowShortcutsInDashboard: org.ShowShortcutsInDashboard,
		UseSimpleLeadStatus:      org.UseSimpleLeadStatus,
	}
	h.r.Writer().Write(w, r, resp)
}

// GetUserByGroups gatekeeper implementation
func (h *Handler) GetUserByGroups(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p AdminFilterIdentityBody
	if err := jsonx.NewStrictDecoder(r.Body).Decode(&p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	is, err := h.r.IdentityPool().ListIdentitiesFilteredWithoutPagination(r.Context(), p)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	h.r.Writer().Write(w, r, is)
}

