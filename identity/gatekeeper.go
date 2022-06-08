package identity

import (
	"bytes"
	"encoding/json"
	"github.com/gofrs/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/herodot"
	"github.com/ory/kratos/gatekeeperschema"
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

// GetOneById gatekeeper implementation
func (h *Handler) GetOneById(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(ps.ByName("id")))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(gatekeeperschema.User)
	if err = json.Unmarshal(i.Traits, userTraits); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
		return
	}
	resp := &gatekeeperschema.User{
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

	var userTraits = new(gatekeeperschema.User)
	if err = json.Unmarshal(is.Traits, userTraits); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
		return
	}
	resp := &gatekeeperschema.User{
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

	var userTraits = new(gatekeeperschema.User)
	if err = json.Unmarshal(is.Traits, userTraits); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
		return
	}
	resp := &gatekeeperschema.User{
		Id:          is.ID.String(),
		Email:       userTraits.Email,
		FirstName:   userTraits.FirstName,
		LastName:    userTraits.LastName,
		PhoneNumber: userTraits.PhoneNumber,
	}
	h.r.Writer().Write(w, r, resp)
}

// CreateWithoutPassword gatekeeper implementation
func (h *Handler) CreateWithoutPassword(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(gatekeeperschema.CreateWithoutPasswordRequest)
	if err := jsonx.NewStrictDecoder(r.Body).Decode(p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	// create default payload for this request
	var cr = new(AdminCreateIdentityBody)
	cr.SchemaID = DefaultSchemaId
	cr.Traits, _ = json.Marshal(&gatekeeperschema.UserTraits{
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

	resp := &gatekeeperschema.User{
		Id:          i.ID.String(),
		Email:       p.Email,
		FirstName:   p.FirstName,
		LastName:    p.LastName,
		PhoneNumber: p.PhoneNumber,
	}
	h.r.Writer().Write(w, r, resp)
}

// CreateWithPassword gatekeeper implementation
func (h *Handler) CreateWithPassword(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(gatekeeperschema.CreateWithPasswordRequest)
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
	cr.Traits, _ = json.Marshal(&gatekeeperschema.UserTraits{
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

	resp := &gatekeeperschema.User{
		Id:          i.ID.String(),
		Email:       p.Email,
		FirstName:   p.FirstName,
		LastName:    p.LastName,
		PhoneNumber: p.PhoneNumber,
	}
	h.r.Writer().Write(w, r, resp)
}

// CreateOrganizationUser gatekeeper implementation
func (h *Handler) CreateOrganizationUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(gatekeeperschema.CreateOrganizationUserRequest)
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
	cr.Traits, _ = json.Marshal(&gatekeeperschema.UserTraits{
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

	resp := &gatekeeperschema.User{
		Id:          i.ID.String(),
		Email:       p.Email,
		FirstName:   p.FirstName,
		LastName:    p.LastName,
		PhoneNumber: p.PhoneNumber,
	}
	h.r.Writer().Write(w, r, resp)
}

// ChangePassword gatekeeper implementation
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(gatekeeperschema.ChangePasswordRequest)
	if err := jsonx.NewStrictDecoder(r.Body).Decode(p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(p.Id))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(gatekeeperschema.UserTraits)
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

	resp := &gatekeeperschema.User{
		Id:          i.ID.String(),
		Email:       userTraits.Email,
		FirstName:   userTraits.FirstName,
		LastName:    userTraits.LastName,
		PhoneNumber: userTraits.PhoneNumber,
	}
	h.r.Writer().Write(w, r, resp)
}

// SoftDelete gatekeeper implementation
func (h *Handler) SoftDelete(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(gatekeeperschema.SoftDeleteRequest)
	if err := jsonx.NewStrictDecoder(r.Body).Decode(p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(p.Id))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(gatekeeperschema.UserTraits)
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

	resp := &gatekeeperschema.User{
		Id:          i.ID.String(),
		Email:       userTraits.Email,
		FirstName:   userTraits.FirstName,
		LastName:    userTraits.LastName,
		PhoneNumber: userTraits.PhoneNumber,
	}
	h.r.Writer().Write(w, r, resp)
}

// ActivateUser gatekeeper implementation
func (h *Handler) ActivateUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(gatekeeperschema.ActivateUserRequest)
	if err := jsonx.NewStrictDecoder(r.Body).Decode(p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(p.Id))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(gatekeeperschema.UserTraits)
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

	resp := &gatekeeperschema.User{
		Id:          i.ID.String(),
		Email:       userTraits.Email,
		FirstName:   userTraits.FirstName,
		LastName:    userTraits.LastName,
		PhoneNumber: userTraits.PhoneNumber,
	}
	h.r.Writer().Write(w, r, resp)
}

// ConfirmPassword gatekeeper implementation
func (h *Handler) ConfirmPassword(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(gatekeeperschema.ConfirmPasswordRequest)
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

	var userTraits = new(gatekeeperschema.UserTraits)
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

	resp := &gatekeeperschema.User{
		Id:          i.ID.String(),
		Email:       userTraits.Email,
		FirstName:   userTraits.FirstName,
		LastName:    userTraits.LastName,
		PhoneNumber: userTraits.PhoneNumber,
	}
	h.r.Writer().Write(w, r, resp)
}

// ChangeUserInfo gatekeeper implementation
func (h *Handler) ChangeUserInfo(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = new(gatekeeperschema.ChangeUserInfoRequest)
	if err := jsonx.NewStrictDecoder(r.Body).Decode(p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(p.Id))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(gatekeeperschema.UserTraits)
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

	resp := &gatekeeperschema.User{
		Id:          i.ID.String(),
		Email:       userTraits.Email,
		FirstName:   userTraits.FirstName,
		LastName:    userTraits.LastName,
		PhoneNumber: userTraits.PhoneNumber,
	}
	h.r.Writer().Write(w, r, resp)
}

// GetUserWithOrganizationById gatekeeper implementation
func (h *Handler) GetUserWithOrganizationById(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var p = new(gatekeeperschema.GetUserWithOrganizationByIdRequest)
	p.Id = ps.ByName("id")

	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(p.Id))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(gatekeeperschema.UserTraits)
	if err = json.Unmarshal(i.Traits, userTraits); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
		return
	}
	resp := &gatekeeperschema.User{
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

	resp.Organization = &gatekeeperschema.OrganizationGatekeeper{
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

// GetOrganizationById gatekeeper implementation
func (h *Handler) GetOrganizationById(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var p = new(gatekeeperschema.GetOrganizationByIdRequest)
	p.Id = ps.ByName("id")

	org, err := h.r.PrivilegedIdentityPool().GetOrganizationDetail(r.Context(), x.ParseUUID(p.Id))
	if err != nil || org == nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	resp := &gatekeeperschema.OrganizationGatekeeper{
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

// CreateOrganization gatekeeper implementation
func (h *Handler) CreateOrganization(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p gatekeeperschema.CreateOrganizationRequest
	if err := jsonx.NewStrictDecoder(r.Body).Decode(&p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	newOrgId, _ := uuid.NewV4()
	i := &Organization{
		ID:                       newOrgId,
		Logo:                     "",
		Name:                     p.Name,
		Slug:                     "",
		LeadsOwner:               "",
		EnableQa:                 false,
		IsActive:                 true,
		ShowCommission:           false,
		ShowMemberStructure:      false,
		UseSimpleLeadStatus:      false,
		ShowLevelInDashboard:     false,
		ShowShortcutsInDashboard: false,
	}
	if err := h.r.IdentityPool().(PrivilegedPool).CreateOrganization(r.Context(), i); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	h.r.Writer().Write(w, r, i)
}

// UpdateOrganizationUser gatekeeper implementation
func (h *Handler) UpdateOrganizationUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p gatekeeperschema.UpdateOrganizationUserRequest
	if err := jsonx.NewStrictDecoder(r.Body).Decode(&p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	var filter = AdminFilterIdentityBody{
		Filters: []*FilterIdentityBody{
			{
				Key:        "traits.email",
				Comparison: "eq",
				Value:      p.Email,
			},
			{
				Key:        "traits.phone_number",
				Comparison: "eq",
				Value:      p.PhoneNumber,
			},
		},
	}
	i, err := h.r.IdentityPool().DetailIdentitiesFiltered(r.Context(), filter)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(gatekeeperschema.UserTraits)
	if err = json.Unmarshal(i.Traits, userTraits); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
		return
	}
	userTraits.OrganizationId = p.OrganizationId
	userTraits.Phone = p.PhoneNumber
	userTraits.PhoneNumber = p.PhoneNumber

	i.Traits, _ = json.Marshal(userTraits)

	if err := h.r.IdentityManager().UpdateTraits(r.Context(), i.ID, i.Traits, ManagerAllowWriteProtectedTraits); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	resp := &gatekeeperschema.User{
		Id:          i.ID.String(),
		Email:       userTraits.Email,
		FirstName:   userTraits.FirstName,
		LastName:    userTraits.LastName,
		PhoneNumber: userTraits.PhoneNumber,
	}

	h.r.Writer().Write(w, r, resp)
}

// UpdateUserOrganization gatekeeper implementation
func (h *Handler) UpdateUserOrganization(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p gatekeeperschema.UpdateUserOrganizationRequest
	if err := jsonx.NewStrictDecoder(r.Body).Decode(&p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	for _, userId := range p.UserIds {
		i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(userId))
		if err != nil {
			h.r.Writer().WriteError(w, r, err)
			return
		}

		var userTraits = new(gatekeeperschema.UserTraits)
		if err = json.Unmarshal(i.Traits, userTraits); err != nil {
			h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
			return
		}

		// assign organization id
		userTraits.OrganizationId = p.OrganizationId
		i.Traits, _ = json.Marshal(userTraits)

		if err := h.r.IdentityManager().UpdateTraits(r.Context(), i.ID, i.Traits, ManagerAllowWriteProtectedTraits); err != nil {
			h.r.Writer().WriteError(w, r, err)
			return
		}
	}
	h.r.Writer().Write(w, r, map[string]bool{"status": true})
}

// UpsertZendeskUserId gatekeeper implementation
func (h *Handler) UpsertZendeskUserId(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p gatekeeperschema.UpsertZendeskUserIdRequest
	if err := jsonx.NewStrictDecoder(r.Body).Decode(&p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	i, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), x.ParseUUID(p.UserId))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var userTraits = new(gatekeeperschema.UserTraits)
	if err = json.Unmarshal(i.Traits, userTraits); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(errors.Errorf("invalid user traits")))
		return
	}

	// assign zendesk user id
	userTraits.ZendeskUserid = p.ZendeskUserid
	i.Traits, _ = json.Marshal(userTraits)

	if err := h.r.IdentityManager().UpdateTraits(r.Context(), i.ID, i.Traits, ManagerAllowWriteProtectedTraits); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().Write(w, r, map[string]interface{}{
		"updated":        true,
		"zendesk_userid": userTraits.ZendeskUserid,
		"user_id":        i.ID.String(),
	})
}
