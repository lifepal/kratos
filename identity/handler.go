package identity

import (
	"context"
	"encoding/json"

	"net/http"
	"time"

	"github.com/ory/kratos/hash"

	"github.com/ory/kratos/x"

	"github.com/ory/kratos/cipher"

	"github.com/ory/herodot"

	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"

	"github.com/ory/x/decoderx"
	"github.com/ory/x/jsonx"
	"github.com/ory/x/sqlxx"
	"github.com/ory/x/urlx"

	"github.com/ory/kratos/driver/config"
)

const (
	RouteCollectionFilter = "/identities-filter"
	RouteOrganizationCollection = "/organization"
	RouteOrganizationCollectionItem = RouteOrganizationCollection + "/:id"
	RouteCollection = "/identities"
	RouteItem = RouteCollection + "/:id"
)

type (
	handlerDependencies interface {
		PoolProvider
		PrivilegedPoolProvider
		ManagementProvider
		x.WriterProvider
		config.Provider
		x.CSRFProvider
		cipher.Provider
		hash.HashProvider
	}
	HandlerProvider interface {
		IdentityHandler() *Handler
	}
	Handler struct {
		r  handlerDependencies
		dx *decoderx.HTTP
	}
)

func (h *Handler) Config(ctx context.Context) *config.Config {
	return h.r.Config(ctx)
}

func NewHandler(r handlerDependencies) *Handler {
	return &Handler{
		r:  r,
		dx: decoderx.NewHTTP(),
	}
}

func (h *Handler) RegisterPublicRoutes(public *x.RouterPublic) {
	h.r.CSRFHandler().IgnoreGlobs(
		RouteCollection, RouteCollection+"/*",
		x.AdminPrefix+RouteCollection, x.AdminPrefix+RouteCollection+"/*",
	)

	// gatekeeper
	public.GET(GetOneByIdRoute, x.RedirectToAdminRoute(h.r))
	public.POST(GetOneByEmailRoute, x.RedirectToAdminRoute(h.r))
	public.POST(GetOneByEmailPhoneRoute, x.RedirectToAdminRoute(h.r))
	public.POST(CreateWithoutPasswordRoute, x.RedirectToAdminRoute(h.r))
	public.POST(CreateWithPasswordRoute, x.RedirectToAdminRoute(h.r))
	public.POST(CreateOrganizationUserRoute, x.RedirectToAdminRoute(h.r))
	public.POST(ChangePasswordRoute, x.RedirectToAdminRoute(h.r))
	public.PUT(SoftDeleteRoute, x.RedirectToAdminRoute(h.r))
	public.PUT(ActivateUserRoute, x.RedirectToAdminRoute(h.r))
	public.PUT(ConfirmPasswordRoute, x.RedirectToAdminRoute(h.r))
	public.PUT(ChangeUserInfoRoute, x.RedirectToAdminRoute(h.r))
	public.GET(GetUserWithOrganizationByIdRoute, x.RedirectToAdminRoute(h.r))
	public.GET(GetOrganizationByIdRoute, x.RedirectToAdminRoute(h.r))
	public.POST(GetUserByGroupsRoute, x.RedirectToAdminRoute(h.r))
	public.POST(CreateOrganizationRoute, x.RedirectToAdminRoute(h.r))
	public.PUT(UpdateOrganizationUserRoute, x.RedirectToAdminRoute(h.r))
	public.PUT(UpdateUserOrganizationRoute, x.RedirectToAdminRoute(h.r))
	public.PUT(UpsertZendeskUserIdRoute, x.RedirectToAdminRoute(h.r))

	public.GET(RouteCollection, x.RedirectToAdminRoute(h.r))
	public.GET(RouteItem, x.RedirectToAdminRoute(h.r))
	public.DELETE(RouteItem, x.RedirectToAdminRoute(h.r))
	public.POST(RouteCollection, x.RedirectToAdminRoute(h.r))
	public.PUT(RouteItem, x.RedirectToAdminRoute(h.r))

	public.GET(x.AdminPrefix+RouteCollection, x.RedirectToAdminRoute(h.r))
	public.GET(x.AdminPrefix+RouteItem, x.RedirectToAdminRoute(h.r))
	public.DELETE(x.AdminPrefix+RouteItem, x.RedirectToAdminRoute(h.r))
	public.POST(x.AdminPrefix+RouteCollection, x.RedirectToAdminRoute(h.r))
	public.PUT(x.AdminPrefix+RouteItem, x.RedirectToAdminRoute(h.r))


	public.GET(RouteOrganizationCollection, x.RedirectToAdminRoute(h.r))
	public.GET(RouteOrganizationCollectionItem, x.RedirectToAdminRoute(h.r))
	public.DELETE(RouteOrganizationCollectionItem, x.RedirectToAdminRoute(h.r))
	public.POST(RouteOrganizationCollection, x.RedirectToAdminRoute(h.r))
	public.PUT(RouteOrganizationCollectionItem, x.RedirectToAdminRoute(h.r))

	public.GET(x.AdminPrefix+RouteOrganizationCollection, x.RedirectToAdminRoute(h.r))
	public.GET(x.AdminPrefix+RouteOrganizationCollectionItem, x.RedirectToAdminRoute(h.r))
	public.DELETE(x.AdminPrefix+RouteOrganizationCollectionItem, x.RedirectToAdminRoute(h.r))
	public.POST(x.AdminPrefix+RouteOrganizationCollection, x.RedirectToAdminRoute(h.r))
	public.PUT(x.AdminPrefix+RouteOrganizationCollectionItem, x.RedirectToAdminRoute(h.r))
}

func (h *Handler) RegisterAdminRoutes(admin *x.RouterAdmin) {
	// gatekeeper
	admin.GET(GetOneByIdRoute, h.GetOneById)
	admin.POST(GetOneByEmailRoute, h.GetOneByEmail)
	admin.POST(GetOneByEmailPhoneRoute, h.GetOneByEmailPhone)
	admin.POST(CreateWithoutPasswordRoute, h.CreateWithoutPassword)
	admin.POST(CreateWithPasswordRoute, h.CreateWithPassword)
	admin.POST(CreateOrganizationUserRoute, h.CreateOrganizationUser)
	admin.POST(ChangePasswordRoute, h.ChangePassword)
	admin.PUT(SoftDeleteRoute, h.SoftDelete)
	admin.PUT(ActivateUserRoute, h.ActivateUser)
	admin.PUT(ConfirmPasswordRoute, h.ConfirmPassword)
	admin.PUT(ChangeUserInfoRoute, h.ChangeUserInfo)
	admin.GET(GetUserWithOrganizationByIdRoute, h.GetUserWithOrganizationById)
	admin.GET(GetOrganizationByIdRoute, h.GetOrganizationById)
	admin.POST(GetUserByGroupsRoute, h.GetUserByGroups)
	admin.POST(CreateOrganizationRoute, h.CreateOrganization)
	admin.PUT(UpdateOrganizationUserRoute, h.UpdateOrganizationUser)
	admin.PUT(UpdateUserOrganizationRoute, h.UpdateUserOrganization)
	admin.PUT(UpsertZendeskUserIdRoute, h.UpsertZendeskUserId)

	admin.GET(RouteCollection, h.list)
	admin.GET(RouteItem, h.get)
	admin.PUT(RouteItem, h.update)
	admin.DELETE(RouteItem, h.delete)

	admin.POST(RouteCollection, h.create)
	admin.POST(RouteCollectionFilter, h.listFiltered)

	admin.GET(RouteOrganizationCollection, h.listOrganization)
	admin.POST(RouteOrganizationCollection, h.createOrganization)
	admin.GET(RouteOrganizationCollectionItem, h.getOrganization)
	admin.DELETE(RouteOrganizationCollectionItem, h.deleteOrganization)
	admin.PUT(RouteOrganizationCollectionItem, h.updateOrganization)
}

// A list of identities.
// swagger:model identityList
// nolint:deadcode,unused
type identityList []Identity

// swagger:parameters adminListIdentities
// nolint:deadcode,unused
type adminListIdentities struct {
	x.PaginationParams
}

// swagger:model adminFilterIdentityBody
type AdminFilterIdentityBody struct {
	Filters []*FilterIdentityBody `json:"filters"`
}

// swagger:model filterIdentityBody
type FilterIdentityBody struct {
	Key string `json:"key"`
	Value string `json:"value"`
	Values []string `json:"values"`
	Comparison ComparisonType `json:"comparison"`
}

// swagger:route POST /admin/identities-filter v0alpha2 adminListIdentitiesFilter
//
// List Identities with filtered value
//
//	comparison = {
//    "eq": "=",
//    "gt": ">",
//    "lt": "<",
//    "gte": ">=",
//    "lte": "<=",
//    "ne": "=!",
//    "in": "in",
//	}
// Lists all identities. with filtered value
// payload will be like this:
//	{
//    "filters":[{
//        "key": "traits.email",
//        "comparison": "eq",
//        "value": "foo",
//    },{
//        "key": "traits.username",
//        "comparison": "in",
//        "values": ["bar", "baz"],
//    }]
//	}
//
// Learn how identities work in [Ory Kratos' User And Identity Model Documentation](https://www.ory.sh/docs/next/kratos/concepts/identity-user-model).
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Security:
//       oryAccessToken:
//
//     Responses:
//       200: identityList
//       500: jsonError
func (h *Handler) listFiltered(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p AdminFilterIdentityBody
	if err := jsonx.NewStrictDecoder(r.Body).Decode(&p); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	page, itemsPerPage := x.ParsePagination(r)
	is, err := h.r.IdentityPool().ListIdentitiesFiltered(r.Context(), p, page, itemsPerPage)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	total, err := h.r.IdentityPool().CountIdentities(r.Context())
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	x.PaginationHeader(w, urlx.AppendPaths(h.r.Config(r.Context()).SelfAdminURL(), RouteCollection), total, page, itemsPerPage)
	h.r.Writer().Write(w, r, is)
}

// swagger:route GET /admin/identities v0alpha2 adminListIdentities
//
// List Identities
//
// Lists all identities. Does not support search at the moment.
//
// Learn how identities work in [Ory Kratos' User And Identity Model Documentation](https://www.ory.sh/docs/next/kratos/concepts/identity-user-model).
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Security:
//       oryAccessToken:
//
//     Responses:
//       200: identityList
//       500: jsonError
func (h *Handler) list(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	page, itemsPerPage := x.ParsePagination(r)
	is, err := h.r.IdentityPool().ListIdentities(r.Context(), page, itemsPerPage)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	total, err := h.r.IdentityPool().CountIdentities(r.Context())
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	x.PaginationHeader(w, urlx.AppendPaths(h.r.Config(r.Context()).SelfAdminURL(), RouteCollection), total, page, itemsPerPage)
	h.r.Writer().Write(w, r, is)
}

// swagger:parameters adminGetIdentity
// nolint:deadcode,unused
type adminGetIdentity struct {
	// ID must be set to the ID of identity you want to get
	//
	// required: true
	// in: path
	ID string `json:"id"`

	// DeclassifyCredentials will declassify one or more identity's credentials
	//
	// Currently, only `oidc` is supported. This will return the initial OAuth 2.0 Access,
	// Refresh and (optionally) OpenID Connect ID Token.
	//
	// required: false
	// in: query
	DeclassifyCredentials []string `json:"include_credential"`
}

// swagger:route GET /admin/identities/{id} v0alpha2 adminGetIdentity
//
// Get an Identity
//
// Learn how identities work in [Ory Kratos' User And Identity Model Documentation](https://www.ory.sh/docs/next/kratos/concepts/identity-user-model).
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Security:
//       oryAccessToken:
//
//     Responses:
//       200: identity
//       404: jsonError
//       500: jsonError
func (h *Handler) get(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

// swagger:parameters adminCreateIdentity
// nolint:deadcode,unused
type adminCreateIdentity struct {
	// in: body
	Body AdminCreateIdentityBody
}

// swagger:model adminCreateIdentityBody
type AdminCreateIdentityBody struct {
	// SchemaID is the ID of the JSON Schema to be used for validating the identity's traits.
	//
	// required: true
	SchemaID string `json:"schema_id"`

	// Traits represent an identity's traits. The identity is able to create, modify, and delete traits
	// in a self-service manner. The input will always be validated against the JSON Schema defined
	// in `schema_url`.
	//
	// required: true
	Traits json.RawMessage `json:"traits"`

	// Credentials represents all credentials that can be used for authenticating this identity.
	//
	// Use this structure to import credentials for a user.
	Credentials *AdminIdentityImportCredentials `json:"credentials"`

	// VerifiableAddresses contains all the addresses that can be verified by the user.
	//
	// Use this structure to import verified addresses for an identity. Please keep in mind
	// that the address needs to be represented in the Identity Schema or this field will be overwritten
	// on the next identity update.
	VerifiableAddresses []VerifiableAddress `json:"verifiable_addresses"`

	// RecoveryAddresses contains all the addresses that can be used to recover an identity.
	//
	// Use this structure to import recovery addresses for an identity. Please keep in mind
	// that the address needs to be represented in the Identity Schema or this field will be overwritten
	// on the next identity update.
	RecoveryAddresses []RecoveryAddress `json:"recovery_addresses"`

	// Store metadata about the identity which the identity itself can see when calling for example the
	// session endpoint. Do not store sensitive information (e.g. credit score) about the identity in this field.
	MetadataPublic json.RawMessage `json:"metadata_public"`

	// Store metadata about the user which is only accessible through admin APIs such as `GET /admin/identities/<id>`.
	MetadataAdmin json.RawMessage `json:"metadata_admin,omitempty"`

	// State is the identity's state.
	//
	// required: false
	State State `json:"state"`
}

// swagger:model adminIdentityImportCredentials
type AdminIdentityImportCredentials struct {
	// Password if set will import a password credential.
	Password *AdminIdentityImportCredentialsPassword `json:"password"`

	// OIDC if set will import an OIDC credential.
	OIDC *AdminIdentityImportCredentialsOIDC `json:"oidc"`
}

// swagger:model adminCreateIdentityImportCredentialsPassword
type AdminIdentityImportCredentialsPassword struct {
	// Configuration options for the import.
	Config AdminIdentityImportCredentialsPasswordConfig `json:"config"`
}

// swagger:model adminCreateIdentityImportCredentialsPasswordConfig
type AdminIdentityImportCredentialsPasswordConfig struct {
	// The hashed password in [PHC format]( https://www.ory.sh/docs/kratos/concepts/credentials/username-email-password#hashed-password-format)
	HashedPassword string `json:"hashed_password"`

	// The password in plain text if no hash is available.
	Password string `json:"password"`
}

// swagger:model adminCreateIdentityImportCredentialsOidc
type AdminIdentityImportCredentialsOIDC struct {
	// Configuration options for the import.
	Config AdminIdentityImportCredentialsOIDCConfig `json:"config"`
}

// swagger:model adminCreateIdentityImportCredentialsOidcConfig
type AdminIdentityImportCredentialsOIDCConfig struct {
	// Configuration options for the import.
	Config AdminIdentityImportCredentialsPasswordConfig `json:"config"`
	// A list of OpenID Connect Providers
	Providers []AdminCreateIdentityImportCredentialsOidcProvider `json:"providers"`
}

// swagger:model adminCreateIdentityImportCredentialsOidcProvider
type AdminCreateIdentityImportCredentialsOidcProvider struct {
	// The subject (`sub`) of the OpenID Connect connection. Usually the `sub` field of the ID Token.
	//
	// required: true
	Subject string `json:"subject"`

	// The OpenID Connect provider to link the subject to. Usually something like `google` or `github`.
	//
	// required: true
	Provider string `json:"provider"`
}

// swagger:route POST /admin/identities v0alpha2 adminCreateIdentity
//
// Create an Identity
//
// This endpoint creates an identity. Learn how identities work in [Ory Kratos' User And Identity Model Documentation](https://www.ory.sh/docs/next/kratos/concepts/identity-user-model).
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Security:
//       oryAccessToken:
//
//     Responses:
//       201: identity
//       400: jsonError
//		 409: jsonError
//       500: jsonError
func (h *Handler) create(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var cr AdminCreateIdentityBody
	if err := jsonx.NewStrictDecoder(r.Body).Decode(&cr); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
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

	h.r.Writer().WriteCreated(w, r,
		urlx.AppendPaths(
			h.r.Config(r.Context()).SelfAdminURL(),
			"identities",
			i.ID.String(),
		).String(),
		WithCredentialsMetadataAndAdminMetadataInJSON(*i),
	)
}

// swagger:parameters adminUpdateIdentity
// nolint:deadcode,unused
type adminUpdateIdentity struct {
	// ID must be set to the ID of identity you want to update
	//
	// required: true
	// in: path
	ID string `json:"id"`

	// in: body
	Body AdminUpdateIdentityBody
}

type AdminUpdateIdentityBody struct {
	// SchemaID is the ID of the JSON Schema to be used for validating the identity's traits. If set
	// will update the Identity's SchemaID.
	//
	// required: true
	SchemaID string `json:"schema_id"`

	// Traits represent an identity's traits. The identity is able to create, modify, and delete traits
	// in a self-service manner. The input will always be validated against the JSON Schema defined
	// in `schema_id`.
	//
	// required: true
	Traits json.RawMessage `json:"traits"`

	// Store metadata about the identity which the identity itself can see when calling for example the
	// session endpoint. Do not store sensitive information (e.g. credit score) about the identity in this field.
	MetadataPublic json.RawMessage `json:"metadata_public"`

	// Store metadata about the user which is only accessible through admin APIs such as `GET /admin/identities/<id>`.
	MetadataAdmin json.RawMessage `json:"metadata_admin,omitempty"`

	// State is the identity's state.
	//
	// required: true
	State State `json:"state"`
}

// swagger:route PUT /admin/identities/{id} v0alpha2 adminUpdateIdentity
//
// Update an Identity
//
// This endpoint updates an identity. The full identity payload (except credentials) is expected. This endpoint does not support patching.
//
// Learn how identities work in [Ory Kratos' User And Identity Model Documentation](https://www.ory.sh/docs/next/kratos/concepts/identity-user-model).
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Security:
//       oryAccessToken:
//
//     Responses:
//       200: identity
//       400: jsonError
//       404: jsonError
//		 409: jsonError
//       500: jsonError
func (h *Handler) update(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var ur AdminUpdateIdentityBody
	if err := h.dx.Decode(r, &ur,
		decoderx.HTTPJSONDecoder()); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	id := x.ParseUUID(ps.ByName("id"))
	identity, err := h.r.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), id)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	if ur.SchemaID != "" {
		identity.SchemaID = ur.SchemaID
	}

	if ur.State != "" && identity.State != ur.State {
		if err := ur.State.IsValid(); err != nil {
			h.r.Writer().WriteError(w, r, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err).WithWrap(err)))
			return
		}

		stateChangedAt := sqlxx.NullTime(time.Now())

		identity.State = ur.State
		identity.StateChangedAt = &stateChangedAt
	}

	identity.Traits = []byte(ur.Traits)
	identity.MetadataPublic = []byte(ur.MetadataPublic)
	identity.MetadataAdmin = []byte(ur.MetadataAdmin)
	if err := h.r.IdentityManager().Update(
		r.Context(),
		identity,
		ManagerAllowWriteProtectedTraits,
	); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().Write(w, r, WithCredentialsMetadataAndAdminMetadataInJSON(*identity))
}

// swagger:parameters adminDeleteIdentity
// nolint:deadcode,unused
type adminDeleteIdentity struct {
	// ID is the identity's ID.
	//
	// required: true
	// in: path
	ID string `json:"id"`
}

// swagger:route DELETE /admin/identities/{id} v0alpha2 adminDeleteIdentity
//
// Delete an Identity
//
// Calling this endpoint irrecoverably and permanently deletes the identity given its ID. This action can not be undone.
// This endpoint returns 204 when the identity was deleted or when the identity was not found, in which case it is
// assumed that is has been deleted already.
//
// Learn how identities work in [Ory Kratos' User And Identity Model Documentation](https://www.ory.sh/docs/next/kratos/concepts/identity-user-model).
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Security:
//       oryAccessToken:
//
//     Responses:
//       204: emptyResponse
//       404: jsonError
//       500: jsonError
func (h *Handler) delete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if err := h.r.IdentityPool().(PrivilegedPool).DeleteIdentity(r.Context(), x.ParseUUID(ps.ByName("id"))); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}



func (h *Handler) listOrganization(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	page, itemsPerPage := x.ParsePagination(r)
	is, err := h.r.IdentityPool().ListOrganizations(r.Context(), page, itemsPerPage)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	total, err := h.r.IdentityPool().CountOrganizations(r.Context())
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	x.PaginationHeader(w, urlx.AppendPaths(h.r.Config(r.Context()).SelfAdminURL(), RouteOrganizationCollection), total, page, itemsPerPage)
	h.r.Writer().Write(w, r, is)
}

type AdminCreateOrganizationBody struct {
	// Logo is the ID of the JSON Schema to be used for validating the identity's traits.
	//
	Logo string `json:"logo"`

	// Name is the ID of the JSON Schema to be used for validating the identity's traits.
	//
	Name string `json:"name"`

	// Slug is the ID of the JSON Schema to be used for validating the identity's traits.
	//
	Slug string `json:"slug"`

	// LeadsOwner is the ID of the JSON Schema to be used for validating the identity's traits.
	//
	LeadsOwner string `json:"leads_owner"`

	// EnableQa is the ID of the JSON Schema to be used for validating the identity's traits.
	//
	EnableQa bool `json:"enable_qa"`

	// IsActive is the ID of the JSON Schema to be used for validating the identity's traits.
	//
	IsActive bool `json:"is_active"`

	// ShowCommission is the ID of the JSON Schema to be used for validating the identity's traits.
	//
	ShowCommission bool `json:"show_commission"`

	// ShowMemberStructure is the ID of the JSON Schema to be used for validating the identity's traits.
	//
	ShowMemberStructure bool `json:"show_member_structure"`

	// UseSimpleLeadStatus is the ID of the JSON Schema to be used for validating the identity's traits.
	//
	UseSimpleLeadStatus bool `json:"use_simple_lead_status"`

	// ShowLevelInDashboard is the ID of the JSON Schema to be used for validating the identity's traits.
	//
	ShowLevelInDashboard bool `json:"show_level_in_dashboard"`

	// ShowShortcutsInDashboard is the ID of the JSON Schema to be used for validating the identity's traits.
	//
	ShowShortcutsInDashboard bool `json:"show_shortcuts_in_dashboard"`

}

func (h *Handler) createOrganization(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var cr AdminCreateOrganizationBody
	if err := jsonx.NewStrictDecoder(r.Body).Decode(&cr); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	i := &Organization{
		Logo:                     cr.Logo,
		Name:                     cr.Name,
		Slug:                     cr.Slug,
		LeadsOwner:               cr.LeadsOwner,
		EnableQa:                 cr.EnableQa,
		IsActive:                 cr.IsActive,
		ShowCommission:           cr.ShowCommission,
		ShowMemberStructure:      cr.ShowMemberStructure,
		UseSimpleLeadStatus:      cr.UseSimpleLeadStatus,
		ShowLevelInDashboard:     cr.ShowLevelInDashboard,
		ShowShortcutsInDashboard: cr.ShowShortcutsInDashboard,
	}

	if err :=h.r.IdentityPool().(PrivilegedPool).CreateOrganization(r.Context(), i); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().WriteCreated(w, r,
		urlx.AppendPaths(
			h.r.Config(r.Context()).SelfAdminURL(),
			"organization",
			i.ID.String(),
		).String(),
		*i,
	)
}

func (h *Handler) getOrganization(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	i, err := h.r.PrivilegedIdentityPool().GetOrganizationDetail(r.Context(), x.ParseUUID(ps.ByName("id")))
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	h.r.Writer().Write(w, r, *i)
}

func (h *Handler) deleteOrganization(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if err := h.r.IdentityPool().(PrivilegedPool).DeleteOrganization(r.Context(), x.ParseUUID(ps.ByName("id"))); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) updateOrganization(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var cr AdminCreateOrganizationBody
	if err := jsonx.NewStrictDecoder(r.Body).Decode(&cr); err != nil {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.WithStack(err))
		return
	}

	i := &Organization{
		ID: x.ParseUUID(ps.ByName("id")),
		Logo:                     cr.Logo,
		Name:                     cr.Name,
		Slug:                     cr.Slug,
		LeadsOwner:               cr.LeadsOwner,
		EnableQa:                 cr.EnableQa,
		IsActive:                 cr.IsActive,
		ShowCommission:           cr.ShowCommission,
		ShowMemberStructure:      cr.ShowMemberStructure,
		UseSimpleLeadStatus:      cr.UseSimpleLeadStatus,
		ShowLevelInDashboard:     cr.ShowLevelInDashboard,
		ShowShortcutsInDashboard: cr.ShowShortcutsInDashboard,
	}

	if err :=h.r.IdentityPool().(PrivilegedPool).UpdateOrganization(r.Context(), i); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().WriteCreated(w, r,
		urlx.AppendPaths(
			h.r.Config(r.Context()).SelfAdminURL(),
			"organization",
			i.ID.String(),
		).String(),
		*i,
	)
}
