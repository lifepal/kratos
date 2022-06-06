package identity

import (
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/kratos/x"
	"github.com/pkg/errors"
	"net/http"
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
