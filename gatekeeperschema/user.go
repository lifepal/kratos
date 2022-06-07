package gatekeeperschema

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
	SocialId       int  `json:"social_id"`
	SocialType     int  `json:"social_type"`
	Source         int  `json:"source"`
	HumanId        int  `json:"human_id"`
	IsVerified     bool   `json:"is_verified"`
	PhoneNumber    string `json:"phone_number"`
	UpdatedAt      string `json:"updated_at"`
	OrganizationId string `json:"organization_id"`
	ZendeskUserid  string `json:"zendesk_userid"`
	GroupId        string `json:"group_id"`
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
