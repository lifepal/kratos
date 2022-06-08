package gatekeeperschema

// CreateOrganizationUserRequest ...
type CreateOrganizationUserRequest struct {
	Email          string `json:"email"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	Password       string `json:"password"`
	PhoneNumber    string `json:"phone_number"`
	OrganizationId string `json:"organization_id"`
}
