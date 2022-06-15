package gatekeeperschema

// UpdateOrganizationUserRequest ...
type UpdateOrganizationUserRequest struct {
	Email          string `json:"email"`
	PhoneNumber    string `json:"phone_number"`
	OrganizationId string `json:"organization_id"`
}
