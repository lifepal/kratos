package gatekeeperschema

// UpdateUserOrganizationRequest ...
type UpdateUserOrganizationRequest struct {
	UserIds        []string `json:"user_ids"`
	OrganizationId string   `json:"organization_id"`
}
