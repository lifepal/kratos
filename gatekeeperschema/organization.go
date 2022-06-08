package gatekeeperschema

// OrganizationGatekeeper Gatekeeper struct
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

// CreateOrganizationRequest ...
type CreateOrganizationRequest struct {
	Name string `json:"name"`
}
