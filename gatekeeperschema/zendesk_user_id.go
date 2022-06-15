package gatekeeperschema

// UpsertZendeskUserIdRequest ...
type UpsertZendeskUserIdRequest struct {
	ZendeskUserid string `json:"zendesk_userid"`
	UserId        string `json:"user_id"`
}
