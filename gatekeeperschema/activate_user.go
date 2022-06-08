package gatekeeperschema

// ActivateUserRequest ...
type ActivateUserRequest struct {
	Id          string `json:"id"`
	NewPassword string `json:"new_password"`
}
