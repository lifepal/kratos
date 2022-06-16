package gatekeeperschema

// ChangePasswordRequest ...
type ChangePasswordRequest struct {
	Id          string `json:"id"`
	NewPassword string `json:"new_password"`
}
