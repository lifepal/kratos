package gatekeeperschema

// ConfirmPasswordRequest ...
type ConfirmPasswordRequest struct {
	Id              string `json:"id"`
	OldPassword     string `json:"old_password"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}
