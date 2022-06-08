package gatekeeperschema

// ChangeUserInfoRequest ...
type ChangeUserInfoRequest struct {
	Id          string `json:"id"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phone_number"`
	FullName    string `json:"full_name"`
}
