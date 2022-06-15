package gatekeeperschema

// CreateWithPasswordRequest ...
type CreateWithPasswordRequest struct {
	Password    string `json:"password"`
	Email       string `json:"email"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	PhoneNumber string `json:"phone_number"`
}
