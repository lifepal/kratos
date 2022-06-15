package gatekeeperschema

// CreateWithoutPasswordRequest ...
type CreateWithoutPasswordRequest struct {
	Email       string `json:"email"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	PhoneNumber string `json:"phone_number"`
}
