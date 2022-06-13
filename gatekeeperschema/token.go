package gatekeeperschema

import "github.com/dgrijalva/jwt-go"

type Token struct {
	// user profile
	Email string `json:"email"`
	Phone string `json:"phone"`
	Source int `json:"source"`
	HumanId int `json:"human_id"`
	IsStaff bool `json:"is_staff"`
	Username string `json:"username"`
	IsActive bool `json:"is_active"`
	LastName string `json:"last_name"`
	SocialId int `json:"social_id"`
	FirstName string `json:"first_name"`
	LastLogin string `json:"last_login"`
	UpdatedAt string `json:"updated_at"`
	DateJoined string `json:"date_joined"`
	IsVerified bool `json:"is_verified"`
	SocialType int `json:"social_type"`
	IsSuperUser bool `json:"is_super_user"`
	PhoneNumber string `json:"phone_number"`
	OrganizationId string `json:"organization_id"`
	// end user profile

	UserId string `json:"user_id"`
	TokenType string `json:"token_type"`
	SessionId string `json:"session_id"`
	SessionToken string `json:"session_token"`
	jwt.StandardClaims
}
