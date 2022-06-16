package gatekeeperschema

// OTPForgotPasswordRequest ...
type OTPForgotPasswordRequest struct {
	FirebaseUid string `json:"firebase_uid"`
	NewPassword string `json:"new_password"`
}
