package login

import "os"

func getJwtSecret() string {
	var jwtSecretString = os.Getenv("JWT_SECRET_SALT")
	if len(jwtSecretString) == 0 {
		return "lifepal"
	}
	return jwtSecretString
}

func getIssuer() string {
	var jwtissuer = os.Getenv("JWT_ISSUER")
	if len(jwtissuer) == 0 {
		return "lifepal"
	}
	return jwtissuer
}
