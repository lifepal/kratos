package session

import (
	"net/http"
	"os"
	"strings"
)

func GetJwtSecret() string {
	var jwtSecretString = os.Getenv("JWT_SECRET_SALT")
	if len(jwtSecretString) == 0 {
		return "lifepal"
	}
	return jwtSecretString
}

func GetIssuer() string {
	var jwtissuer = os.Getenv("JWT_ISSUER")
	if len(jwtissuer) == 0 {
		return "lifepal"
	}
	return jwtissuer
}

func bearerTokenFromRequest(r *http.Request) (string, bool) {
	parts := strings.Split(r.Header.Get("Authorization"), " ")

	if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
		return parts[1], true
	}

	return "", false
}

func getJwtSecret() string {
	var jwtSecretString = os.Getenv("JWT_SECRET_SALT")
	if len(jwtSecretString) == 0 {
		return "lifepal"
	}
	return jwtSecretString
}
