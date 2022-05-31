package login

import "os"

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

func getFirebaseCredential() string {
	var firebaseCred = os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if len(firebaseCred) == 0{
		// example: path/to/serviceAccountKey.json
		return "service-account-file.json"
	}
	return firebaseCred
}
