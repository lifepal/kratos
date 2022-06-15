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
		return "/Volumes/Dataku/Development/Go/go-firebase/django-auth-345906-firebase-adminsdk-jgqh7-85ea2d42c9.json"
	}
	return firebaseCred
}
