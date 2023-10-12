package helper

import (
	"time"

	models "github.com/blackhat/model"

	"github.com/dgrijalva/jwt-go"
)

func DateTime() string {
	currentTime := time.Now()
	result := currentTime.Format("2006-01-02 15:04:05") //yyyy-mm-dd HH:mm:ss
	return result
}

func JwtGenerator(username, firstname, lastname, key string) string {
	//Generate Token JWT for auth
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":  username,
		"firstname": firstname,
		"lastname":  lastname,
	})

	tokenString, err := token.SignedString([]byte(key))
	if err != nil {
		return err.Error()
	}
	return tokenString
}

func ErrorLog(rc int, detail, ext_ref string) models.Error {
	var error models.Error
	error.ResponseCode = rc
	error.Message = "Failed"
	error.Detail = detail
	error.ExternalReference = ext_ref

	return error
}
