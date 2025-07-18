package token

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var JwtSecretKey = []byte("")

func CreateJWT(userName, password string, userID uint) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  userName,
		"exp":  time.Now().Add(time.Hour * 24 * 30).Unix(),
		"id":   float64(userID),
		"pass": password,
	})
	t, err := token.SignedString(JwtSecretKey)
	if err != nil {
		return "", err
	}
	return t, nil
}

func DeserializationJWT(token string) (jwt.MapClaims, error) {
	tk, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(JwtSecretKey), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, fmt.Errorf("токен недействителен: %w", err)
	}
	if claims, ok := tk.Claims.(jwt.MapClaims); ok {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			return nil, fmt.Errorf("срок действия токена истёк")
		} else {
			return claims, nil
		}
	} else {
		return nil, fmt.Errorf("что-то пошло не так")
	}
}
