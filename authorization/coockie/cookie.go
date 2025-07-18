package coockie

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
)

type UserCoockie struct {
	UserID   uint
	UserName string
	JWTtoken string
	Exp      int64
}

var ErrCookieMissing = errors.New("cookie отсутствует")

func SetCookie(ctx *gin.Context, userName, jwtToken string, userId uint) error {
	user := UserCoockie{
		UserID:   userId,
		UserName: userName,
		JWTtoken: jwtToken,
		Exp:      time.Now().Add(24 * 30 * time.Hour).Unix(),
	}
	data, err := json.Marshal(&user)
	if err != nil {
		return errors.New(fmt.Sprintf("ошибка при сериализации cookie: %w", err))
	}
	encoded := base64.StdEncoding.EncodeToString(data)

	ctx.SetCookie(
		"authorization",
		encoded,
		86400*30,
		"/",
		"localhost",
		true,
		true)
	return nil
}

func GetCookie(ctx *gin.Context) (*UserCoockie, error) {
	encoded, err := ctx.Cookie("authorization")
	if err != nil {
		return nil, ErrCookieMissing
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("не удалось декодировать cookie: %w", err)
	}

	var user UserCoockie
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("ошибка десериализации cookie: %w", err)
	}

	if int64(user.Exp) < time.Now().Unix() {

		return nil, errors.New("срок действия сессии истёк, войдите в аккаунт заново")
	}

	return &user, nil
}
