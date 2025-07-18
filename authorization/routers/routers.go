package routers

import (
	token "blogV2_REST-API/authorization/Token"
	"blogV2_REST-API/authorization/coockie"
	"blogV2_REST-API/authorization/storage/psql"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type UserRegister struct {
	ID       uint
	UserName string `json:"username" validate:"required,min=7,max=21"`
	Password string `json:"password" validate:"password"`
}

func POSTlogin(ctx *gin.Context) {
	var userData UserRegister
	ctx.ShouldBindJSON(&userData)
	if errAdddb := psql.AddUser(psql.DB, userData.UserName, userData.Password); errAdddb != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"уведомление": fmt.Sprintf("ошибка при регистрации: %w", errAdddb),
		})
		return
	} else {
		ctx.JSON(http.StatusOK, gin.H{
			"уведомление": "регистрация успешно завершена",
		})
	}

}

func POSTSignIn(ctx *gin.Context) {
	userCookie, errGetCookie := coockie.GetCookie(ctx)

	if errGetCookie == nil {
		ctx.JSON(http.StatusNotFound, gin.H{
			"уведомление": "сессия аткивна",
		})
		return
	}
	if errors.Is(errGetCookie, coockie.ErrCookieMissing) {
		var user UserRegister
		ctx.ShouldBindJSON(&user)
		signIn, errSign := psql.SignIn(psql.DB, user.UserName, user.Password, ctx)
		if signIn {
			ctx.JSON(http.StatusOK, gin.H{
				"уведомление": "вход выполнен",
			})
		} else {
			ctx.JSON(http.StatusNotFound, gin.H{
				"уведомление": fmt.Sprintf("вход не выполнен: %w", errSign),
			})
		}
	} else if errGetCookie != nil {
		ctx.JSON(http.StatusOK, gin.H{
			"уведомление": fmt.Sprintf("вход не выполнен: %w", errGetCookie),
		})
	} else if errors.Is(errGetCookie, errors.New("срок действия сессии истёк, войдите в аккаунт заново")) {
		jwtdata, errDiss := token.DeserializationJWT(userCookie.JWTtoken)
		if errDiss != nil {
			ctx.JSON(http.StatusOK, gin.H{
				"уведомление": fmt.Sprintf("вход не выполнен: %w", errDiss),
			})
		}
		var user UserRegister
		ctx.ShouldBindJSON(&user)

		if jwtdata["pass"] == user.Password && jwtdata["sub"] == user.UserName {
			t, errToken := token.CreateJWT(user.UserName, user.Password, user.ID)
			if errToken != nil {
				ctx.JSON(http.StatusOK, gin.H{
					"уведомление": fmt.Sprintf("вход не выполнен: %w", errToken),
				})
			}
			coockie.SetCookie(ctx, user.UserName, t, user.ID)
			ctx.JSON(http.StatusOK, gin.H{
				"уведомление": "входы выполнен",
			})
		} else {
			ctx.JSON(http.StatusOK, gin.H{
				"уведомление": "неверное имя пользователя или пароль",
			})
		}
	}
}
