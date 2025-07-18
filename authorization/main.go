package main

import (
	"blogV2_REST-API/authorization/routers"

	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	router.POST("/login", routers.POSTlogin)
	router.POST("/SignIn", routers.POSTSignIn)

	router.Run()
}
