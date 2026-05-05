package oidc

import "github.com/gin-gonic/gin"

func RegisterRoutes(r *gin.Engine, handler *Handler) {
	r.GET("/.well-known/openid-configuration", handler.Discovery)
	r.GET("/.well-known/jwks.json", handler.JWKS)

	group := r.Group("/oidc")
	group.GET("/authorize", handler.Authorize)
	group.POST("/token", handler.Token)
	group.GET("/userinfo", handler.UserInfo)
	group.POST("/userinfo", handler.UserInfo)
	group.POST("/revoke", handler.Revoke)
	group.POST("/logout", handler.Logout)
	group.POST("/introspect", handler.Introspect)
}
