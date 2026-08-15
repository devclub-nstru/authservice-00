package oidc

import (
	"github.com/gin-gonic/gin"
	"kael/internal/config"
	"kael/internal/middleware"
	"time"
)

func RegisterRoutes(r *gin.Engine, handler *Handler, cfg *config.Config) {
	r.GET("/.well-known/openid-configuration", handler.Discovery)
	r.GET("/.well-known/jwks.json", handler.JWKS)

	group := r.Group("/oidc")
	group.Use(
		middleware.RateLimit("rl:oidc:client", cfg.OIDCRateLimitPerMinute, time.Minute, middleware.ExtractClientID()),
		middleware.RateLimit("rl:oidc:ip", cfg.OIDCRateLimitPerMinute, time.Minute, middleware.ExtractIP()),
	)
	
	group.GET("/authorize", handler.Authorize)
	group.GET("/consent/details", handler.GetConsentDetails)
	group.POST("/consent", handler.SubmitConsent)
	group.POST("/token", handler.Token)
	group.GET("/userinfo", handler.UserInfo)
	group.POST("/userinfo", handler.UserInfo)
	group.POST("/revoke", handler.Revoke)
	group.POST("/logout", handler.Logout)
	group.GET("/logout", handler.OIDCLogout)
	group.POST("/introspect", handler.Introspect)
}
