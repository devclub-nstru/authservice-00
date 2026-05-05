package auth

import (
	"time"

	"kael/internal/config"
	"kael/internal/middleware"
	"kael/internal/sessions"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func RegisterRoutes(r *gin.Engine, handler *Handler, cfg *config.Config, sessionsService *sessions.Service, redisClient *redis.Client) {
	group := r.Group("/auth")
	group.POST("/signup", middleware.RateLimit(redisClient, "rl:signup", cfg.AuthRateLimitPerMinute, time.Minute), handler.Signup)
	group.POST("/login", middleware.RateLimit(redisClient, "rl:login", cfg.LoginRateLimitPerMinute, time.Minute), handler.Login)
	group.POST("/mfa/verify", middleware.RateLimit(redisClient, "rl:mfa", cfg.MfaRateLimitPerMinute, time.Minute), handler.VerifyMFA)
	group.POST("/mfa/trigger", middleware.RateLimit(redisClient, "rl:mfa", cfg.MfaRateLimitPerMinute, time.Minute), handler.TriggerMFA)
	group.POST("/refresh", handler.Refresh)
	group.POST("/logout", middleware.RequireSession(cfg, sessionsService), handler.Logout)
	group.POST("/password/forgot", handler.PasswordForgot)
	group.POST("/password/reset", handler.PasswordReset)
	group.POST("/email/verify", handler.EmailVerify)
	group.POST("/email/resend", handler.EmailResend)

	authed := r.Group("/auth")
	authed.Use(middleware.RequireSession(cfg, sessionsService))
	authed.GET("/me", handler.Me)
	authed.DELETE("/me/clients/:id", handler.DisconnectClient)
	authed.POST("/password/change", handler.PasswordChange)
	authed.POST("/password/set", handler.PasswordSet)
	authed.POST("/email/update", handler.EmailUpdate)
}
