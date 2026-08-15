package mfa

import (
	"kael/internal/config"
	"kael/internal/middleware"
	"kael/internal/sessions"

	"github.com/gin-gonic/gin"
	"time"
)

func RegisterRoutes(r *gin.Engine, handler *Handler, cfg *config.Config, sessionsService *sessions.Service) {
	group := r.Group("/mfa")
	group.Use(middleware.RequireSession(cfg, sessionsService))
	group.Use(
		middleware.RateLimit("rl:mfa:user", cfg.MfaRateLimitPerMinute, time.Minute, middleware.ExtractUser()),
		middleware.RateLimit("rl:mfa:ip", cfg.MfaRateLimitPerMinute, time.Minute, middleware.ExtractIP()),
	)
	group.POST("/totp/enable", handler.EnableTOTP)
	group.POST("/totp/verify", handler.VerifyTOTP)
	group.POST("/totp/disable", handler.DisableTOTP)
	group.POST("/email/enable", handler.EnableEmail)
	group.POST("/email/verify", handler.VerifyEmail)
	group.POST("/email/disable", handler.DisableEmail)
}
