package oauth

import (
	"kael/internal/config"
	"kael/internal/middleware"
	"kael/internal/sessions"

	"github.com/gin-gonic/gin"
	"time"
)

func RegisterRoutes(r *gin.Engine, handler *Handler, cfg *config.Config, sessionService *sessions.Service) {
	group := r.Group("/oauth")
	group.Use(middleware.RateLimit("rl:oauth:ip", cfg.OAuthRateLimitPerMinute, time.Minute, middleware.ExtractIP()))
	group.GET("/google/start", handler.StartGoogle)
	group.GET("/github/start", handler.StartGitHub)
	group.GET("/google/callback", handler.CallbackGoogle)
	group.GET("/github/callback", handler.CallbackGitHub)

	linkGroup := r.Group("/oauth")
	linkGroup.Use(middleware.RequireSession(cfg, sessionService))
	linkGroup.Use(
		middleware.RateLimit("rl:oauth_link:user", cfg.OAuthRateLimitPerMinute, time.Minute, middleware.ExtractUser()),
		middleware.RateLimit("rl:oauth_link:ip", cfg.OAuthRateLimitPerMinute, time.Minute, middleware.ExtractIP()),
	)
	linkGroup.GET("/google/link", handler.LinkGoogle)
	linkGroup.GET("/github/link", handler.LinkGitHub)
}
