package auth

import (
	"kael/internal/config"
	"kael/internal/middleware"
	"kael/internal/sessions"

	"github.com/gin-gonic/gin"
	"time"
)

func RegisterRoutes(r *gin.Engine, handler *Handler, cfg *config.Config, sessionsService *sessions.Service) {
	group := r.Group("/auth")
	
	// Signup: Protect by Email & IP
	group.POST("/signup", 
		middleware.RateLimit("rl:signup:email", cfg.AuthRateLimitPerMinute, time.Minute, middleware.ExtractEmail()),
		middleware.RateLimit("rl:signup:ip", cfg.AuthRateLimitPerMinute, time.Minute, middleware.ExtractIP()),
		handler.Signup)
		
	// Login: Protect by Email & IP
	group.POST("/login", 
		middleware.RateLimit("rl:login:email", cfg.LoginRateLimitPerMinute, time.Minute, middleware.ExtractEmail()),
		middleware.RateLimit("rl:login:ip", cfg.LoginRateLimitPerMinute, time.Minute, middleware.ExtractIP()),
		handler.Login)
		
	// MFA Verify/Trigger: Protect by User/Email & IP
	group.POST("/mfa/verify", 
		middleware.RateLimit("rl:mfa:email", cfg.MfaRateLimitPerMinute, time.Minute, middleware.ExtractEmail(), middleware.ExtractUser()),
		middleware.RateLimit("rl:mfa:ip", cfg.MfaRateLimitPerMinute, time.Minute, middleware.ExtractIP()),
		handler.VerifyMFA)
	group.POST("/mfa/trigger", 
		middleware.RateLimit("rl:mfa:email", cfg.MfaRateLimitPerMinute, time.Minute, middleware.ExtractEmail(), middleware.ExtractUser()),
		middleware.RateLimit("rl:mfa:ip", cfg.MfaRateLimitPerMinute, time.Minute, middleware.ExtractIP()),
		handler.TriggerMFA)
		
	// Refresh: Protect by IP
	group.POST("/refresh", 
		middleware.RateLimit("rl:refresh:ip", cfg.AuthRateLimitPerMinute, time.Minute, middleware.ExtractIP()),
		handler.Refresh)
		
	group.POST("/logout", middleware.RequireSession(cfg, sessionsService), handler.Logout)
	
	// Password Forgot/Reset: Protect by Email & IP
	group.POST("/password/forgot", 
		middleware.RateLimit("rl:pwforgot:email", cfg.PasswordResetRateLimitPerMinute, time.Minute, middleware.ExtractEmail()),
		middleware.RateLimit("rl:pwforgot:ip", cfg.PasswordResetRateLimitPerMinute, time.Minute, middleware.ExtractIP()),
		handler.PasswordForgot)
	group.POST("/password/reset", 
		middleware.RateLimit("rl:pwreset:email", cfg.PasswordResetRateLimitPerMinute, time.Minute, middleware.ExtractEmail()),
		middleware.RateLimit("rl:pwreset:ip", cfg.PasswordResetRateLimitPerMinute, time.Minute, middleware.ExtractIP()),
		handler.PasswordReset)
		
	// Email Verify/Resend: Protect by Email & IP
	group.POST("/email/verify", 
		middleware.RateLimit("rl:emailverify:email", cfg.AuthRateLimitPerMinute, time.Minute, middleware.ExtractEmail()),
		middleware.RateLimit("rl:emailverify:ip", cfg.AuthRateLimitPerMinute, time.Minute, middleware.ExtractIP()),
		handler.EmailVerify)
	group.POST("/email/resend", 
		middleware.RateLimit("rl:emailresend:email", cfg.PasswordResetRateLimitPerMinute, time.Minute, middleware.ExtractEmail()),
		middleware.RateLimit("rl:emailresend:ip", cfg.PasswordResetRateLimitPerMinute, time.Minute, middleware.ExtractIP()),
		handler.EmailResend)

	authed := r.Group("/auth")
	authed.Use(middleware.RequireSession(cfg, sessionsService))
	// Authenticated routes, protect by User & IP
	authed.Use(
		middleware.RateLimit("rl:auth:user", cfg.AuthRateLimitPerMinute, time.Minute, middleware.ExtractUser()),
		middleware.RateLimit("rl:auth:ip", cfg.AuthRateLimitPerMinute, time.Minute, middleware.ExtractIP()),
	)
	authed.GET("/me", handler.Me)
	authed.DELETE("/me/clients/:id", handler.DisconnectClient)
	authed.POST("/password/change", handler.PasswordChange)
	authed.POST("/password/set", handler.PasswordSet)
	authed.POST("/email/update", handler.EmailUpdate)
}
