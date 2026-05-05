package middleware

import (
	"net/http"

	"kael/internal/config"
	"kael/internal/ctxkeys"
	"kael/internal/httpx"
	"kael/internal/sessions"

	"github.com/gin-gonic/gin"
)

func RequireSession(cfg *config.Config, service *sessions.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		deviceID := c.GetHeader("X-Device-ID")
		if deviceID == "" {
			httpx.RespondError(c, http.StatusBadRequest, "device_id_missing", "X-Device-ID header required", nil)
			c.Abort()
			return
		}

		token, err := c.Cookie(cfg.SessionCookieName)
		if err != nil || token == "" {
			httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "session cookie required", nil)
			c.Abort()
			return
		}

		session, err := service.Validate(c.Request.Context(), token, deviceID)
		if err != nil {
			switch err {
			case sessions.ErrSessionExpired:
				httpx.RespondError(c, http.StatusUnauthorized, "session_expired", "session expired", nil)
			case sessions.ErrMFAPending:
				httpx.RespondError(c, http.StatusForbidden, "mfa_pending", "mfa verification required", nil)
			case sessions.ErrEmailNotVerified:
				httpx.RespondError(c, http.StatusForbidden, "email_not_verified", "email verification required", nil)
			default:
				httpx.RespondError(c, http.StatusUnauthorized, "session_invalid", "invalid session", nil)
			}
			c.Abort()
			return
		}

		c.Set(ctxkeys.UserIDKey, session.UserID.String())
		c.Set(ctxkeys.SessionIDKey, session.ID.String())
		c.Next()
	}
}
