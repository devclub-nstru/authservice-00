package auth

import (
	"net/http"

	"kael/internal/config"
	"kael/internal/ctxkeys"
	"kael/internal/httpx"
	"kael/internal/mfa"
	"kael/internal/sessions"
	"kael/internal/tokens"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Handler struct {
	service *Service
	cfg     *config.Config
}

func NewHandler(service *Service, cfg *config.Config) *Handler {
	return &Handler{service: service, cfg: cfg}
}

// Signup registers a new user
// @Summary      Register a new user
// @Description  Create a new user account with email and password
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body SignupRequest true "Signup request payload"
// @Success      201  {object}  httpx.Response{data=AuthResponse}
// @Failure      400  {object}  httpx.Response{error=httpx.ErrorResponse}
// @Failure      409  {object}  httpx.Response{error=httpx.ErrorResponse}
// @Router       /auth/signup [post]
func (h *Handler) Signup(c *gin.Context) {
	var req SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	user, err := h.service.Signup(c.Request.Context(), req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	httpx.Respond(c, http.StatusCreated, AuthResponse{User: mapUser(user)})
}

// Login authenticates a user
// @Summary      Login user
// @Description  Authenticate user with email and password and return session token or MFA challenge
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        X-Device-ID header string true "Device Identifier"
// @Param        request body LoginRequest true "Login request payload"
// @Success      200  {object}  httpx.Response{data=AuthResponse}
// @Failure      401  {object}  httpx.Response{error=httpx.ErrorResponse}
// @Router       /auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	deviceID := c.GetHeader("X-Device-ID")
	if deviceID == "" {
		httpx.RespondError(c, http.StatusBadRequest, "device_id_missing", "X-Device-ID header required", nil)
		return
	}

	result, err := h.service.Login(c.Request.Context(), req, deviceID, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		h.handleError(c, err)
		return
	}

	if result.SessionToken != "" {
		SetSessionCookie(c, h.cfg, result.SessionToken, result.SessionExpiry)
	}

	httpx.Respond(c, http.StatusOK, AuthResponse{
		User:        mapUser(result.User),
		MFARequired: result.MFARequired,
		MFAToken:    result.MFAToken,
		MFAMethods:  result.MFAMethods,
	})
}

// VerifyMFA verifies an MFA factor
// @Summary      Verify MFA
// @Description  Complete login by verifying an MFA factor (OTP/TOTP)
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body MFAVerifyRequest true "MFA verification payload"
// @Success      200  {object}  httpx.Response{data=AuthResponse}
// @Failure      400  {object}  httpx.Response{error=httpx.ErrorResponse}
// @Router       /auth/mfa/verify [post]
func (h *Handler) VerifyMFA(c *gin.Context) {
	var req MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	result, err := h.service.VerifyMFA(c.Request.Context(), req.ChallengeToken, req.Factor, req.Code)
	if err != nil {
		h.handleError(c, err)
		return
	}

	if result.SessionToken != "" {
		SetSessionCookie(c, h.cfg, result.SessionToken, result.SessionExpiry)
	}

	httpx.Respond(c, http.StatusOK, AuthResponse{
		User:        mapUser(result.User),
		MFARequired: result.MFARequired,
		MFAToken:    result.MFAToken,
		MFAMethods:  result.MFAMethods,
	})
}

func (h *Handler) TriggerMFA(c *gin.Context) {
	var req MFATriggerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	if err := h.service.TriggerMFA(c.Request.Context(), req.ChallengeToken, req.Factor); err != nil {
		h.handleError(c, err)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{"triggered": true})
}


// Refresh rotates the session token
// @Summary      Refresh session
// @Description  Rotate the session token using a valid session cookie
// @Tags         auth
// @Produce      json
// @Param        X-Device-ID header string true "Device Identifier"
// @Success      200  {object}  httpx.Response{data=AuthResponse}
// @Failure      401  {object}  httpx.Response{error=httpx.ErrorResponse}
// @Router       /auth/refresh [post]
func (h *Handler) Refresh(c *gin.Context) {
	deviceID := c.GetHeader("X-Device-ID")
	if deviceID == "" {
		httpx.RespondError(c, http.StatusBadRequest, "device_id_missing", "X-Device-ID header required", nil)
		return
	}

	token, err := c.Cookie(h.cfg.SessionCookieName)
	if err != nil || token == "" {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "session cookie required", nil)
		return
	}

	result, err := h.service.Refresh(c.Request.Context(), token, deviceID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	SetSessionCookie(c, h.cfg, result.SessionToken, result.SessionExpiry)
	httpx.Respond(c, http.StatusOK, AuthResponse{User: mapUser(result.User)})
}

// Logout terminates the session
// @Summary      Logout
// @Description  Revoke the current session token
// @Tags         auth
// @Produce      json
// @Success      200  {object}  httpx.Response{data=map[string]bool}
// @Router       /auth/logout [post]
func (h *Handler) Logout(c *gin.Context) {
	token, err := c.Cookie(h.cfg.SessionCookieName)
	if err == nil && token != "" {
		_ = h.service.Logout(c.Request.Context(), token)
	}
	ClearSessionCookie(c, h.cfg)
	httpx.Respond(c, http.StatusOK, gin.H{"logged_out": true})
}

// PasswordForgot requests a password reset link
// @Summary      Forgot password
// @Description  Send a password reset email to the user
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body PasswordForgotRequest true "Forgot password payload"
// @Success      200  {object}  httpx.Response{data=map[string]bool}
// @Router       /auth/password/forgot [post]
func (h *Handler) PasswordForgot(c *gin.Context) {
	var req PasswordForgotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	_ = h.service.SendPasswordReset(c.Request.Context(), req.Email)
	httpx.Respond(c, http.StatusOK, gin.H{"sent": true})
}

// PasswordReset resets the password
// @Summary      Reset password
// @Description  Reset password using the token from the reset email
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body PasswordResetRequest true "Reset password payload"
// @Success      200  {object}  httpx.Response{data=map[string]bool}
// @Failure      400  {object}  httpx.Response{error=httpx.ErrorResponse}
// @Router       /auth/password/reset [post]
func (h *Handler) PasswordReset(c *gin.Context) {
	var req PasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	if err := h.service.ResetPassword(c.Request.Context(), req.Token, req.NewPassword); err != nil {
		h.handleError(c, err)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{"reset": true})
}

// PasswordChange changes the user password
// @Summary      Change password
// @Description  Change password for an authenticated user
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body PasswordChangeRequest true "Change password payload"
// @Success      200  {object}  httpx.Response{data=map[string]bool}
// @Failure      401  {object}  httpx.Response{error=httpx.ErrorResponse}
// @Router       /auth/password/change [post]
func (h *Handler) PasswordChange(c *gin.Context) {
	var req PasswordChangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	userID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	if err := h.service.ChangePassword(c.Request.Context(), userID, req.CurrentPassword, req.NewPassword); err != nil {
		h.handleError(c, err)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{"updated": true})
}

// PasswordSet sets the password for the first time
// @Summary      Set password
// @Description  Set password for a user who doesn't have one (e.g. OAuth only)
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body PasswordSetRequest true "Set password payload"
// @Success      200  {object}  httpx.Response{data=map[string]bool}
// @Failure      401  {object}  httpx.Response{error=httpx.ErrorResponse}
// @Router       /auth/password/set [post]
func (h *Handler) PasswordSet(c *gin.Context) {
	var req PasswordSetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	userID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	if err := h.service.SetPassword(c.Request.Context(), userID, req.Password); err != nil {
		h.handleError(c, err)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{"updated": true})
}

// EmailVerify verifies user email
// @Summary      Verify email
// @Description  Verify email using the token from the verification email
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body EmailVerifyRequest true "Email verify payload"
// @Success      200  {object}  httpx.Response{data=map[string]bool}
// @Router       /auth/email/verify [post]
func (h *Handler) EmailVerify(c *gin.Context) {
	var req EmailVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	if err := h.service.VerifyEmail(c.Request.Context(), req.Token); err != nil {
		h.handleError(c, err)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{"verified": true})
}

// EmailResend resends the verification email
// @Summary      Resend verification email
// @Description  Resend the email verification link to the user
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body EmailResendRequest true "Email resend payload"
// @Success      200  {object}  httpx.Response{data=map[string]bool}
// @Router       /auth/email/resend [post]
func (h *Handler) EmailResend(c *gin.Context) {
	var req EmailResendRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	_ = h.service.ResendVerification(c.Request.Context(), req.Email)
	httpx.Respond(c, http.StatusOK, gin.H{"sent": true})
}

// EmailUpdate updates the user email
// @Summary      Update email
// @Description  Update user email address and send new verification link
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body EmailUpdateRequest true "Email update payload"
// @Success      200  {object}  httpx.Response{data=map[string]bool}
// @Failure      401  {object}  httpx.Response{error=httpx.ErrorResponse}
// @Router       /auth/email/update [post]
func (h *Handler) EmailUpdate(c *gin.Context) {
	var req EmailUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	userID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	if err := h.service.UpdateEmail(c.Request.Context(), userID, req.Email); err != nil {
		h.handleError(c, err)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{"updated": true})
}

// Me returns the current user profile
// @Summary      Get current user
// @Description  Get the profile of the currently authenticated user
// @Tags         auth
// @Produce      json
// @Success      200  {object}  httpx.Response{data=UserResponse}
// @Failure      401  {object}  httpx.Response{error=httpx.ErrorResponse}
// @Router       /auth/me [get]
func (h *Handler) Me(c *gin.Context) {
	userID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	profile, err := h.service.GetProfile(c.Request.Context(), userID)
	if err != nil {
		httpx.RespondError(c, http.StatusNotFound, "user_not_found", "user not found", nil)
		return
	}

	httpx.Respond(c, http.StatusOK, mapProfile(profile))
}

func getUserID(c *gin.Context) (uuid.UUID, error) {
	val, ok := c.Get(ctxkeys.UserIDKey)
	if !ok {
		return uuid.Nil, http.ErrNoCookie
	}
	return uuid.Parse(val.(string))
}

func (h *Handler) handleError(c *gin.Context, err error) {
	switch err {
	case ErrUserExists:
		httpx.RespondError(c, http.StatusConflict, "user_exists", err.Error(), nil)
	case ErrInvalidCredentials:
		httpx.RespondError(c, http.StatusUnauthorized, "invalid_credentials", err.Error(), nil)
	case ErrPasswordDisabled:
		httpx.RespondError(c, http.StatusForbidden, "password_disabled", err.Error(), nil)
	case ErrPasswordAlreadySet:
		httpx.RespondError(c, http.StatusConflict, "password_already_set", err.Error(), nil)
	case ErrEmailNotVerified:
		httpx.RespondError(c, http.StatusForbidden, "email_not_verified", err.Error(), nil)
	case ErrMFANotConfigured:
		httpx.RespondError(c, http.StatusBadRequest, "mfa_not_configured", err.Error(), nil)
	case mfa.ErrInvalidCode:
		httpx.RespondError(c, http.StatusBadRequest, "mfa_invalid_code", err.Error(), nil)
	case tokens.ErrTokenInvalid:
		httpx.RespondError(c, http.StatusBadRequest, "token_invalid", err.Error(), nil)
	case sessions.ErrSessionExpired:
		httpx.RespondError(c, http.StatusUnauthorized, "session_expired", err.Error(), nil)
	case sessions.ErrSessionInvalid:
		httpx.RespondError(c, http.StatusUnauthorized, "session_invalid", err.Error(), nil)
	default:
		httpx.RespondError(c, http.StatusBadRequest, "auth_error", err.Error(), nil)
	}
}
