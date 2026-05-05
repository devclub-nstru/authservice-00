package mfa

import (
	"encoding/json"
	"net/http"

	"kael/internal/config"
	"kael/internal/ctxkeys"
	"kael/internal/email"
	"kael/internal/httpx"
	"kael/internal/ques"
	"kael/internal/security"
	"kael/internal/users"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
)

type Handler struct {
	repo    *Repository
	users   *users.Repository
	cfg     *config.Config
	asynq   *asynq.Client
	totpKey []byte
}

type TOTPVerifyRequest struct {
	Code string `json:"code" binding:"required"`
}

type EmailVerifyRequest struct {
	Code string `json:"code" binding:"required"`
}

func NewHandler(repo *Repository, usersRepo *users.Repository, cfg *config.Config, asynqClient *asynq.Client) (*Handler, error) {
	var key []byte
	var err error
	if cfg.TOTPEncryptionKey != "" {
		key, err = security.DecodeBase64Key(cfg.TOTPEncryptionKey)
		if err != nil {
			return nil, err
		}
	}
	return &Handler{repo: repo, users: usersRepo, cfg: cfg, asynq: asynqClient, totpKey: key}, nil
}

// EnableTOTP generates a new TOTP secret
// @Summary      Enable TOTP
// @Description  Generate a new TOTP secret and return the secret and otpauth URL for QR code
// @Tags         mfa
// @Produce      json
// @Success      200  {object}  httpx.Response{data=map[string]string}
// @Failure      401  {object}  httpx.Response{error=httpx.ErrorResponse}
// @Router       /mfa/totp/enable [post]
func (h *Handler) EnableTOTP(c *gin.Context) {
	userID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}
	if h.totpKey == nil {
		httpx.RespondError(c, http.StatusBadRequest, "totp_unavailable", "totp not configured", nil)
		return
	}

	user, err := h.users.FindByID(c.Request.Context(), userID)
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_user", err.Error(), nil)
		return
	}

	secret, url, err := GenerateTOTPSecret(user.Email)
	if err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "totp_generate_failed", err.Error(), nil)
		return
	}

	enc, err := security.Encrypt(h.totpKey, []byte(secret))
	if err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "totp_encrypt_failed", err.Error(), nil)
		return
	}

	if _, err := h.repo.UpsertFactor(c.Request.Context(), userID, "totp", enc, false); err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "totp_store_failed", err.Error(), nil)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{
		"secret":      secret,
		"otpauth_url": url,
	})
}

// VerifyTOTP verifies and enables TOTP MFA
// @Summary      Verify TOTP
// @Description  Verify the first TOTP code to enable TOTP MFA for the user
// @Tags         mfa
// @Accept       json
// @Produce      json
// @Param        request body TOTPVerifyRequest true "TOTP verification payload"
// @Success      200  {object}  httpx.Response{data=map[string]bool}
// @Failure      400  {object}  httpx.Response{error=httpx.ErrorResponse}
// @Router       /mfa/totp/verify [post]
func (h *Handler) VerifyTOTP(c *gin.Context) {
	userID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}
	if h.totpKey == nil {
		httpx.RespondError(c, http.StatusBadRequest, "totp_unavailable", "totp not configured", nil)
		return
	}

	var req TOTPVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	factor, err := h.repo.GetFactor(c.Request.Context(), userID, "totp")
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "totp_missing", "totp not configured", nil)
		return
	}

	secret, err := security.Decrypt(h.totpKey, factor.SecretEncrypted)
	if err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "totp_decrypt_failed", err.Error(), nil)
		return
	}

	if !VerifyTOTP(string(secret), req.Code) {
		httpx.RespondError(c, http.StatusBadRequest, "totp_invalid", "invalid code", nil)
		return
	}

	if err := h.repo.Enable(c.Request.Context(), userID, "totp"); err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "totp_enable_failed", err.Error(), nil)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{"enabled": true})
}

// DisableTOTP disables TOTP MFA
// @Summary      Disable TOTP
// @Description  Disable TOTP MFA for the user
// @Tags         mfa
// @Produce      json
// @Success      200  {object}  httpx.Response{data=map[string]bool}
// @Router       /mfa/totp/disable [post]
func (h *Handler) DisableTOTP(c *gin.Context) {
	userID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	if err := h.repo.Disable(c.Request.Context(), userID, "totp"); err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "totp_disable_failed", err.Error(), nil)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{"disabled": true})
}

// EnableEmail starts email MFA setup by sending an OTP
// @Summary      Enable Email MFA
// @Description  Start enabling Email MFA by sending a verification code
// @Tags         mfa
// @Produce      json
// @Success      200  {object}  httpx.Response{data=map[string]string}
// @Router       /mfa/email/enable [post]
func (h *Handler) EnableEmail(c *gin.Context) {
	userID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	user, err := h.users.FindByID(c.Request.Context(), userID)
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_user", err.Error(), nil)
		return
	}

	code, err := security.GenerateNumericCode(6)
	if err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "code_generate_failed", err.Error(), nil)
		return
	}

	hash := security.HashToken(code)
	if _, err := h.repo.UpsertFactor(c.Request.Context(), userID, "email", []byte(hash), false); err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "email_mfa_setup_failed", err.Error(), nil)
		return
	}

	payload := email.TaskPayload{
		To:      user.Email,
		Subject: "Verify Email MFA Setup",
		Text:    "Your verification code is: " + code,
	}
	data, _ := json.Marshal(payload)
	_, _ = h.asynq.Enqueue(asynq.NewTask(ques.TaskEmailOTP, data), asynq.Queue(ques.QueueDefault))

	httpx.Respond(c, http.StatusOK, gin.H{"message": "verification code sent to email"})
}

// VerifyEmail verifies and enables email MFA
// @Summary      Verify Email MFA
// @Description  Verify the email code to enable Email MFA for the user
// @Tags         mfa
// @Accept       json
// @Produce      json
// @Param        request body EmailVerifyRequest true "Email verification payload"
// @Success      200  {object}  httpx.Response{data=map[string]bool}
// @Failure      400  {object}  httpx.Response{error=httpx.ErrorResponse}
// @Router       /mfa/email/verify [post]
func (h *Handler) VerifyEmail(c *gin.Context) {
	userID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	var req EmailVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	factor, err := h.repo.GetFactor(c.Request.Context(), userID, "email")
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "email_mfa_missing", "email mfa not configured", nil)
		return
	}

	if security.HashToken(req.Code) != string(factor.SecretEncrypted) {
		httpx.RespondError(c, http.StatusBadRequest, "email_mfa_invalid", "invalid code", nil)
		return
	}

	if err := h.repo.Enable(c.Request.Context(), userID, "email"); err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "email_mfa_enable_failed", err.Error(), nil)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{"enabled": true})
}

// DisableEmail disables email MFA
// @Summary      Disable Email MFA
// @Description  Disable Email MFA for the user
// @Tags         mfa
// @Produce      json
// @Success      200  {object}  httpx.Response{data=map[string]bool}
// @Router       /mfa/email/disable [post]
func (h *Handler) DisableEmail(c *gin.Context) {
	userID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	if err := h.repo.Disable(c.Request.Context(), userID, "email"); err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "email_mfa_disable_failed", err.Error(), nil)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{"disabled": true})
}

func getUserID(c *gin.Context) (uuid.UUID, error) {
	val, ok := c.Get(ctxkeys.UserIDKey)
	if !ok {
		return uuid.Nil, http.ErrNoCookie
	}
	return uuid.Parse(val.(string))
}
