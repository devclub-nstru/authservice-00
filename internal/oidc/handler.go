package oidc

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"kael/internal/config"
	"kael/internal/ctxkeys"
	"kael/internal/httpx"
	"kael/internal/sessions"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Handler struct {
	service         *Service
	cfg             *config.Config
	sessionsService *sessions.Service
}

func NewHandler(service *Service, cfg *config.Config, sessionsService *sessions.Service) *Handler {
	return &Handler{
		service:         service,
		cfg:             cfg,
		sessionsService: sessionsService,
	}
}

// Authorize handles the OIDC authorization endpoint
// @Summary      OIDC Authorize
// @Description  Start the OIDC Authorization Code flow. Requires an active platform session.
// @Tags         oidc
// @Param        client_id query string true "Client ID"
// @Param        redirect_uri query string true "Redirect URI"
// @Param        response_type query string true "Response type (must be 'code')"
// @Param        scope query string false "Requested scopes"
// @Param        state query string false "CSRF state parameter"
// @Param        nonce query string false "Nonce for ID token"
// @Param        code_challenge query string false "PKCE code challenge"
// @Param        code_challenge_method query string false "PKCE method (S256)"
// @Success      302 "Redirect to client with authorization code"
// @Failure      302 "Redirect to login if no session"
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /oidc/authorize [get]
func (h *Handler) Authorize(c *gin.Context) {
	params := AuthorizeParams{
		ClientID:            c.Query("client_id"),
		RedirectURI:         c.Query("redirect_uri"),
		ResponseType:        c.Query("response_type"),
		Scope:               c.Query("scope"),
		State:               c.Query("state"),
		Nonce:               c.Query("nonce"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
	}

	if params.ClientID == "" || params.RedirectURI == "" || params.ResponseType == "" {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_request", "client_id, redirect_uri, and response_type are required", nil)
		return
	}

	userID, sessionID, err := h.resolveSession(c)
	if err != nil {
		authorizeURL := c.Request.URL.String()
		loginURL := fmt.Sprintf("%s/login?redirect=%s",
			h.cfg.FrontendBaseURL,
			url.QueryEscape(h.cfg.APIBaseURL+authorizeURL),
		)
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	result, err := h.service.Authorize(c.Request.Context(), params, userID, sessionID)
	if err != nil {
		switch err {
		case ErrMFAPending:
			mfaURL := fmt.Sprintf("%s/mfa?redirect=%s",
				h.cfg.FrontendBaseURL,
				url.QueryEscape(c.Request.URL.String()),
			)
			c.Redirect(http.StatusFound, mfaURL)
		case ErrInvalidClient, ErrInvalidRedirectURI:
			httpx.RespondError(c, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		default:
			httpx.RespondError(c, http.StatusBadRequest, "authorize_error", err.Error(), nil)
		}
		return
	}

	redirectURL, err := url.Parse(result.RedirectURI)
	if err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "redirect_error", "invalid redirect URI", nil)
		return
	}

	q := redirectURL.Query()
	q.Set("code", result.Code)
	if result.State != "" {
		q.Set("state", result.State)
	}
	redirectURL.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, redirectURL.String())
}

// Token handles the OIDC token endpoint
// @Summary      OIDC Token
// @Description  Exchange an authorization code for tokens, or refresh an access token using a refresh token
// @Tags         oidc
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        grant_type formData string true "Grant type (authorization_code or refresh_token)"
// @Param        code formData string false "Authorization code (required only for authorization_code grant)"
// @Param        redirect_uri formData string false "Redirect URI used in authorize (required only for authorization_code grant)"
// @Param        client_id formData string true "Client ID"
// @Param        client_secret formData string false "Client secret (required for confidential clients)"
// @Param        code_verifier formData string false "PKCE code verifier (required only when PKCE was used)"
// @Param        refresh_token formData string false "Refresh token (required only for refresh_token grant)"
// @Success      200 {object} TokenResponse
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /oidc/token [post]
func (h *Handler) Token(c *gin.Context) {
	var req TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		return
	}

	var resp *TokenResponse
	var err error

	switch req.GrantType {
	case "authorization_code":
		resp, err = h.service.ExchangeCode(c.Request.Context(), req)
	case "refresh_token":
		resp, err = h.service.RefreshTokens(c.Request.Context(), req)
	default:
		httpx.RespondError(c, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token", nil)
		return
	}

	if err != nil {
		h.handleOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// UserInfo returns user profile information
// @Summary      OIDC UserInfo
// @Description  Return user profile data based on access token
// @Tags         oidc
// @Produce      json
// @Success      200 {object} UserInfoResponse
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /oidc/userinfo [get]
func (h *Handler) UserInfo(c *gin.Context) {
	accessToken := extractBearerToken(c)
	if accessToken == "" {
		httpx.RespondError(c, http.StatusUnauthorized, "invalid_token", "Bearer token required", nil)
		return
	}

	info, err := h.service.UserInfo(c.Request.Context(), accessToken)
	if err != nil {
		h.handleOAuthError(c, err)
		return
	}

	c.JSON(http.StatusOK, info)
}

// Revoke revokes an access or refresh token
// @Summary      Revoke Token
// @Description  Revoke an access or refresh token
// @Tags         oidc
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        token formData string true "Token to revoke"
// @Success      200 {object} httpx.Response{data=map[string]bool}
// @Router       /oidc/revoke [post]
func (h *Handler) Revoke(c *gin.Context) {
	var req RevokeRequest
	if err := c.ShouldBind(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		return
	}

	_ = h.service.Revoke(c.Request.Context(), req.Token)
	httpx.Respond(c, http.StatusOK, gin.H{"revoked": true})
}

// Logout revokes all tokens for a user-client pair
// @Summary      OIDC Logout
// @Description  Revoke all tokens for the client associated with the access token
// @Tags         oidc
// @Produce      json
// @Success      200 {object} httpx.Response{data=map[string]bool}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /oidc/logout [post]
func (h *Handler) Logout(c *gin.Context) {
	accessToken := extractBearerToken(c)
	if accessToken == "" {
		httpx.RespondError(c, http.StatusUnauthorized, "invalid_token", "Bearer token required", nil)
		return
	}

	if err := h.service.Logout(c.Request.Context(), accessToken); err != nil {
		h.handleOAuthError(c, err)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{"logged_out": true})
}

// Discovery returns the OpenID Connect discovery document
// @Summary      OIDC Discovery
// @Description  Return the OpenID Connect discovery document
// @Tags         oidc
// @Produce      json
// @Success      200 {object} DiscoveryDocument
// @Router       /.well-known/openid-configuration [get]
func (h *Handler) Discovery(c *gin.Context) {
	c.JSON(http.StatusOK, h.service.Discovery())
}

// JWKS returns the JSON Web Key Set for RS256 token verification
// @Summary      JWKS
// @Description  Return the public RSA keys used to verify ID tokens
// @Tags         oidc
// @Produce      json
// @Success      200 {object} JWKSDocument
// @Router       /.well-known/jwks.json [get]
func (h *Handler) JWKS(c *gin.Context) {
	c.JSON(http.StatusOK, h.service.JWKS())
}

// Introspect validates an access token and returns its metadata
// @Summary      Token Introspection
// @Description  Inspect an access token — returns active status and claims
// @Tags         oidc
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        token formData string true "The access token to introspect"
// @Success      200 {object} IntrospectResponse
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /oidc/introspect [post]
func (h *Handler) Introspect(c *gin.Context) {
	var req IntrospectRequest
	if err := c.ShouldBind(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		return
	}
	// Always return 200 per RFC 7662 — inactive if invalid
	c.JSON(http.StatusOK, h.service.Introspect(c.Request.Context(), req.Token))
}

func (h *Handler) resolveSession(c *gin.Context) (uuid.UUID, uuid.UUID, error) {
	cookieValue, err := c.Cookie(h.cfg.SessionCookieName)
	if err != nil || cookieValue == "" {
		return uuid.Nil, uuid.Nil, ErrSessionRequired
	}

	token, deviceID, ok := sessions.DecodeCookieValue(cookieValue)
	if !ok {
		return uuid.Nil, uuid.Nil, ErrSessionRequired
	}

	session, err := h.sessionsService.Validate(c.Request.Context(), token, deviceID)
	if err != nil {
		return uuid.Nil, uuid.Nil, ErrSessionRequired
	}

	return session.UserID, session.ID, nil
}

func extractBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func (h *Handler) handleOAuthError(c *gin.Context, err error) {
	switch err {
	case ErrInvalidClient:
		httpx.RespondError(c, http.StatusBadRequest, "invalid_client", err.Error(), nil)
	case ErrCodeInvalid, ErrCodeExpired:
		httpx.RespondError(c, http.StatusBadRequest, "invalid_grant", err.Error(), nil)
	case ErrInvalidRedirectURI:
		httpx.RespondError(c, http.StatusBadRequest, "invalid_redirect_uri", err.Error(), nil)
	case ErrClientSecretInvalid:
		httpx.RespondError(c, http.StatusUnauthorized, "invalid_client", err.Error(), nil)
	case ErrPKCEFailed:
		httpx.RespondError(c, http.StatusBadRequest, "invalid_grant", err.Error(), nil)
	case ErrTokenInvalid:
		httpx.RespondError(c, http.StatusUnauthorized, "invalid_token", err.Error(), nil)
	case ErrSessionInactive:
		httpx.RespondError(c, http.StatusUnauthorized, "invalid_token", err.Error(), nil)
	case ErrSigningKey:
		httpx.RespondError(c, http.StatusInternalServerError, "server_error", "OIDC signing not configured", nil)
	case ErrUnsupportedGrant:
		httpx.RespondError(c, http.StatusBadRequest, "unsupported_grant_type", err.Error(), nil)
	default:
		httpx.RespondError(c, http.StatusBadRequest, "invalid_request", err.Error(), nil)
	}
}

func getSessionUserID(c *gin.Context) (uuid.UUID, error) {
	val, ok := c.Get(ctxkeys.UserIDKey)
	if !ok {
		return uuid.Nil, http.ErrNoCookie
	}
	return uuid.Parse(val.(string))
}
