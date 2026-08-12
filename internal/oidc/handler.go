package oidc

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"kael/internal/config"
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
// @Description  Start or resume the OIDC Authorization Code flow.
// @Tags         oidc
// @Param        tx query string false "Authorization transaction ID"
// @Param        client_id query string false "Client ID"
// @Param        redirect_uri query string false "Redirect URI"
// @Param        response_type query string false "Response type (must be 'code')"
// @Param        scope query string false "Requested scopes"
// @Param        state query string false "CSRF state parameter"
// @Param        nonce query string false "Nonce for ID token"
// @Param        code_challenge query string false "PKCE code challenge"
// @Param        code_challenge_method query string false "PKCE method (S256)"
// @Success      302 "Redirect to client or frontend consent/login page"
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /oidc/authorize [get]
func (h *Handler) Authorize(c *gin.Context) {
	txID := c.Query("tx")
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")

	if txID == "" && (clientID == "" || redirectURI == "" || responseType == "") {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_request", "client_id, redirect_uri, and response_type are required", nil)
		return
	}

	params := AuthorizeParams{
		TransactionID:       txID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		Scope:               c.Query("scope"),
		State:               c.Query("state"),
		Nonce:               c.Query("nonce"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
	}

	userID, sessionID, _ := h.resolveSession(c)

	result, err := h.service.Authorize(c.Request.Context(), params, userID, sessionID)
	if err != nil {
		switch err {
		case ErrMFAPending:
			mfaURL := fmt.Sprintf("%s/mfa-verify?redirect=%s",
				h.cfg.FrontendBaseURL,
				url.QueryEscape(c.Request.URL.String()),
			)
			c.Redirect(http.StatusFound, mfaURL)
		case ErrInvalidClient, ErrInvalidRedirectURI:
			httpx.RespondError(c, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		case ErrTransactionConsumed, ErrTransactionExpired, ErrTransactionInvalid:
			httpx.RespondError(c, http.StatusBadRequest, "invalid_transaction", err.Error(), nil)
		default:
			httpx.RespondError(c, http.StatusBadRequest, "authorize_error", err.Error(), nil)
		}
		return
	}

	switch result.ActionRequired {
	case "redirect_client":
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

	case "redirect_login", "redirect_consent":
		c.Redirect(http.StatusFound, result.RedirectURI)

	default:
		httpx.RespondError(c, http.StatusInternalServerError, "server_error", "unknown authorize state", nil)
	}
}

// GetConsentDetails retrieves application and scope details for a pending consent transaction
// @Summary      Get OIDC Consent Details
// @Description  Fetch client metadata and requested scopes for consent prompt
// @Tags         oidc
// @Produce      json
// @Param        tx query string true "Authorization transaction ID"
// @Success      200 {object} httpx.Response{data=ConsentDetailsResponse}
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /oidc/consent/details [get]
func (h *Handler) GetConsentDetails(c *gin.Context) {
	userID, _, err := h.resolveSession(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_required", "authentication required", nil)
		return
	}

	txID := c.Query("tx")
	if txID == "" {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_request", "transaction id required", nil)
		return
	}

	details, err := h.service.GetConsentDetails(c.Request.Context(), txID, userID)
	if err != nil {
		h.handleOAuthError(c, err)
		return
	}

	httpx.Respond(c, http.StatusOK, details)
}

// SubmitConsent processes user decision (allow or deny) for an authorization transaction
// @Summary      Submit OIDC Consent
// @Description  Approve or deny requested scopes for a pending authorization transaction
// @Tags         oidc
// @Accept       json
// @Produce      json
// @Param        request body ConsentSubmitRequest true "Consent decision payload"
// @Success      200 {object} httpx.Response{data=ConsentSubmitResponse}
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /oidc/consent [post]
func (h *Handler) SubmitConsent(c *gin.Context) {
	userID, sessionID, err := h.resolveSession(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_required", "authentication required", nil)
		return
	}

	var req ConsentSubmitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	resp, err := h.service.SubmitConsent(c.Request.Context(), req, userID, sessionID)
	if err != nil {
		h.handleOAuthError(c, err)
		return
	}

	httpx.Respond(c, http.StatusOK, resp)
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

// OIDCLogout handles the OIDC RP-initiated logout (GET /oidc/logout)
// @Summary      OIDC RP-initiated Logout
// @Description  End the user session and logout from all connected client applications
// @Tags         oidc
// @Param        id_token_hint query string false "ID Token Hint"
// @Param        post_logout_redirect_uri query string false "Post Logout Redirect URI"
// @Param        state query string false "State parameter to return"
// @Success      302 "Redirect to post_logout_redirect_uri or login page"
// @Router       /oidc/logout [get]
func (h *Handler) OIDCLogout(c *gin.Context) {
	idTokenHint := c.Query("id_token_hint")
	postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
	state := c.Query("state")

	var sessionID uuid.UUID
	var userID uuid.UUID
	var err error

	// 1. Try to resolve session from id_token_hint
	if idTokenHint != "" {
		claims, err := h.service.VerifyIDToken(idTokenHint)
		if err == nil && claims.Sid != "" {
			sessionID, _ = uuid.Parse(claims.Sid)
			userID, _ = uuid.Parse(claims.Sub)
		}
	}

	// 2. Fallback to platform session cookie
	if sessionID == uuid.Nil {
		userID, sessionID, err = h.resolveSession(c)
	}

	var frontChannelURLs []string
	if sessionID != uuid.Nil && userID != uuid.Nil {
		// 3. Trigger SLO and revoke OIDC tokens / platform session
		frontChannelURLs, err = h.service.PerformSingleLogout(c.Request.Context(), sessionID)
		if err == nil {
			_ = h.sessionsService.Revoke(c.Request.Context(), userID, sessionID)
			ClearSessionCookie(c, h.cfg)
		}
	}

	// 4. Validate and construct redirect URL
	redirectURL := h.cfg.FrontendBaseURL
	if postLogoutRedirectURI != "" {
		if h.service.ValidatePostLogoutRedirectURI(c.Request.Context(), postLogoutRedirectURI) {
			redirectURL = postLogoutRedirectURI
			if state != "" {
				parsed, err := url.Parse(redirectURL)
				if err == nil {
					q := parsed.Query()
					q.Set("state", state)
					parsed.RawQuery = q.Encode()
					redirectURL = parsed.String()
				}
			}
		}
	}

	// 5. If we have front-channel iframes, render HTML, otherwise redirect immediately
	if len(frontChannelURLs) > 0 {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, buildLogoutHTML(frontChannelURLs, redirectURL))
		return
	}

	c.Redirect(http.StatusFound, redirectURL)
}

func buildLogoutHTML(urls []string, redirectURL string) string {
	var iframes strings.Builder
	for _, u := range urls {
		iframes.WriteString(fmt.Sprintf(`<iframe src="%s" style="display:none; width:0; height:0; border:0;"></iframe>`, u))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Logging out...</title>
    <script>
        setTimeout(function() {
            window.location.href = %q;
        }, 1000);
    </script>
</head>
<body style="background: #0a0a0a; color: #ffffff; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;">
    <div style="text-align: center; max-width: 400px; padding: 2rem; background: #121212; border: 1px solid #222; border-radius: 24px; box-shadow: 0 20px 40px rgba(0,0,0,0.5);">
        <div style="margin: 0 auto 1.5rem; width: 50px; height: 50px; border: 3px solid rgba(255,255,255,0.1); border-top-color: #3b82f6; border-radius: 50%%; animation: spin 1s linear infinite;"></div>
        <h2 style="font-size: 1.5rem; font-weight: 800; margin: 0 0 0.5rem; letter-spacing: -0.025em;">Signing out</h2>
        <p style="color: #a3a3a3; font-size: 0.95rem; line-height: 1.5; font-weight: 500; margin: 0;">Logging you out of all connected applications safely...</p>
    </div>
    <style>
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
    %s
</body>
</html>`, redirectURL, iframes.String())
}

func ClearSessionCookie(c *gin.Context, cfg *config.Config) {
	c.SetCookie(
		cfg.SessionCookieName,
		"",
		-1,
		"/",
		cfg.SessionCookieDomain,
		cfg.SessionCookieSecure,
		true,
	)
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
	case ErrTokenInvalid, ErrSessionInactive:
		httpx.RespondError(c, http.StatusUnauthorized, "invalid_token", err.Error(), nil)
	case ErrTransactionExpired, ErrTransactionConsumed, ErrTransactionInvalid:
		httpx.RespondError(c, http.StatusBadRequest, "invalid_transaction", err.Error(), nil)
	case ErrSigningKey:
		httpx.RespondError(c, http.StatusInternalServerError, "server_error", "OIDC signing not configured", nil)
	case ErrUnsupportedGrant:
		httpx.RespondError(c, http.StatusBadRequest, "unsupported_grant_type", err.Error(), nil)
	default:
		httpx.RespondError(c, http.StatusBadRequest, "invalid_request", err.Error(), nil)
	}
}
