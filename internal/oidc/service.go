package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"kael/internal/clients"
	"kael/internal/config"
	"kael/internal/security"
	"kael/internal/users"

	"github.com/google/uuid"
)

var (
	ErrInvalidClient       = errors.New("invalid client_id")
	ErrInvalidRedirectURI  = errors.New("redirect_uri does not match")
	ErrInvalidResponseType = errors.New("unsupported response_type")
	ErrSessionRequired     = errors.New("active session required")
	ErrMFAPending          = errors.New("mfa verification required")
	ErrCodeExpired         = errors.New("authorization code expired or consumed")
	ErrCodeInvalid         = errors.New("invalid authorization code")
	ErrPKCEFailed          = errors.New("PKCE verification failed")
	ErrClientSecretInvalid = errors.New("invalid client_secret")
	ErrTokenInvalid        = errors.New("invalid or expired token")
	ErrSessionInactive     = errors.New("linked platform session is no longer active")
	ErrUnsupportedGrant    = errors.New("unsupported grant_type")
	ErrSigningKey          = errors.New("OIDC signing key not configured")
	ErrTransactionExpired  = errors.New("authorization transaction expired")
	ErrTransactionConsumed = errors.New("authorization transaction already processed")
	ErrTransactionInvalid  = errors.New("invalid authorization transaction")
	ErrConsentDenied       = errors.New("user denied authorization request")
)

type Service struct {
	cfg        *config.Config
	repo       *Repository
	clientRepo *clients.Repository
	usersRepo  *users.Repository
	keyPair    *RSAKeyPair
}

func NewService(cfg *config.Config, repo *Repository, clientRepo *clients.Repository, usersRepo *users.Repository) (*Service, error) {
	var kp *RSAKeyPair
	var err error

	if cfg.OIDCPrivateKeyPath != "" {
		kp, err = LoadRSAKeyPairFromPEM(cfg.OIDCPrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("OIDC: %w", err)
		}
	} else {
		// No path configured — generate an ephemeral key (tokens won't survive restarts)
		kp, err = GenerateRSAKeyPair()
		if err != nil {
			return nil, err
		}
	}

	return &Service{
		cfg:        cfg,
		repo:       repo,
		clientRepo: clientRepo,
		usersRepo:  usersRepo,
		keyPair:    kp,
	}, nil
}

type AuthorizeParams struct {
	TransactionID       string
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type AuthorizeResult struct {
	ActionRequired string // redirect_client, redirect_login, redirect_consent
	RedirectURI    string
	Code           string
	State          string
	TransactionID  string
}

func (s *Service) Authorize(ctx context.Context, params AuthorizeParams, userID uuid.UUID, sessionID uuid.UUID) (*AuthorizeResult, error) {
	var tx *OIDCAuthorizationTransaction
	var client *clients.Client
	var err error

	if params.TransactionID != "" {
		txUUID, err := uuid.Parse(params.TransactionID)
		if err != nil {
			return nil, ErrTransactionInvalid
		}
		tx, err = s.repo.FindTransactionByID(ctx, txUUID)
		if err != nil {
			return nil, ErrTransactionInvalid
		}

		if tx.Status != "pending" {
			return nil, ErrTransactionConsumed
		}
		if time.Now().After(tx.ExpiresAt) {
			_ = s.repo.UpdateTransactionStatus(ctx, tx.ID, "expired")
			return nil, ErrTransactionExpired
		}

		client, err = s.clientRepo.FindByID(ctx, tx.ClientPK)
		if err != nil {
			return nil, ErrInvalidClient
		}

		if userID != uuid.Nil {
			tx.UserID = &userID
			_ = s.repo.UpdateTransactionUserID(ctx, tx.ID, userID)
		}
	} else {
		if params.ResponseType != "code" {
			return nil, ErrInvalidResponseType
		}

		client, err = s.clientRepo.FindByClientID(ctx, params.ClientID)
		if err != nil {
			return nil, ErrInvalidClient
		}

		valid, err := s.clientRepo.HasRedirectURI(ctx, client.ID, params.RedirectURI)
		if err != nil || !valid {
			return nil, ErrInvalidRedirectURI
		}

		scope := params.Scope
		if scope == "" {
			scope = "openid profile email"
		}

		var userPtr *uuid.UUID
		if userID != uuid.Nil {
			userPtr = &userID
		}

		var state *string
		if params.State != "" {
			state = &params.State
		}
		var nonce *string
		if params.Nonce != "" {
			nonce = &params.Nonce
		}
		var challenge *string
		if params.CodeChallenge != "" {
			challenge = &params.CodeChallenge
		}
		var method *string
		if params.CodeChallengeMethod != "" {
			method = &params.CodeChallengeMethod
		}

		newTx := OIDCAuthorizationTransaction{
			ClientPK:            client.ID,
			UserID:              userPtr,
			RedirectURI:         params.RedirectURI,
			Scope:               scope,
			State:               state,
			Nonce:               nonce,
			CodeChallenge:       challenge,
			CodeChallengeMethod: method,
			ResponseType:        params.ResponseType,
			Status:              "pending",
			ExpiresAt:           time.Now().Add(15 * time.Minute),
		}

		tx, err = s.repo.CreateTransaction(ctx, newTx)
		if err != nil {
			return nil, err
		}
	}

	// 1. Unauthenticated -> Redirect to Login
	if userID == uuid.Nil {
		loginURL := fmt.Sprintf("%s/login?tx=%s", s.cfg.FrontendBaseURL, tx.ID.String())
		return &AuthorizeResult{
			ActionRequired: "redirect_login",
			RedirectURI:    loginURL,
			TransactionID:  tx.ID.String(),
		}, nil
	}

	// 2. Authenticated -> Check consent
	hasConsent, _, _ := s.checkConsent(ctx, userID, client.ID, tx.Scope)

	// If user already approved all requested scopes -> immediate authorize
	if hasConsent {
		rawCode, err := security.GenerateToken(32)
		if err != nil {
			return nil, err
		}
		codeHash := security.HashToken(rawCode)

		authCode := AuthorizationCode{
			CodeHash:            codeHash,
			ClientPK:            client.ID,
			UserID:              userID,
			SessionID:           sessionID,
			RedirectURI:         tx.RedirectURI,
			Scope:               tx.Scope,
			State:               tx.State,
			Nonce:               tx.Nonce,
			CodeChallenge:       tx.CodeChallenge,
			CodeChallengeMethod: tx.CodeChallengeMethod,
			ExpiresAt:           time.Now().Add(s.cfg.OIDCCodeTTL),
		}

		if _, err := s.repo.CreateAuthCode(ctx, authCode); err != nil {
			return nil, err
		}

		_ = s.repo.UpdateTransactionStatus(ctx, tx.ID, "approved")

		isMember, err := s.clientRepo.IsMember(ctx, client.ID, userID)
		if err == nil && !isMember {
			_, _ = s.clientRepo.AddMember(ctx, client.ID, userID, "member")
		}

		stateStr := ""
		if tx.State != nil {
			stateStr = *tx.State
		}

		return &AuthorizeResult{
			ActionRequired: "redirect_client",
			RedirectURI:    tx.RedirectURI,
			Code:           rawCode,
			State:          stateStr,
		}, nil
	}

	// 3. Authenticated but needs consent -> Redirect to Consent page
	consentURL := fmt.Sprintf("%s/oidc/consent?tx=%s", s.cfg.FrontendBaseURL, tx.ID.String())
	return &AuthorizeResult{
		ActionRequired: "redirect_consent",
		RedirectURI:    consentURL,
		TransactionID:  tx.ID.String(),
	}, nil
}

func (s *Service) GetConsentDetails(ctx context.Context, txID string, userID uuid.UUID) (*ConsentDetailsResponse, error) {
	txUUID, err := uuid.Parse(txID)
	if err != nil {
		return nil, ErrTransactionInvalid
	}

	tx, err := s.repo.FindTransactionByID(ctx, txUUID)
	if err != nil {
		return nil, ErrTransactionInvalid
	}

	if tx.Status != "pending" {
		return nil, ErrTransactionConsumed
	}

	if time.Now().After(tx.ExpiresAt) {
		_ = s.repo.UpdateTransactionStatus(ctx, tx.ID, "expired")
		return nil, ErrTransactionExpired
	}

	if tx.UserID == nil {
		tx.UserID = &userID
		_ = s.repo.UpdateTransactionUserID(ctx, tx.ID, userID)
	} else if *tx.UserID != userID {
		return nil, ErrTransactionInvalid
	}

	client, err := s.clientRepo.FindByID(ctx, tx.ClientPK)
	if err != nil {
		return nil, ErrInvalidClient
	}

	user, err := s.usersRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	var domain *string
	if parsed, err := url.Parse(tx.RedirectURI); err == nil && parsed.Host != "" {
		d := parsed.Host
		domain = &d
	}

	clientInfo := ConsentClientInfo{
		ID:        client.ClientID,
		Name:      client.Name,
		AvatarURL: client.AvatarURL,
		Domain:    domain,
	}

	userInfo := ConsentUserInfo{
		ID:        user.ID.String(),
		Email:     user.Email,
		Name:      user.Name,
		AvatarURL: user.AvatarURL,
	}

	_, grantedSet, _ := s.checkConsent(ctx, userID, client.ID, tx.Scope)

	requestedList := parseScopes(tx.Scope)
	scopeItems := make([]ConsentScopeItem, 0, len(requestedList))

	for _, sc := range requestedList {
		item := translateScope(sc)
		if _, granted := grantedSet[sc]; !granted {
			item.IsNew = true
		} else {
			item.IsNew = false
		}
		scopeItems = append(scopeItems, item)
	}

	return &ConsentDetailsResponse{
		TransactionID: tx.ID.String(),
		Client:        clientInfo,
		User:          userInfo,
		Scopes:        scopeItems,
	}, nil
}

func (s *Service) SubmitConsent(ctx context.Context, req ConsentSubmitRequest, userID uuid.UUID, sessionID uuid.UUID) (*ConsentSubmitResponse, error) {
	txUUID, err := uuid.Parse(req.TransactionID)
	if err != nil {
		return nil, ErrTransactionInvalid
	}

	tx, err := s.repo.FindTransactionByID(ctx, txUUID)
	if err != nil {
		return nil, ErrTransactionInvalid
	}

	if tx.Status != "pending" {
		return nil, ErrTransactionConsumed
	}

	if time.Now().After(tx.ExpiresAt) {
		_ = s.repo.UpdateTransactionStatus(ctx, tx.ID, "expired")
		return nil, ErrTransactionExpired
	}

	if tx.UserID == nil || *tx.UserID != userID {
		return nil, ErrTransactionInvalid
	}

	client, err := s.clientRepo.FindByID(ctx, tx.ClientPK)
	if err != nil {
		return nil, ErrInvalidClient
	}

	if req.Decision == "deny" {
		_ = s.repo.UpdateTransactionStatus(ctx, tx.ID, "denied")

		redirectURL, err := url.Parse(tx.RedirectURI)
		if err != nil {
			return nil, ErrInvalidRedirectURI
		}

		q := redirectURL.Query()
		q.Set("error", "access_denied")
		if tx.State != nil && *tx.State != "" {
			q.Set("state", *tx.State)
		}
		redirectURL.RawQuery = q.Encode()

		return &ConsentSubmitResponse{
			RedirectURL: redirectURL.String(),
		}, nil
	}

	if req.Decision != "allow" {
		return nil, errors.New("invalid decision value")
	}

	// 1. Merge existing scopes with new requested scopes
	existingConsent, err := s.repo.GetConsent(ctx, userID, client.ID)
	var mergedScopes string
	if err == nil && existingConsent != nil {
		mergedScopes = mergeScopes(existingConsent.Scopes, tx.Scope)
	} else {
		mergedScopes = tx.Scope
	}

	_, err = s.repo.UpsertConsent(ctx, userID, client.ID, mergedScopes)
	if err != nil {
		return nil, err
	}

	// 2. Add membership if not already a member
	isMember, err := s.clientRepo.IsMember(ctx, client.ID, userID)
	if err == nil && !isMember {
		_, _ = s.clientRepo.AddMember(ctx, client.ID, userID, "member")
	}

	// 3. Issue Authorization Code
	rawCode, err := security.GenerateToken(32)
	if err != nil {
		return nil, err
	}
	codeHash := security.HashToken(rawCode)

	authCode := AuthorizationCode{
		CodeHash:            codeHash,
		ClientPK:            client.ID,
		UserID:              userID,
		SessionID:           sessionID,
		RedirectURI:         tx.RedirectURI,
		Scope:               tx.Scope,
		State:               tx.State,
		Nonce:               tx.Nonce,
		CodeChallenge:       tx.CodeChallenge,
		CodeChallengeMethod: tx.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(s.cfg.OIDCCodeTTL),
	}

	if _, err := s.repo.CreateAuthCode(ctx, authCode); err != nil {
		return nil, err
	}

	_ = s.repo.UpdateTransactionStatus(ctx, tx.ID, "approved")

	redirectURL, err := url.Parse(tx.RedirectURI)
	if err != nil {
		return nil, ErrInvalidRedirectURI
	}

	q := redirectURL.Query()
	q.Set("code", rawCode)
	if tx.State != nil && *tx.State != "" {
		q.Set("state", *tx.State)
	}
	redirectURL.RawQuery = q.Encode()

	return &ConsentSubmitResponse{
		RedirectURL: redirectURL.String(),
	}, nil
}

func (s *Service) ExchangeCode(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	client, err := s.clientRepo.FindByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	codeHash := security.HashToken(req.Code)
	authCode, err := s.repo.FindAuthCodeByHash(ctx, codeHash)
	if err != nil {
		return nil, ErrCodeInvalid
	}

	if authCode.ConsumedAt != nil || time.Now().After(authCode.ExpiresAt) {
		return nil, ErrCodeExpired
	}

	if authCode.ClientPK != client.ID {
		return nil, ErrCodeInvalid
	}

	if authCode.RedirectURI != req.RedirectURI {
		return nil, ErrInvalidRedirectURI
	}

	if req.ClientSecret == "" {
		return nil, ErrClientSecretInvalid
	}
	secretHash := security.HashToken(req.ClientSecret)
	if secretHash != client.ClientSecretHash {
		return nil, ErrClientSecretInvalid
	}

	if authCode.CodeChallenge != nil && *authCode.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			return nil, ErrPKCEFailed
		}
		if !verifyPKCE(*authCode.CodeChallenge, req.CodeVerifier) {
			return nil, ErrPKCEFailed
		}
	}

	active, err := s.repo.IsSessionActive(ctx, authCode.SessionID)
	if err != nil || !active {
		return nil, ErrSessionInactive
	}

	if err := s.repo.ConsumeAuthCode(ctx, authCode.ID); err != nil {
		return nil, err
	}

	return s.issueTokens(ctx, client, authCode.UserID, authCode.SessionID, authCode.Scope, authCode.Nonce)
}

func (s *Service) RefreshTokens(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	client, err := s.clientRepo.FindByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	if req.ClientSecret == "" {
		return nil, ErrClientSecretInvalid
	}
	secretHash := security.HashToken(req.ClientSecret)
	if secretHash != client.ClientSecretHash {
		return nil, ErrClientSecretInvalid
	}

	refreshHash := security.HashToken(req.RefreshToken)
	token, err := s.repo.FindTokenByRefreshHash(ctx, refreshHash)
	if err != nil {
		return nil, ErrTokenInvalid
	}

	if token.RevokedAt != nil {
		return nil, ErrTokenInvalid
	}
	if token.RefreshExpiresAt != nil && time.Now().After(*token.RefreshExpiresAt) {
		return nil, ErrTokenInvalid
	}
	if token.ClientPK != client.ID {
		return nil, ErrTokenInvalid
	}

	active, err := s.repo.IsSessionActive(ctx, token.SessionID)
	if err != nil || !active {
		return nil, ErrSessionInactive
	}

	if err := s.repo.RevokeToken(ctx, token.ID); err != nil {
		return nil, err
	}

	return s.issueTokens(ctx, client, token.UserID, token.SessionID, token.Scope, nil)
}

func (s *Service) UserInfo(ctx context.Context, accessToken string) (*UserInfoResponse, error) {
	tokenHash := security.HashToken(accessToken)
	token, err := s.repo.FindTokenByAccessHash(ctx, tokenHash)
	if err != nil {
		return nil, ErrTokenInvalid
	}

	if token.RevokedAt != nil || time.Now().After(token.AccessExpiresAt) {
		return nil, ErrTokenInvalid
	}

	active, err := s.repo.IsSessionActive(ctx, token.SessionID)
	if err != nil || !active {
		return nil, ErrSessionInactive
	}

	user, err := s.usersRepo.FindByID(ctx, token.UserID)
	if err != nil {
		return nil, err
	}

	return &UserInfoResponse{
		Sub:           user.ID.String(),
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.Name,
		Picture:       user.AvatarURL,
	}, nil
}

func (s *Service) Revoke(ctx context.Context, rawToken string) error {
	tokenHash := security.HashToken(rawToken)

	if err := s.repo.RevokeTokenByAccessHash(ctx, tokenHash); err == nil {
		return nil
	}
	return s.repo.RevokeTokenByRefreshHash(ctx, tokenHash)
}

func (s *Service) Logout(ctx context.Context, accessToken string) error {
	tokenHash := security.HashToken(accessToken)
	token, err := s.repo.FindTokenByAccessHash(ctx, tokenHash)
	if err != nil {
		return ErrTokenInvalid
	}
	return s.repo.RevokeTokensByUserAndClient(ctx, token.UserID, token.ClientPK)
}

func (s *Service) JWKS() *JWKSDocument {
	return BuildJWKS(s.keyPair)
}

func (s *Service) Introspect(ctx context.Context, rawToken string) *IntrospectResponse {
	inactive := &IntrospectResponse{Active: false}

	tokenHash := security.HashToken(rawToken)
	token, err := s.repo.FindTokenByAccessHash(ctx, tokenHash)
	if err != nil {
		return inactive
	}

	if token.RevokedAt != nil || time.Now().After(token.AccessExpiresAt) {
		return inactive
	}

	active, err := s.repo.IsSessionActive(ctx, token.SessionID)
	if err != nil || !active {
		return inactive
	}

	client, err := s.clientRepo.FindByID(ctx, token.ClientPK)
	if err != nil {
		return inactive
	}

	return &IntrospectResponse{
		Active:    true,
		Sub:       token.UserID.String(),
		ClientID:  client.ClientID,
		Scope:     token.Scope,
		Exp:       token.AccessExpiresAt.Unix(),
		Iat:       token.CreatedAt.Unix(),
		TokenType: "Bearer",
	}
}

func (s *Service) Discovery() *DiscoveryDocument {
	issuer := s.cfg.OIDCIssuer
	if issuer == "" {
		issuer = s.cfg.APIBaseURL
	}

	return &DiscoveryDocument{
		Issuer:                             issuer,
		AuthorizationEndpoint:              issuer + "/oidc/authorize",
		TokenEndpoint:                      issuer + "/oidc/token",
		UserinfoEndpoint:                   issuer + "/oidc/userinfo",
		RevocationEndpoint:                 issuer + "/oidc/revoke",
		IntrospectionEndpoint:              issuer + "/oidc/introspect",
		EndSessionEndpoint:                 issuer + "/oidc/logout",
		JWKSUri:                            issuer + "/.well-known/jwks.json",
		ResponseTypesSupported:             []string{"code"},
		SubjectTypesSupported:              []string{"public"},
		IDTokenSigningAlgValuesSupported:   []string{"RS256"},
		ScopesSupported:                    []string{"openid", "profile", "email"},
		TokenEndpointAuthMethodsSupported:  []string{"client_secret_post"},
		CodeChallengeMethodsSupported:      []string{"S256"},
		GrantTypesSupported:                []string{"authorization_code", "refresh_token"},
		FrontchannelLogoutSupported:        true,
		FrontchannelLogoutSessionSupported: true,
		BackchannelLogoutSupported:         true,
		BackchannelLogoutSessionSupported:  true,
	}
}

func (s *Service) issueTokens(ctx context.Context, client *clients.Client, userID uuid.UUID, sessionID uuid.UUID, scope string, nonce *string) (*TokenResponse, error) {
	rawRefresh, err := security.GenerateToken(48)
	if err != nil {
		return nil, err
	}

	refreshHash := security.HashToken(rawRefresh)
	accessExpiry := time.Now().Add(s.cfg.OIDCAccessTokenTTL)
	refreshExpiry := time.Now().Add(s.cfg.OIDCRefreshTokenTTL)

	issuer := s.cfg.OIDCIssuer
	if issuer == "" {
		issuer = s.cfg.APIBaseURL
	}

	// Generate signed JWT Access Token
	jti := uuid.New().String()
	accessTokenClaims := AccessTokenClaims{
		Iss:      issuer,
		Sub:      userID.String(),
		Aud:      client.ClientID,
		Exp:      accessExpiry.Unix(),
		Iat:      time.Now().Unix(),
		ClientID: client.ClientID,
		Scope:    scope,
		Jti:      jti,
	}

	rawAccess, err := SignAccessTokenRS256(s.keyPair, accessTokenClaims)
	if err != nil {
		return nil, err
	}

	accessHash := security.HashToken(rawAccess)

	tokenRecord := OIDCToken{
		ClientPK:         client.ID,
		UserID:           userID,
		SessionID:        sessionID,
		AccessTokenHash:  accessHash,
		RefreshTokenHash: &refreshHash,
		Scope:            scope,
		AccessExpiresAt:  accessExpiry,
		RefreshExpiresAt: &refreshExpiry,
	}

	if _, err := s.repo.CreateToken(ctx, tokenRecord); err != nil {
		return nil, err
	}

	user, err := s.usersRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	claims := BuildIDTokenClaims(
		issuer, userID, client.ClientID, nonce,
		user.Email, user.EmailVerified, user.Name, user.AvatarURL,
		sessionID.String(),
		s.cfg.OIDCAccessTokenTTL,
	)

	idToken, err := SignIDTokenRS256(s.keyPair, claims)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  rawAccess,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.cfg.OIDCAccessTokenTTL.Seconds()),
		IDToken:      idToken,
		RefreshToken: rawRefresh,
	}, nil
}

func (s *Service) checkConsent(ctx context.Context, userID uuid.UUID, clientPK uuid.UUID, requestedScopes string) (bool, map[string]struct{}, []string) {
	grantedMap := make(map[string]struct{})
	consent, err := s.repo.GetConsent(ctx, userID, clientPK)
	if err == nil && consent != nil {
		for _, sc := range parseScopes(consent.Scopes) {
			grantedMap[sc] = struct{}{}
		}
	}

	reqList := parseScopes(requestedScopes)
	var newScopes []string
	allGranted := true

	for _, sc := range reqList {
		if _, granted := grantedMap[sc]; !granted {
			allGranted = false
			newScopes = append(newScopes, sc)
		}
	}

	return allGranted, grantedMap, newScopes
}

func parseScopes(scopeStr string) []string {
	parts := strings.Fields(scopeStr)
	result := make([]string, 0, len(parts))
	seen := make(map[string]bool)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

func mergeScopes(existing string, requested string) string {
	seen := make(map[string]bool)
	var result []string

	for _, sc := range parseScopes(existing) {
		if !seen[sc] {
			seen[sc] = true
			result = append(result, sc)
		}
	}
	for _, sc := range parseScopes(requested) {
		if !seen[sc] {
			seen[sc] = true
			result = append(result, sc)
		}
	}
	return strings.Join(result, " ")
}

func translateScope(scope string) ConsentScopeItem {
	switch scope {
	case "openid":
		return ConsentScopeItem{
			Key:         "openid",
			Title:       "View your account ID",
			Description: "Allows the application to recognize you using your unique account ID.",
		}
	case "profile":
		return ConsentScopeItem{
			Key:         "profile",
			Title:       "View your profile information",
			Description: "Allows the application to read your name and profile picture.",
		}
	case "email":
		return ConsentScopeItem{
			Key:         "email",
			Title:       "View your email address",
			Description: "Allows the application to see your primary email address.",
		}
	default:
		title := strings.Title(strings.ReplaceAll(scope, ":", " "))
		return ConsentScopeItem{
			Key:         scope,
			Title:       title,
			Description: fmt.Sprintf("Allows access to %s.", scope),
		}
	}
}

func verifyPKCE(challenge string, verifier string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}

func (s *Service) PerformSingleLogout(ctx context.Context, sessionID uuid.UUID) ([]string, error) {
	rows, err := s.repo.db.Query(ctx, `
		SELECT DISTINCT client_id
		FROM oidc_tokens
		WHERE session_id = $1 AND revoked_at IS NULL`,
		sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clientIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		clientIDs = append(clientIDs, id)
	}

	var frontChannelURLs []string

	for _, clientID := range clientIDs {
		client, err := s.clientRepo.FindByID(ctx, clientID)
		if err != nil {
			continue
		}

		var userID uuid.UUID
		err = s.repo.db.QueryRow(ctx, `
			SELECT user_id FROM sessions WHERE id = $1`,
			sessionID,
		).Scan(&userID)
		if err != nil {
			continue
		}

		if client.BackChannelLogoutURI != nil && *client.BackChannelLogoutURI != "" {
			s.triggerBackChannelLogout(ctx, client.ClientID, *client.BackChannelLogoutURI, userID, sessionID)
		}

		if client.FrontChannelLogoutURI != nil && *client.FrontChannelLogoutURI != "" {
			issuer := s.cfg.OIDCIssuer
			if issuer == "" {
				issuer = s.cfg.APIBaseURL
			}
			fcURL, err := url.Parse(*client.FrontChannelLogoutURI)
			if err == nil {
				q := fcURL.Query()
				q.Set("iss", issuer)
				q.Set("sid", sessionID.String())
				fcURL.RawQuery = q.Encode()
				frontChannelURLs = append(frontChannelURLs, fcURL.String())
			}
		}
	}

	_, err = s.repo.db.Exec(ctx, `
		UPDATE oidc_tokens
		SET revoked_at = $2
		WHERE session_id = $1 AND revoked_at IS NULL`,
		sessionID, time.Now(),
	)
	if err != nil {
		return nil, err
	}

	return frontChannelURLs, nil
}

func (s *Service) triggerBackChannelLogout(ctx context.Context, clientID string, backChannelURI string, userID uuid.UUID, sessionID uuid.UUID) {
	issuer := s.cfg.OIDCIssuer
	if issuer == "" {
		issuer = s.cfg.APIBaseURL
	}

	claims := LogoutTokenClaims{
		Iss: issuer,
		Sub: userID.String(),
		Aud: clientID,
		Iat: time.Now().Unix(),
		Jti: uuid.New().String(),
		Sid: sessionID.String(),
		Events: map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
	}

	logoutToken, err := SignLogoutTokenRS256(s.keyPair, claims)
	if err != nil {
		return
	}

	go func() {
		reqCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		val := url.Values{}
		val.Set("logout_token", logoutToken)

		req, err := http.NewRequestWithContext(reqCtx, "POST", backChannelURI, strings.NewReader(val.Encode()))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
	}()
}

func (s *Service) ValidatePostLogoutRedirectURI(ctx context.Context, uri string) bool {
	u, err := url.ParseRequestURI(uri)
	if err != nil {
		return false
	}
	_ = u

	query := `SELECT EXISTS(SELECT 1 FROM client_redirect_uris WHERE uri = $1)`
	var exists bool
	err = s.repo.db.QueryRow(ctx, query, uri).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

func (s *Service) VerifyIDToken(tokenStr string) (*IDTokenClaims, error) {
	return VerifyIDTokenRS256(s.keyPair, tokenStr)
}
