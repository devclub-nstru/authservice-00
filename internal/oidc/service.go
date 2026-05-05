package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
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
)

type Service struct {
	cfg        *config.Config
	repo       *Repository
	clientRepo *clients.Repository
	usersRepo  *users.Repository
	signingKey []byte
}

func NewService(cfg *config.Config, repo *Repository, clientRepo *clients.Repository, usersRepo *users.Repository) (*Service, error) {
	var signingKey []byte
	if cfg.OIDCSigningKey != "" {
		var err error
		signingKey, err = DecodeBase64SigningKey(cfg.OIDCSigningKey)
		if err != nil {
			return nil, err
		}
	}

	return &Service{
		cfg:        cfg,
		repo:       repo,
		clientRepo: clientRepo,
		usersRepo:  usersRepo,
		signingKey: signingKey,
	}, nil
}

type AuthorizeParams struct {
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
	RedirectURI string
	Code        string
	State       string
}

func (s *Service) Authorize(ctx context.Context, params AuthorizeParams, userID uuid.UUID, sessionID uuid.UUID) (*AuthorizeResult, error) {
	if params.ResponseType != "code" {
		return nil, ErrInvalidResponseType
	}

	client, err := s.clientRepo.FindByClientID(ctx, params.ClientID)
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

	rawCode, err := security.GenerateToken(32)
	if err != nil {
		return nil, err
	}
	codeHash := security.HashToken(rawCode)

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

	authCode := AuthorizationCode{
		CodeHash:            codeHash,
		ClientPK:            client.ID,
		UserID:              userID,
		SessionID:           sessionID,
		RedirectURI:         params.RedirectURI,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		ExpiresAt:           time.Now().Add(s.cfg.OIDCCodeTTL),
	}

	if _, err := s.repo.CreateAuthCode(ctx, authCode); err != nil {
		return nil, err
	}

	// Auto-create membership if not already a member
	isMember, err := s.clientRepo.IsMember(ctx, client.ID, userID)
	if err == nil && !isMember {
		_, _ = s.clientRepo.AddMember(ctx, client.ID, userID, "member")
	}

	return &AuthorizeResult{
		RedirectURI: params.RedirectURI,
		Code:        rawCode,
		State:       params.State,
	}, nil
}

func (s *Service) ExchangeCode(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	if s.signingKey == nil {
		return nil, ErrSigningKey
	}

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
	if s.signingKey == nil {
		return nil, ErrSigningKey
	}

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

func (s *Service) Discovery() *DiscoveryDocument {
	issuer := s.cfg.OIDCIssuer
	if issuer == "" {
		issuer = s.cfg.APIBaseURL
	}

	return &DiscoveryDocument{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/oidc/authorize",
		TokenEndpoint:                     issuer + "/oidc/token",
		UserinfoEndpoint:                  issuer + "/oidc/userinfo",
		RevocationEndpoint:                issuer + "/oidc/revoke",
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"HS256"},
		ScopesSupported:                   []string{"openid", "profile", "email"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
	}
}

func (s *Service) issueTokens(ctx context.Context, client *clients.Client, userID uuid.UUID, sessionID uuid.UUID, scope string, nonce *string) (*TokenResponse, error) {
	rawAccess, err := security.GenerateToken(48)
	if err != nil {
		return nil, err
	}
	rawRefresh, err := security.GenerateToken(48)
	if err != nil {
		return nil, err
	}

	accessHash := security.HashToken(rawAccess)
	refreshHash := security.HashToken(rawRefresh)
	accessExpiry := time.Now().Add(s.cfg.OIDCAccessTokenTTL)
	refreshExpiry := time.Now().Add(s.cfg.OIDCRefreshTokenTTL)

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

	issuer := s.cfg.OIDCIssuer
	if issuer == "" {
		issuer = s.cfg.APIBaseURL
	}

	claims := BuildIDTokenClaims(
		issuer, userID, client.ClientID, nonce,
		user.Email, user.EmailVerified, user.Name, user.AvatarURL,
		s.cfg.OIDCAccessTokenTTL,
	)

	idToken, err := SignIDToken(s.signingKey, claims)
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

func verifyPKCE(challenge string, verifier string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}
