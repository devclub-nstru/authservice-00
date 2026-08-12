package oidc

import (
	"time"

	"github.com/google/uuid"
)

type AuthorizationCode struct {
	ID                  uuid.UUID  `json:"id"`
	CodeHash            string     `json:"-"`
	ClientPK            uuid.UUID  `json:"client_id"`
	UserID              uuid.UUID  `json:"user_id"`
	SessionID           uuid.UUID  `json:"session_id"`
	RedirectURI         string     `json:"redirect_uri"`
	Scope               string     `json:"scope"`
	State               *string    `json:"state,omitempty"`
	Nonce               *string    `json:"nonce,omitempty"`
	CodeChallenge       *string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod *string    `json:"code_challenge_method,omitempty"`
	ExpiresAt           time.Time  `json:"expires_at"`
	ConsumedAt          *time.Time `json:"consumed_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

type OIDCToken struct {
	ID               uuid.UUID  `json:"id"`
	ClientPK         uuid.UUID  `json:"client_id"`
	UserID           uuid.UUID  `json:"user_id"`
	SessionID        uuid.UUID  `json:"session_id"`
	AccessTokenHash  string     `json:"-"`
	RefreshTokenHash *string    `json:"-"`
	Scope            string     `json:"scope"`
	AccessExpiresAt  time.Time  `json:"access_expires_at"`
	RefreshExpiresAt *time.Time `json:"refresh_expires_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

type OIDCConsent struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	ClientPK  uuid.UUID `json:"client_id"`
	Scopes    string    `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type OIDCAuthorizationTransaction struct {
	ID                  uuid.UUID  `json:"id"`
	ClientPK            uuid.UUID  `json:"client_id"`
	UserID              *uuid.UUID `json:"user_id,omitempty"`
	RedirectURI         string     `json:"redirect_uri"`
	Scope               string     `json:"scope"`
	State               *string    `json:"state,omitempty"`
	Nonce               *string    `json:"nonce,omitempty"`
	CodeChallenge       *string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod *string    `json:"code_challenge_method,omitempty"`
	ResponseType        string     `json:"response_type"`
	Status              string     `json:"status"` // pending, approved, denied, expired
	ExpiresAt           time.Time  `json:"expires_at"`
	CreatedAt           time.Time  `json:"created_at"`
}

type ConsentScopeItem struct {
	Key         string `json:"key"`
	Title       string `json:"title"`
	Description string `json:"description"`
	IsNew       bool   `json:"is_new"`
}

type ConsentClientInfo struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	AvatarURL *string `json:"avatar_url,omitempty"`
	Domain    *string `json:"domain,omitempty"`
}

type ConsentUserInfo struct {
	ID        string  `json:"id"`
	Email     string  `json:"email"`
	Name      *string `json:"name,omitempty"`
	AvatarURL *string `json:"avatar_url,omitempty"`
}

type ConsentDetailsResponse struct {
	TransactionID string             `json:"transaction_id"`
	Client        ConsentClientInfo  `json:"client"`
	User          ConsentUserInfo    `json:"user"`
	Scopes        []ConsentScopeItem `json:"scopes"`
}

type ConsentSubmitRequest struct {
	TransactionID string `json:"transaction_id" binding:"required"`
	Decision      string `json:"decision" binding:"required"` // allow or deny
}

type ConsentSubmitResponse struct {
	RedirectURL string `json:"redirect_url"`
}
