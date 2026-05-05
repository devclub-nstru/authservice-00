package clients

import (
	"time"

	"github.com/google/uuid"
)

type Client struct {
	ID               uuid.UUID `json:"id"`
	OwnerID          uuid.UUID `json:"owner_id"`
	ClientID         string    `json:"client_id"`
	ClientSecretHash string    `json:"-"`
	Name             string    `json:"name"`
	AvatarURL        *string   `json:"avatar_url,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type RedirectURI struct {
	ID       uuid.UUID `json:"id"`
	ClientPK uuid.UUID `json:"client_id"`
	URI      string    `json:"uri"`
}

type Membership struct {
	ID        uuid.UUID `json:"id"`
	ClientPK  uuid.UUID `json:"client_id"`
	UserID    uuid.UUID `json:"user_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type MemberProfile struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	Name      *string   `json:"name,omitempty"`
	AvatarURL *string   `json:"avatar_url,omitempty"`
	Role      string    `json:"role"`
	JoinedAt  time.Time `json:"joined_at"`
}

type ConnectedClient struct {
	ID          uuid.UUID `json:"id"`
	ClientID    string    `json:"client_id"`
	Name        string    `json:"name"`
	AvatarURL   *string   `json:"avatar_url,omitempty"`
	Role        string    `json:"role"`
	ConnectedAt time.Time `json:"connected_at"`
}
