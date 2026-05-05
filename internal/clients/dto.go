package clients

import "time"

type CreateClientRequest struct {
	Name         string   `json:"name" binding:"required"`
	AvatarURL    *string  `json:"avatar_url"`
	RedirectURIs []string `json:"redirect_uris" binding:"required,min=1"`
}

type UpdateClientRequest struct {
	Name         *string  `json:"name"`
	AvatarURL    *string  `json:"avatar_url"`
	RedirectURIs []string `json:"redirect_uris"`
}

type AddMemberRequest struct {
	Email string `json:"email" binding:"required,email"`
	Role  string `json:"role" binding:"omitempty"`
}

type ClientResponse struct {
	ID           string    `json:"id"`
	ClientID     string    `json:"client_id"`
	Name         string    `json:"name"`
	AvatarURL    *string   `json:"avatar_url,omitempty"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type CreateClientResponse struct {
	Client       ClientResponse `json:"client"`
	ClientSecret string         `json:"client_secret"`
}

type RotateSecretResponse struct {
	ClientSecret string `json:"client_secret"`
}
