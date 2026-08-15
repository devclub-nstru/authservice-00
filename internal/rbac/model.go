package rbac

import (
	"time"

	"github.com/google/uuid"
)

type Permission struct {
	ID          uuid.UUID `json:"id"`
	ClientID    uuid.UUID `json:"client_id"`
	Name        string    `json:"name"`
	Value       string    `json:"value"`
	Description *string   `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type PermissionGroup struct {
	ID          uuid.UUID    `json:"id"`
	ClientID    uuid.UUID    `json:"client_id"`
	Name        string       `json:"name"`
	Description *string      `json:"description,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	Permissions []Permission `json:"permissions,omitempty"`
}

type UserPermissionGroup struct {
	ID         uuid.UUID  `json:"id"`
	ClientID   uuid.UUID  `json:"client_id"`
	Email      string     `json:"email"`
	UserID     *uuid.UUID `json:"user_id,omitempty"`
	GroupID    uuid.UUID  `json:"group_id"`
	GroupName  string     `json:"group_name,omitempty"`
	AssignedAt time.Time  `json:"assigned_at"`
}

type UserPermissionsResult struct {
	Email       string            `json:"email"`
	UserID      *uuid.UUID        `json:"user_id,omitempty"`
	Groups      []PermissionGroup `json:"groups"`
	Permissions []Permission      `json:"permissions"`
}
