package rbac

import "github.com/google/uuid"

type CreatePermissionRequest struct {
	Name        string  `json:"name" binding:"required"`
	Value       string  `json:"value" binding:"required"`
	Description *string `json:"description"`
}

type UpdatePermissionRequest struct {
	Name        *string `json:"name"`
	Value       *string `json:"value"`
	Description *string `json:"description"`
}

type CreateGroupRequest struct {
	Name          string      `json:"name" binding:"required"`
	Description   *string     `json:"description"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
}

type UpdateGroupRequest struct {
	Name          *string     `json:"name"`
	Description   *string     `json:"description"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
}

type AssignUserGroupRequest struct {
	Email     string     `json:"email" binding:"required,email"`
	GroupID   *uuid.UUID `json:"group_id"`
	GroupName *string    `json:"group_name"`
}

type UnassignUserGroupRequest struct {
	Email     string     `json:"email" binding:"required,email"`
	GroupID   *uuid.UUID `json:"group_id"`
	GroupName *string    `json:"group_name"`
}

type AssignUserGroupResponse struct {
	Status     string     `json:"status"`
	Email      string     `json:"email"`
	UserExists bool       `json:"user_exists"`
	UserID     *uuid.UUID `json:"user_id,omitempty"`
	GroupID    uuid.UUID  `json:"group_id"`
	GroupName  string     `json:"group_name"`
}
