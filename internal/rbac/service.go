package rbac

import (
	"context"
	"errors"
	"fmt"

	"kael/internal/users"

	"github.com/google/uuid"
)

var (
	ErrInvalidRequest = errors.New("invalid request parameters")
)

type Service struct {
	repo      *Repository
	usersRepo *users.Repository
}

func NewService(repo *Repository, usersRepo *users.Repository) *Service {
	return &Service{repo: repo, usersRepo: usersRepo}
}

// --- Permissions Service ---

func (s *Service) CreatePermission(ctx context.Context, clientID uuid.UUID, req CreatePermissionRequest) (*Permission, error) {
	if req.Name == "" || req.Value == "" {
		return nil, fmt.Errorf("%w: name and value are required", ErrInvalidRequest)
	}
	return s.repo.CreatePermission(ctx, clientID, req.Name, req.Value, req.Description)
}

func (s *Service) GetPermission(ctx context.Context, clientID, permID uuid.UUID) (*Permission, error) {
	return s.repo.GetPermissionByID(ctx, clientID, permID)
}

func (s *Service) ListPermissions(ctx context.Context, clientID uuid.UUID) ([]Permission, error) {
	return s.repo.ListPermissions(ctx, clientID)
}

func (s *Service) UpdatePermission(ctx context.Context, clientID, permID uuid.UUID, req UpdatePermissionRequest) (*Permission, error) {
	return s.repo.UpdatePermission(ctx, clientID, permID, req.Name, req.Value, req.Description)
}

func (s *Service) DeletePermission(ctx context.Context, clientID, permID uuid.UUID) error {
	return s.repo.DeletePermission(ctx, clientID, permID)
}

// --- Groups Service ---

func (s *Service) CreateGroup(ctx context.Context, clientID uuid.UUID, req CreateGroupRequest) (*PermissionGroup, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("%w: group name is required", ErrInvalidRequest)
	}
	if req.PermissionIDs == nil {
		req.PermissionIDs = []uuid.UUID{}
	}
	return s.repo.CreateGroup(ctx, clientID, req.Name, req.Description, req.PermissionIDs)
}

func (s *Service) GetGroup(ctx context.Context, clientID, groupID uuid.UUID) (*PermissionGroup, error) {
	return s.repo.GetGroupByID(ctx, clientID, groupID)
}

func (s *Service) ListGroups(ctx context.Context, clientID uuid.UUID) ([]PermissionGroup, error) {
	return s.repo.ListGroups(ctx, clientID)
}

func (s *Service) UpdateGroup(ctx context.Context, clientID, groupID uuid.UUID, req UpdateGroupRequest) (*PermissionGroup, error) {
	return s.repo.UpdateGroup(ctx, clientID, groupID, req.Name, req.Description, req.PermissionIDs)
}

func (s *Service) DeleteGroup(ctx context.Context, clientID, groupID uuid.UUID) error {
	return s.repo.DeleteGroup(ctx, clientID, groupID)
}

// --- User Assignment Service (with Lazy Binding) ---

func (s *Service) AssignUserGroup(ctx context.Context, clientID uuid.UUID, req AssignUserGroupRequest) (*AssignUserGroupResponse, error) {
	if req.Email == "" {
		return nil, fmt.Errorf("%w: email is required", ErrInvalidRequest)
	}

	var group *PermissionGroup
	var err error

	if req.GroupID != nil {
		group, err = s.repo.GetGroupByID(ctx, clientID, *req.GroupID)
	} else if req.GroupName != nil && *req.GroupName != "" {
		group, err = s.repo.GetGroupByName(ctx, clientID, *req.GroupName)
	} else {
		return nil, fmt.Errorf("%w: group_id or group_name required", ErrInvalidRequest)
	}

	if err != nil {
		return nil, err
	}

	// Check if user account already exists in authservice
	var targetUserID *uuid.UUID
	userExists := false
	user, err := s.usersRepo.FindByEmail(ctx, req.Email)
	if err == nil && user != nil {
		targetUserID = &user.ID
		userExists = true
	}

	upg, err := s.repo.AssignUserGroup(ctx, clientID, req.Email, targetUserID, group.ID)
	if err != nil {
		return nil, err
	}

	return &AssignUserGroupResponse{
		Status:     "assigned",
		Email:      upg.Email,
		UserExists: userExists,
		UserID:     upg.UserID,
		GroupID:    group.ID,
		GroupName:  group.Name,
	}, nil
}

func (s *Service) UnassignUserGroup(ctx context.Context, clientID uuid.UUID, req UnassignUserGroupRequest) error {
	if req.Email == "" {
		return fmt.Errorf("%w: email is required", ErrInvalidRequest)
	}

	var groupID uuid.UUID
	if req.GroupID != nil {
		groupID = *req.GroupID
	} else if req.GroupName != nil && *req.GroupName != "" {
		group, err := s.repo.GetGroupByName(ctx, clientID, *req.GroupName)
		if err != nil {
			return err
		}
		groupID = group.ID
	} else {
		return fmt.Errorf("%w: group_id or group_name required", ErrInvalidRequest)
	}

	return s.repo.UnassignUserGroup(ctx, clientID, req.Email, groupID)
}

func (s *Service) GetUserPermissions(ctx context.Context, clientID uuid.UUID, email string) (*UserPermissionsResult, error) {
	if email == "" {
		return nil, fmt.Errorf("%w: email is required", ErrInvalidRequest)
	}

	var targetUserID *uuid.UUID
	user, err := s.usersRepo.FindByEmail(ctx, email)
	if err == nil && user != nil {
		targetUserID = &user.ID
	}

	return s.repo.GetUserPermissions(ctx, clientID, email, targetUserID)
}

// BindPendingUserAssignments should be called whenever a new user is created in authservice
func (s *Service) BindPendingUserAssignments(ctx context.Context, userID uuid.UUID, email string) (int64, error) {
	return s.repo.BindPendingUserAssignments(ctx, userID, email)
}
