package rbac

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrPermissionNotFound = errors.New("permission not found")
	ErrGroupNotFound      = errors.New("permission group not found")
	ErrAssignmentNotFound = errors.New("user group assignment not found")
	ErrAlreadyExists      = errors.New("permission or group already exists")
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// --- Permissions ---

func (r *Repository) CreatePermission(ctx context.Context, clientID uuid.UUID, name, value string, description *string) (*Permission, error) {
	query := `
		INSERT INTO client_permissions (client_id, name, value, description)
		VALUES ($1, $2, $3, $4)
		RETURNING id, client_id, name, value, description, created_at, updated_at`

	var p Permission
	err := r.db.QueryRow(ctx, query, clientID, name, value, description).Scan(
		&p.ID, &p.ClientID, &p.Name, &p.Value, &p.Description, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *Repository) GetPermissionByID(ctx context.Context, clientID, permID uuid.UUID) (*Permission, error) {
	query := `
		SELECT id, client_id, name, value, description, created_at, updated_at
		FROM client_permissions
		WHERE id = $1 AND client_id = $2`

	var p Permission
	err := r.db.QueryRow(ctx, query, permID, clientID).Scan(
		&p.ID, &p.ClientID, &p.Name, &p.Value, &p.Description, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPermissionNotFound
		}
		return nil, err
	}
	return &p, nil
}

func (r *Repository) ListPermissions(ctx context.Context, clientID uuid.UUID) ([]Permission, error) {
	query := `
		SELECT id, client_id, name, value, description, created_at, updated_at
		FROM client_permissions
		WHERE client_id = $1
		ORDER BY name ASC, value ASC`

	rows, err := r.db.Query(ctx, query, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.ClientID, &p.Name, &p.Value, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

func (r *Repository) UpdatePermission(ctx context.Context, clientID, permID uuid.UUID, name, value *string, description *string) (*Permission, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if name != nil {
		_, err := tx.Exec(ctx, `UPDATE client_permissions SET name = $3, updated_at = $4 WHERE id = $1 AND client_id = $2`, permID, clientID, *name, time.Now())
		if err != nil {
			return nil, err
		}
	}
	if value != nil {
		_, err := tx.Exec(ctx, `UPDATE client_permissions SET value = $3, updated_at = $4 WHERE id = $1 AND client_id = $2`, permID, clientID, *value, time.Now())
		if err != nil {
			return nil, err
		}
	}
	if description != nil {
		_, err := tx.Exec(ctx, `UPDATE client_permissions SET description = $3, updated_at = $4 WHERE id = $1 AND client_id = $2`, permID, clientID, *description, time.Now())
		if err != nil {
			return nil, err
		}
	}

	var p Permission
	err = tx.QueryRow(ctx, `SELECT id, client_id, name, value, description, created_at, updated_at FROM client_permissions WHERE id = $1 AND client_id = $2`, permID, clientID).Scan(
		&p.ID, &p.ClientID, &p.Name, &p.Value, &p.Description, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *Repository) DeletePermission(ctx context.Context, clientID, permID uuid.UUID) error {
	res, err := r.db.Exec(ctx, `DELETE FROM client_permissions WHERE id = $1 AND client_id = $2`, permID, clientID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrPermissionNotFound
	}
	return nil
}

// --- Permission Groups ---

func (r *Repository) CreateGroup(ctx context.Context, clientID uuid.UUID, name string, description *string, permIDs []uuid.UUID) (*PermissionGroup, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	queryGroup := `
		INSERT INTO client_permission_groups (client_id, name, description)
		VALUES ($1, $2, $3)
		RETURNING id, client_id, name, description, created_at, updated_at`

	var g PermissionGroup
	err = tx.QueryRow(ctx, queryGroup, clientID, name, description).Scan(
		&g.ID, &g.ClientID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	for _, pID := range permIDs {
		_, err := tx.Exec(ctx, `INSERT INTO client_permission_group_items (group_id, permission_id) VALUES ($1, $2)`, g.ID, pID)
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return r.GetGroupByID(ctx, clientID, g.ID)
}

func (r *Repository) GetGroupByID(ctx context.Context, clientID, groupID uuid.UUID) (*PermissionGroup, error) {
	queryGroup := `
		SELECT id, client_id, name, description, created_at, updated_at
		FROM client_permission_groups
		WHERE id = $1 AND client_id = $2`

	var g PermissionGroup
	err := r.db.QueryRow(ctx, queryGroup, groupID, clientID).Scan(
		&g.ID, &g.ClientID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrGroupNotFound
		}
		return nil, err
	}

	queryPerms := `
		SELECT p.id, p.client_id, p.name, p.value, p.description, p.created_at, p.updated_at
		FROM client_permission_group_items item
		JOIN client_permissions p ON item.permission_id = p.id
		WHERE item.group_id = $1
		ORDER BY p.name ASC, p.value ASC`

	rows, err := r.db.Query(ctx, queryPerms, g.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.ClientID, &p.Name, &p.Value, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		g.Permissions = append(g.Permissions, p)
	}
	if g.Permissions == nil {
		g.Permissions = []Permission{}
	}

	return &g, nil
}

func (r *Repository) GetGroupByName(ctx context.Context, clientID uuid.UUID, name string) (*PermissionGroup, error) {
	queryGroup := `
		SELECT id, client_id, name, description, created_at, updated_at
		FROM client_permission_groups
		WHERE client_id = $1 AND name = $2`

	var g PermissionGroup
	err := r.db.QueryRow(ctx, queryGroup, clientID, name).Scan(
		&g.ID, &g.ClientID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrGroupNotFound
		}
		return nil, err
	}
	return r.GetGroupByID(ctx, clientID, g.ID)
}

func (r *Repository) ListGroups(ctx context.Context, clientID uuid.UUID) ([]PermissionGroup, error) {
	queryGroups := `
		SELECT id, client_id, name, description, created_at, updated_at
		FROM client_permission_groups
		WHERE client_id = $1
		ORDER BY name ASC`

	rows, err := r.db.Query(ctx, queryGroups, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []PermissionGroup
	for rows.Next() {
		var g PermissionGroup
		if err := rows.Scan(&g.ID, &g.ClientID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}

	for i := range groups {
		gDetail, err := r.GetGroupByID(ctx, clientID, groups[i].ID)
		if err == nil {
			groups[i].Permissions = gDetail.Permissions
		}
	}

	return groups, nil
}

func (r *Repository) UpdateGroup(ctx context.Context, clientID, groupID uuid.UUID, name *string, description *string, permIDs []uuid.UUID) (*PermissionGroup, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if name != nil {
		_, err := tx.Exec(ctx, `UPDATE client_permission_groups SET name = $3, updated_at = $4 WHERE id = $1 AND client_id = $2`, groupID, clientID, *name, time.Now())
		if err != nil {
			return nil, err
		}
	}
	if description != nil {
		_, err := tx.Exec(ctx, `UPDATE client_permission_groups SET description = $3, updated_at = $4 WHERE id = $1 AND client_id = $2`, groupID, clientID, *description, time.Now())
		if err != nil {
			return nil, err
		}
	}

	if permIDs != nil {
		_, err := tx.Exec(ctx, `DELETE FROM client_permission_group_items WHERE group_id = $1`, groupID)
		if err != nil {
			return nil, err
		}
		for _, pID := range permIDs {
			_, err := tx.Exec(ctx, `INSERT INTO client_permission_group_items (group_id, permission_id) VALUES ($1, $2)`, groupID, pID)
			if err != nil {
				return nil, err
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return r.GetGroupByID(ctx, clientID, groupID)
}

func (r *Repository) DeleteGroup(ctx context.Context, clientID, groupID uuid.UUID) error {
	res, err := r.db.Exec(ctx, `DELETE FROM client_permission_groups WHERE id = $1 AND client_id = $2`, groupID, clientID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrGroupNotFound
	}
	return nil
}

// --- User Group Assignments & Lazy Binding ---

func (r *Repository) AssignUserGroup(ctx context.Context, clientID uuid.UUID, email string, userID *uuid.UUID, groupID uuid.UUID) (*UserPermissionGroup, error) {
	query := `
		INSERT INTO client_user_permission_groups (client_id, email, user_id, group_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (client_id, email, group_id) 
		DO UPDATE SET user_id = EXCLUDED.user_id, assigned_at = now()
		RETURNING id, client_id, email, user_id, group_id, assigned_at`

	var upg UserPermissionGroup
	err := r.db.QueryRow(ctx, query, clientID, email, userID, groupID).Scan(
		&upg.ID, &upg.ClientID, &upg.Email, &upg.UserID, &upg.GroupID, &upg.AssignedAt,
	)
	if err != nil {
		return nil, err
	}
	return &upg, nil
}

func (r *Repository) UnassignUserGroup(ctx context.Context, clientID uuid.UUID, email string, groupID uuid.UUID) error {
	res, err := r.db.Exec(ctx, `DELETE FROM client_user_permission_groups WHERE client_id = $1 AND email = $2 AND group_id = $3`, clientID, email, groupID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrAssignmentNotFound
	}
	return nil
}

// BindPendingUserAssignments links all pending email assignments across ALL clients to the newly created user_id
func (r *Repository) BindPendingUserAssignments(ctx context.Context, userID uuid.UUID, email string) (int64, error) {
	query := `
		UPDATE client_user_permission_groups
		SET user_id = $1
		WHERE email = $2 AND user_id IS NULL`

	tag, err := r.db.Exec(ctx, query, userID, email)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *Repository) GetUserPermissions(ctx context.Context, clientID uuid.UUID, email string, userID *uuid.UUID) (*UserPermissionsResult, error) {
	result := &UserPermissionsResult{
		Email:       email,
		UserID:      userID,
		Groups:      []PermissionGroup{},
		Permissions: []Permission{},
	}

	queryGroups := `
		SELECT g.id, g.client_id, g.name, g.description, g.created_at, g.updated_at
		FROM client_user_permission_groups upg
		JOIN client_permission_groups g ON upg.group_id = g.id
		WHERE upg.client_id = $1 AND (upg.email = $2 OR (upg.user_id IS NOT NULL AND upg.user_id = $3))`

	var queryUserID interface{}
	if userID != nil {
		queryUserID = *userID
	} else {
		queryUserID = uuid.Nil
	}

	rows, err := r.db.Query(ctx, queryGroups, clientID, email, queryUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groupIDs := []uuid.UUID{}
	for rows.Next() {
		var g PermissionGroup
		if err := rows.Scan(&g.ID, &g.ClientID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		result.Groups = append(result.Groups, g)
		groupIDs = append(groupIDs, g.ID)
	}

	if len(groupIDs) == 0 {
		return result, nil
	}

	queryPerms := `
		SELECT DISTINCT p.id, p.client_id, p.name, p.value, p.description, p.created_at, p.updated_at
		FROM client_permission_group_items item
		JOIN client_permissions p ON item.permission_id = p.id
		WHERE item.group_id = ANY($1)
		ORDER BY p.name ASC, p.value ASC`

	rowsPerms, err := r.db.Query(ctx, queryPerms, groupIDs)
	if err != nil {
		return nil, err
	}
	defer rowsPerms.Close()

	for rowsPerms.Next() {
		var p Permission
		if err := rowsPerms.Scan(&p.ID, &p.ClientID, &p.Name, &p.Value, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		result.Permissions = append(result.Permissions, p)
	}

	return result, nil
}
