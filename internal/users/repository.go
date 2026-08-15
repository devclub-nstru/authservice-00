package users

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(ctx context.Context, params CreateUserParams) (*User, error) {
	query := `
		INSERT INTO users (email, email_verified, password_hash, password_enabled, name, avatar_url)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, email, email_verified, password_hash, password_enabled, name, avatar_url, created_at, updated_at, last_login_at`

	row := r.db.QueryRow(ctx, query, params.Email, params.EmailVerified, params.PasswordHash, params.PasswordEnabled, params.Name, params.AvatarURL)
	user, err := scanUser(row)
	if err != nil {
		return nil, err
	}

	// Auto-bind any pending RBAC group assignments created before the user registered
	_, _ = r.db.Exec(ctx, `UPDATE client_user_permission_groups SET user_id = $1 WHERE email = $2 AND user_id IS NULL`, user.ID, user.Email)

	return user, nil
}

func (r *Repository) FindByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT id, email, email_verified, password_hash, password_enabled, name, avatar_url, created_at, updated_at, last_login_at
		FROM users WHERE email = $1`
	row := r.db.QueryRow(ctx, query, email)
	return scanUser(row)
}

func (r *Repository) FindByID(ctx context.Context, id uuid.UUID) (*User, error) {
	query := `
		SELECT id, email, email_verified, password_hash, password_enabled, name, avatar_url, created_at, updated_at, last_login_at
		FROM users WHERE id = $1`
	row := r.db.QueryRow(ctx, query, id)
	return scanUser(row)
}

func (r *Repository) VerifyEmail(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE users
		SET email_verified = true, updated_at = $2
		WHERE id = $1`
	_, err := r.db.Exec(ctx, query, userID, time.Now())
	return err
}

func (r *Repository) UpdateEmail(ctx context.Context, userID uuid.UUID, email string) error {
	query := `
		UPDATE users
		SET email = $2, email_verified = false, updated_at = $3
		WHERE id = $1`
	_, err := r.db.Exec(ctx, query, userID, email, time.Now())
	return err
}

func (r *Repository) SetPassword(ctx context.Context, userID uuid.UUID, hash string, enabled bool) error {
	query := `
		UPDATE users
		SET password_hash = $2, password_enabled = $3, updated_at = $4
		WHERE id = $1`
	_, err := r.db.Exec(ctx, query, userID, hash, enabled, time.Now())
	return err
}

func (r *Repository) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE users
		SET last_login_at = $2, updated_at = $2
		WHERE id = $1`
	_, err := r.db.Exec(ctx, query, userID, time.Now())
	return err
}

func scanUser(row pgx.Row) (*User, error) {
	var user User
	if err := row.Scan(
		&user.ID,
		&user.Email,
		&user.EmailVerified,
		&user.PasswordHash,
		&user.PasswordEnabled,
		&user.Name,
		&user.AvatarURL,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	); err != nil {
		return nil, err
	}
	return &user, nil
}
