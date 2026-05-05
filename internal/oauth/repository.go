package oauth

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

func (r *Repository) Create(ctx context.Context, account Account) (*Account, error) {
	query := `
		INSERT INTO oauth_accounts (user_id, provider, provider_user_id, email, email_verified)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, user_id, provider, provider_user_id, email, email_verified, created_at, updated_at`

	row := r.db.QueryRow(ctx, query, account.UserID, account.Provider, account.ProviderUserID, account.Email, account.EmailVerified)
	return scanAccount(row)
}

func (r *Repository) FindByProviderUserID(ctx context.Context, provider string, providerUserID string) (*Account, error) {
	query := `
		SELECT id, user_id, provider, provider_user_id, email, email_verified, created_at, updated_at
		FROM oauth_accounts
		WHERE provider = $1 AND provider_user_id = $2`
	row := r.db.QueryRow(ctx, query, provider, providerUserID)
	return scanAccount(row)
}

func (r *Repository) FindByUserProvider(ctx context.Context, userID uuid.UUID, provider string) (*Account, error) {
	query := `
		SELECT id, user_id, provider, provider_user_id, email, email_verified, created_at, updated_at
		FROM oauth_accounts
		WHERE user_id = $1 AND provider = $2`
	row := r.db.QueryRow(ctx, query, userID, provider)
	return scanAccount(row)
}

func (r *Repository) ListByUser(ctx context.Context, userID uuid.UUID) ([]Account, error) {
	query := `
		SELECT id, user_id, provider, provider_user_id, email, email_verified, created_at, updated_at
		FROM oauth_accounts
		WHERE user_id = $1`
	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []Account
	for rows.Next() {
		account, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, *account)
	}
	return accounts, rows.Err()
}

func (r *Repository) Touch(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE oauth_accounts SET updated_at = $2 WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id, time.Now())
	return err
}

func scanAccount(row pgx.Row) (*Account, error) {
	var account Account
	if err := row.Scan(
		&account.ID,
		&account.UserID,
		&account.Provider,
		&account.ProviderUserID,
		&account.Email,
		&account.EmailVerified,
		&account.CreatedAt,
		&account.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &account, nil
}
