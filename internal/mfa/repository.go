package mfa

import (
	"context"
	"encoding/json"
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

func (r *Repository) UpsertFactor(ctx context.Context, userID uuid.UUID, factorType string, secret []byte, enabled bool) (*Factor, error) {
	query := `
		INSERT INTO mfa_factors (user_id, factor_type, secret_encrypted, enabled)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, factor_type)
		DO UPDATE SET secret_encrypted = $3, enabled = $4, updated_at = $5
		RETURNING id, user_id, factor_type, secret_encrypted, enabled, created_at, updated_at, last_used_at`

	row := r.db.QueryRow(ctx, query, userID, factorType, secret, enabled, time.Now())
	return scanFactor(row)
}

func (r *Repository) GetFactor(ctx context.Context, userID uuid.UUID, factorType string) (*Factor, error) {
	query := `
		SELECT id, user_id, factor_type, secret_encrypted, enabled, created_at, updated_at, last_used_at
		FROM mfa_factors WHERE user_id = $1 AND factor_type = $2`

	row := r.db.QueryRow(ctx, query, userID, factorType)
	return scanFactor(row)
}

func (r *Repository) ListEnabled(ctx context.Context, userID uuid.UUID) ([]Factor, error) {
	query := `
		SELECT id, user_id, factor_type, secret_encrypted, enabled, created_at, updated_at, last_used_at
		FROM mfa_factors WHERE user_id = $1 AND enabled = true`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var factors []Factor
	for rows.Next() {
		factor, err := scanFactor(rows)
		if err != nil {
			return nil, err
		}
		factors = append(factors, *factor)
	}
	return factors, rows.Err()
}

func (r *Repository) Disable(ctx context.Context, userID uuid.UUID, factorType string) error {
	query := `
		UPDATE mfa_factors
		SET enabled = false, updated_at = $3
		WHERE user_id = $1 AND factor_type = $2`
	_, err := r.db.Exec(ctx, query, userID, factorType, time.Now())
	return err
}

func (r *Repository) Enable(ctx context.Context, userID uuid.UUID, factorType string) error {
	query := `
		UPDATE mfa_factors
		SET enabled = true, updated_at = $3
		WHERE user_id = $1 AND factor_type = $2`
	_, err := r.db.Exec(ctx, query, userID, factorType, time.Now())
	return err
}

func (r *Repository) CreateChallenge(ctx context.Context, challenge Challenge) (*Challenge, error) {
	required, err := json.Marshal(challenge.RequiredFactors)
	if err != nil {
		return nil, err
	}
	verified, err := json.Marshal(challenge.VerifiedFactors)
	if err != nil {
		return nil, err
	}

	query := `
		INSERT INTO mfa_challenges (user_id, challenge_token_hash, required_factors, verified_factors, email_code_hash, expires_at, device_id, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, user_id, challenge_token_hash, required_factors, verified_factors, email_code_hash, expires_at, consumed_at, device_id, ip_address, user_agent, created_at`

	row := r.db.QueryRow(ctx, query,
		challenge.UserID,
		challenge.TokenHash,
		required,
		verified,
		challenge.EmailCodeHash,
		challenge.ExpiresAt,
		challenge.DeviceID,
		challenge.IPAddress,
		challenge.UserAgent,
	)
	return scanChallenge(row)
}

func (r *Repository) FindChallengeByTokenHash(ctx context.Context, tokenHash string) (*Challenge, error) {
	query := `
		SELECT id, user_id, challenge_token_hash, required_factors, verified_factors, email_code_hash, expires_at, consumed_at, device_id, ip_address, user_agent, created_at
		FROM mfa_challenges WHERE challenge_token_hash = $1`

	row := r.db.QueryRow(ctx, query, tokenHash)
	return scanChallenge(row)
}

func (r *Repository) UpdateChallenge(ctx context.Context, challengeID uuid.UUID, verified []string, consumedAt *time.Time) error {
	verifiedJSON, err := json.Marshal(verified)
	if err != nil {
		return err
	}

	query := `
		UPDATE mfa_challenges
		SET verified_factors = $2, consumed_at = $3
		WHERE id = $1`
	_, err = r.db.Exec(ctx, query, challengeID, verifiedJSON, consumedAt)
	return err
}

func (r *Repository) UpdateEmailCode(ctx context.Context, challengeID uuid.UUID, codeHash string, expiresAt time.Time) error {
	query := `
		UPDATE mfa_challenges
		SET email_code_hash = $2, expires_at = $3
		WHERE id = $1`
	_, err := r.db.Exec(ctx, query, challengeID, codeHash, expiresAt)
	return err
}

func scanFactor(row pgx.Row) (*Factor, error) {
	var factor Factor
	if err := row.Scan(
		&factor.ID,
		&factor.UserID,
		&factor.FactorType,
		&factor.SecretEncrypted,
		&factor.Enabled,
		&factor.CreatedAt,
		&factor.UpdatedAt,
		&factor.LastUsedAt,
	); err != nil {
		return nil, err
	}
	return &factor, nil
}

func scanChallenge(row pgx.Row) (*Challenge, error) {
	var (
		requiredJSON []byte
		verifiedJSON []byte
	)
	var challenge Challenge
	if err := row.Scan(
		&challenge.ID,
		&challenge.UserID,
		&challenge.TokenHash,
		&requiredJSON,
		&verifiedJSON,
		&challenge.EmailCodeHash,
		&challenge.ExpiresAt,
		&challenge.ConsumedAt,
		&challenge.DeviceID,
		&challenge.IPAddress,
		&challenge.UserAgent,
		&challenge.CreatedAt,
	); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(requiredJSON, &challenge.RequiredFactors); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(verifiedJSON, &challenge.VerifiedFactors); err != nil {
		return nil, err
	}
	return &challenge, nil
}
