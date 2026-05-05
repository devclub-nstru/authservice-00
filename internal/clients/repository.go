package clients

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

func (r *Repository) Create(ctx context.Context, client Client, redirectURIs []string) (*Client, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	query := `
		INSERT INTO clients (owner_id, client_id, client_secret_hash, name, avatar_url)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, owner_id, client_id, client_secret_hash, name, avatar_url, created_at, updated_at`

	row := tx.QueryRow(ctx, query,
		client.OwnerID, client.ClientID, client.ClientSecretHash,
		client.Name, client.AvatarURL,
	)

	created, err := scanClient(row)
	if err != nil {
		return nil, err
	}

	for _, uri := range redirectURIs {
		_, err := tx.Exec(ctx,
			`INSERT INTO client_redirect_uris (client_id, uri) VALUES ($1, $2)`,
			created.ID, uri,
		)
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return created, nil
}

func (r *Repository) FindByID(ctx context.Context, id uuid.UUID) (*Client, error) {
	query := `
		SELECT id, owner_id, client_id, client_secret_hash, name, avatar_url, created_at, updated_at
		FROM clients WHERE id = $1`
	return scanClient(r.db.QueryRow(ctx, query, id))
}

func (r *Repository) FindByClientID(ctx context.Context, clientID string) (*Client, error) {
	query := `
		SELECT id, owner_id, client_id, client_secret_hash, name, avatar_url, created_at, updated_at
		FROM clients WHERE client_id = $1`
	return scanClient(r.db.QueryRow(ctx, query, clientID))
}

func (r *Repository) ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]Client, error) {
	query := `
		SELECT id, owner_id, client_id, client_secret_hash, name, avatar_url, created_at, updated_at
		FROM clients WHERE owner_id = $1 ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, *c)
	}
	return clients, rows.Err()
}

func (r *Repository) Update(ctx context.Context, id uuid.UUID, name *string, avatarURL *string, redirectURIs []string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if name != nil {
		_, err := tx.Exec(ctx,
			`UPDATE clients SET name = $2, updated_at = $3 WHERE id = $1`,
			id, *name, time.Now(),
		)
		if err != nil {
			return err
		}
	}

	if avatarURL != nil {
		_, err := tx.Exec(ctx,
			`UPDATE clients SET avatar_url = $2, updated_at = $3 WHERE id = $1`,
			id, *avatarURL, time.Now(),
		)
		if err != nil {
			return err
		}
	}

	if redirectURIs != nil {
		_, err := tx.Exec(ctx, `DELETE FROM client_redirect_uris WHERE client_id = $1`, id)
		if err != nil {
			return err
		}
		for _, uri := range redirectURIs {
			_, err := tx.Exec(ctx,
				`INSERT INTO client_redirect_uris (client_id, uri) VALUES ($1, $2)`,
				id, uri,
			)
			if err != nil {
				return err
			}
		}
	}

	return tx.Commit(ctx)
}

func (r *Repository) UpdateSecretHash(ctx context.Context, id uuid.UUID, hash string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE clients SET client_secret_hash = $2, updated_at = $3 WHERE id = $1`,
		id, hash, time.Now(),
	)
	return err
}

func (r *Repository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx, `DELETE FROM clients WHERE id = $1`, id)
	return err
}

func (r *Repository) ListRedirectURIs(ctx context.Context, clientPK uuid.UUID) ([]string, error) {
	rows, err := r.db.Query(ctx,
		`SELECT uri FROM client_redirect_uris WHERE client_id = $1`,
		clientPK,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var uris []string
	for rows.Next() {
		var uri string
		if err := rows.Scan(&uri); err != nil {
			return nil, err
		}
		uris = append(uris, uri)
	}
	return uris, rows.Err()
}

func (r *Repository) HasRedirectURI(ctx context.Context, clientPK uuid.UUID, uri string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM client_redirect_uris WHERE client_id = $1 AND uri = $2)`,
		clientPK, uri,
	).Scan(&exists)
	return exists, err
}

// Membership operations

func (r *Repository) AddMember(ctx context.Context, clientPK uuid.UUID, userID uuid.UUID, role string) (*Membership, error) {
	if role == "" {
		role = "member"
	}
	query := `
		INSERT INTO client_memberships (client_id, user_id, role)
		VALUES ($1, $2, $3)
		ON CONFLICT (client_id, user_id) DO NOTHING
		RETURNING id, client_id, user_id, role, created_at`

	var m Membership
	err := r.db.QueryRow(ctx, query, clientPK, userID, role).Scan(
		&m.ID, &m.ClientPK, &m.UserID, &m.Role, &m.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (r *Repository) RemoveMember(ctx context.Context, clientPK uuid.UUID, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM client_memberships WHERE client_id = $1 AND user_id = $2`,
		clientPK, userID,
	)
	return err
}

func (r *Repository) IsMember(ctx context.Context, clientPK uuid.UUID, userID uuid.UUID) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM client_memberships WHERE client_id = $1 AND user_id = $2)`,
		clientPK, userID,
	).Scan(&exists)
	return exists, err
}

func (r *Repository) ListMembers(ctx context.Context, clientPK uuid.UUID) ([]MemberProfile, error) {
	query := `
		SELECT u.id, u.email, u.name, u.avatar_url, m.role, m.created_at
		FROM client_memberships m
		JOIN users u ON m.user_id = u.id
		WHERE m.client_id = $1
		ORDER BY m.created_at ASC`

	rows, err := r.db.Query(ctx, query, clientPK)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []MemberProfile
	for rows.Next() {
		var mp MemberProfile
		if err := rows.Scan(&mp.UserID, &mp.Email, &mp.Name, &mp.AvatarURL, &mp.Role, &mp.JoinedAt); err != nil {
			return nil, err
		}
		members = append(members, mp)
	}
	return members, rows.Err()
}

func (r *Repository) ListConnectedByUser(ctx context.Context, userID uuid.UUID) ([]ConnectedClient, error) {
	query := `
		SELECT c.id, c.client_id, c.name, c.avatar_url, m.role, m.created_at
		FROM client_memberships m
		JOIN clients c ON m.client_id = c.id
		WHERE m.user_id = $1
		ORDER BY m.created_at DESC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []ConnectedClient
	for rows.Next() {
		var cc ConnectedClient
		if err := rows.Scan(&cc.ID, &cc.ClientID, &cc.Name, &cc.AvatarURL, &cc.Role, &cc.ConnectedAt); err != nil {
			return nil, err
		}
		clients = append(clients, cc)
	}
	return clients, rows.Err()
}

func scanClient(row pgx.Row) (*Client, error) {
	var c Client
	if err := row.Scan(
		&c.ID, &c.OwnerID, &c.ClientID, &c.ClientSecretHash,
		&c.Name, &c.AvatarURL, &c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &c, nil
}
