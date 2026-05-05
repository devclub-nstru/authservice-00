package clients

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"kael/internal/security"
	"kael/internal/users"

	"github.com/google/uuid"
)

var (
	ErrClientNotFound = errors.New("client not found")
	ErrNotOwner       = errors.New("not the client owner")
	ErrNoRedirectURIs = errors.New("at least one redirect URI required")
	ErrInvalidURI     = errors.New("invalid redirect URI")
	ErrUserNotFound   = errors.New("user not found")
	ErrAlreadyMember  = errors.New("user is already a member")
)

type Service struct {
	repo      *Repository
	usersRepo *users.Repository
}

func NewService(repo *Repository, usersRepo *users.Repository) *Service {
	return &Service{repo: repo, usersRepo: usersRepo}
}

func (s *Service) Create(ctx context.Context, ownerID uuid.UUID, req CreateClientRequest) (*Client, string, []string, error) {
	if len(req.RedirectURIs) == 0 {
		return nil, "", nil, ErrNoRedirectURIs
	}
	for _, uri := range req.RedirectURIs {
		if err := validateRedirectURI(uri); err != nil {
			return nil, "", nil, fmt.Errorf("%w: %s", ErrInvalidURI, uri)
		}
	}

	clientIDSuffix, err := security.GenerateToken(24)
	if err != nil {
		return nil, "", nil, err
	}
	clientID := "kael_" + clientIDSuffix

	rawSecret, err := security.GenerateToken(48)
	if err != nil {
		return nil, "", nil, err
	}
	clientSecret := "kaelsec_" + rawSecret
	secretHash := security.HashToken(clientSecret)

	client := Client{
		OwnerID:          ownerID,
		ClientID:         clientID,
		ClientSecretHash: secretHash,
		Name:             req.Name,
		AvatarURL:        req.AvatarURL,
	}

	created, err := s.repo.Create(ctx, client, req.RedirectURIs)
	if err != nil {
		return nil, "", nil, err
	}

	return created, clientSecret, req.RedirectURIs, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID, ownerID uuid.UUID) (*Client, []string, error) {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, nil, ErrClientNotFound
	}
	if client.OwnerID != ownerID {
		return nil, nil, ErrNotOwner
	}
	uris, err := s.repo.ListRedirectURIs(ctx, client.ID)
	if err != nil {
		return nil, nil, err
	}
	return client, uris, nil
}

func (s *Service) List(ctx context.Context, ownerID uuid.UUID) ([]Client, error) {
	return s.repo.ListByOwner(ctx, ownerID)
}

func (s *Service) Update(ctx context.Context, id uuid.UUID, ownerID uuid.UUID, req UpdateClientRequest) error {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return ErrClientNotFound
	}
	if client.OwnerID != ownerID {
		return ErrNotOwner
	}

	if req.RedirectURIs != nil {
		if len(req.RedirectURIs) == 0 {
			return ErrNoRedirectURIs
		}
		for _, uri := range req.RedirectURIs {
			if err := validateRedirectURI(uri); err != nil {
				return fmt.Errorf("%w: %s", ErrInvalidURI, uri)
			}
		}
	}

	return s.repo.Update(ctx, id, req.Name, req.AvatarURL, req.RedirectURIs)
}

func (s *Service) RotateSecret(ctx context.Context, id uuid.UUID, ownerID uuid.UUID) (string, error) {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return "", ErrClientNotFound
	}
	if client.OwnerID != ownerID {
		return "", ErrNotOwner
	}

	rawSecret, err := security.GenerateToken(48)
	if err != nil {
		return "", err
	}
	clientSecret := "kaelsec_" + rawSecret
	secretHash := security.HashToken(clientSecret)

	if err := s.repo.UpdateSecretHash(ctx, id, secretHash); err != nil {
		return "", err
	}
	return clientSecret, nil
}

func (s *Service) Delete(ctx context.Context, id uuid.UUID, ownerID uuid.UUID) error {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return ErrClientNotFound
	}
	if client.OwnerID != ownerID {
		return ErrNotOwner
	}
	return s.repo.Delete(ctx, id)
}

func (s *Service) AddMember(ctx context.Context, clientPK uuid.UUID, ownerID uuid.UUID, email string, role string) (*MemberProfile, error) {
	client, err := s.repo.FindByID(ctx, clientPK)
	if err != nil {
		return nil, ErrClientNotFound
	}
	if client.OwnerID != ownerID {
		return nil, ErrNotOwner
	}

	user, err := s.usersRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, ErrUserNotFound
	}

	membership, err := s.repo.AddMember(ctx, clientPK, user.ID, role)
	if err != nil {
		return nil, ErrAlreadyMember
	}

	return &MemberProfile{
		UserID:    user.ID,
		Email:     user.Email,
		Name:      user.Name,
		AvatarURL: user.AvatarURL,
		Role:      membership.Role,
		JoinedAt:  membership.CreatedAt,
	}, nil
}

func (s *Service) RemoveMember(ctx context.Context, clientPK uuid.UUID, ownerID uuid.UUID, userID uuid.UUID) error {
	client, err := s.repo.FindByID(ctx, clientPK)
	if err != nil {
		return ErrClientNotFound
	}
	if client.OwnerID != ownerID {
		return ErrNotOwner
	}
	return s.repo.RemoveMember(ctx, clientPK, userID)
}

func (s *Service) ListMembers(ctx context.Context, clientPK uuid.UUID, ownerID uuid.UUID) ([]MemberProfile, error) {
	client, err := s.repo.FindByID(ctx, clientPK)
	if err != nil {
		return nil, ErrClientNotFound
	}
	if client.OwnerID != ownerID {
		return nil, ErrNotOwner
	}
	return s.repo.ListMembers(ctx, clientPK)
}

func validateRedirectURI(rawURI string) error {
	u, err := url.ParseRequestURI(rawURI)
	if err != nil {
		return err
	}
	if u.Scheme == "" || u.Host == "" {
		return errors.New("redirect URI must have scheme and host")
	}
	if u.Fragment != "" {
		return errors.New("redirect URI must not contain fragment")
	}
	return nil
}
