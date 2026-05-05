package sessions

import (
	"context"
	"errors"
	"time"

	"kael/internal/config"
	"kael/internal/security"

	"github.com/google/uuid"
)

var (
	ErrSessionExpired   = errors.New("session expired")
	ErrSessionInvalid   = errors.New("session invalid")
	ErrMFAPending       = errors.New("mfa pending")
	ErrEmailNotVerified = errors.New("email not verified")
)

type Service struct {
	repo *Repository
	cfg  *config.Config
}

func NewService(repo *Repository, cfg *config.Config) *Service {
	return &Service{repo: repo, cfg: cfg}
}

func (s *Service) Create(ctx context.Context, userID uuid.UUID, deviceID string, ipAddress string, userAgent string) (*Session, string, error) {
	if err := s.repo.RevokeActiveByUserDevice(ctx, userID, deviceID); err != nil {
		return nil, "", err
	}

	token, err := security.GenerateToken(32)
	if err != nil {
		return nil, "", err
	}

	hash := security.HashToken(token)
	var ipPtr *string
	var uaPtr *string
	if ipAddress != "" {
		ipPtr = &ipAddress
	}
	if userAgent != "" {
		uaPtr = &userAgent
	}

	session := Session{
		UserID:     userID,
		DeviceID:   deviceID,
		TokenHash:  hash,
		IPAddress:  ipPtr,
		UserAgent:  uaPtr,
		ExpiresAt:  time.Now().Add(s.cfg.SessionTTL),
		IsActive:   true,
		MFAPending: false,
	}

	created, err := s.repo.Create(ctx, session)
	if err != nil {
		return nil, "", err
	}

	return created, token, nil
}

func (s *Service) Validate(ctx context.Context, token string, deviceID string) (*Session, error) {
	hash := security.HashToken(token)
	session, err := s.repo.FindByTokenHash(ctx, hash)
	if err != nil {
		return nil, ErrSessionInvalid
	}

	if session.DeviceID != deviceID || !session.IsActive || session.RevokedAt != nil {
		return nil, ErrSessionInvalid
	}

	if session.MFAPending {
		return nil, ErrMFAPending
	}

	if !session.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	now := time.Now()
	if s.cfg.SessionIdleTTL > 0 && now.Sub(session.LastSeenAt) > s.cfg.SessionIdleTTL {
		_ = s.repo.RevokeByTokenHash(ctx, hash)
		return nil, ErrSessionExpired
	}

	if now.After(session.ExpiresAt) {
		_ = s.repo.RevokeByTokenHash(ctx, hash)
		return nil, ErrSessionExpired
	}

	_ = s.repo.UpdateLastSeen(ctx, session.ID)
	return session, nil
}

func (s *Service) Rotate(ctx context.Context, sessionID uuid.UUID) (string, error) {
	token, err := security.GenerateToken(32)
	if err != nil {
		return "", err
	}

	hash := security.HashToken(token)
	expires := time.Now().Add(s.cfg.SessionRefreshTTL)
	if err := s.repo.RotateToken(ctx, sessionID, hash, expires); err != nil {
		return "", err
	}

	return token, nil
}

func (s *Service) Revoke(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) error {
	return s.repo.RevokeByID(ctx, userID, sessionID)
}

func (s *Service) RevokeByToken(ctx context.Context, token string) error {
	hash := security.HashToken(token)
	return s.repo.RevokeByTokenHash(ctx, hash)
}

func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	return s.repo.ListByUser(ctx, userID)
}
