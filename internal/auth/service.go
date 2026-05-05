package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"kael/internal/config"
	"kael/internal/email"
	"kael/internal/mfa"
	"kael/internal/ques"
	"kael/internal/security"
	"kael/internal/sessions"
	"kael/internal/tokens"
	"kael/internal/users"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5"
)

const (
	emailVerificationTTL = 24 * time.Hour
	passwordResetTTL     = 30 * time.Minute
)

var (
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrPasswordDisabled   = errors.New("password login disabled")
	ErrPasswordAlreadySet = errors.New("password already set")
	ErrMFARequired        = errors.New("mfa required")
	ErrMFANotConfigured   = errors.New("mfa not configured")
	ErrEmailNotVerified   = errors.New("email not verified")
)

type Service struct {
	cfg        *config.Config
	usersRepo  *users.Repository
	sessions   *sessions.Service
	mfaRepo    *mfa.Repository
	tokensRepo *tokens.Repository
	oauthLister OAuthProviderLister
	asynq      *asynq.Client
	totpKey    []byte
}

type OAuthProviderLister interface {
	ListProvidersByUser(ctx context.Context, userID uuid.UUID) ([]string, error)
}

type Profile struct {
	User          *users.User
	MFAEnabled    []string
	OAuthAccounts []string
}

type LoginResult struct {
	User          *users.User
	MFARequired   bool
	MFAToken      string
	MFAMethods    []string
	SessionToken  string
	SessionExpiry time.Time
}

func NewService(cfg *config.Config, usersRepo *users.Repository, sessionsService *sessions.Service, mfaRepo *mfa.Repository, tokensRepo *tokens.Repository, oauthLister OAuthProviderLister, asynqClient *asynq.Client) (*Service, error) {
	var key []byte
	var err error
	if cfg.TOTPEncryptionKey != "" {
		key, err = security.DecodeBase64Key(cfg.TOTPEncryptionKey)
		if err != nil {
			return nil, err
		}
	}

	return &Service{
		cfg:        cfg,
		usersRepo:  usersRepo,
		sessions:   sessionsService,
		mfaRepo:    mfaRepo,
		tokensRepo: tokensRepo,
		oauthLister: oauthLister,
		asynq:      asynqClient,
		totpKey:    key,
	}, nil
}

func (s *Service) GetProfile(ctx context.Context, userID uuid.UUID) (*Profile, error) {
	user, err := s.usersRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	factors, err := s.mfaRepo.ListEnabled(ctx, userID)
	if err != nil {
		return nil, err
	}
	mfaMethods := make([]string, 0, len(factors))
	for _, f := range factors {
		mfaMethods = append(mfaMethods, f.FactorType)
	}

	providers, err := s.oauthLister.ListProvidersByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &Profile{
		User:          user,
		MFAEnabled:    mfaMethods,
		OAuthAccounts: providers,
	}, nil
}

func (s *Service) Signup(ctx context.Context, req SignupRequest) (*users.User, error) {
	if err := security.ValidatePassword(req.Password); err != nil {
		return nil, err
	}
	if _, err := s.usersRepo.FindByEmail(ctx, req.Email); err == nil {
		return nil, ErrUserExists
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	passwordHash, err := security.HashPassword(req.Password, s.cfg.BcryptCost)
	if err != nil {
		return nil, err
	}

	var name *string
	if req.Name != "" {
		name = &req.Name
	}

	user, err := s.usersRepo.Create(ctx, users.CreateUserParams{
		Email:           req.Email,
		EmailVerified:   false,
		PasswordHash:    &passwordHash,
		PasswordEnabled: true,
		Name:            name,
	})
	if err != nil {
		return nil, err
	}

	if err := s.sendVerificationEmail(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *Service) Login(ctx context.Context, req LoginRequest, deviceID string, ipAddress string, userAgent string) (*LoginResult, error) {
	user, err := s.usersRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if !user.PasswordEnabled || user.PasswordHash == nil {
		return nil, ErrPasswordDisabled
	}

	if err := security.ComparePassword(*user.PasswordHash, req.Password); err != nil {
		return nil, ErrInvalidCredentials
	}

	return s.CompleteLogin(ctx, user, deviceID, ipAddress, userAgent)
}

func (s *Service) CompleteLogin(ctx context.Context, user *users.User, deviceID string, ipAddress string, userAgent string) (*LoginResult, error) {
	if !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	_ = s.usersRepo.UpdateLastLogin(ctx, user.ID)

	factors, err := s.mfaRepo.ListEnabled(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if len(factors) == 0 {
		session, token, err := s.sessions.Create(ctx, user.ID, deviceID, ipAddress, userAgent)
		if err != nil {
			return nil, err
		}
		return &LoginResult{
			User:          user,
			SessionToken:  token,
			SessionExpiry: session.ExpiresAt,
		}, nil
	}

	challengeToken, methods, err := s.createMFAChallenge(ctx, user, deviceID, ipAddress, userAgent, factors)
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		User:        user,
		MFARequired: true,
		MFAToken:    challengeToken,
		MFAMethods:  methods,
	}, nil
}

func (s *Service) VerifyMFA(ctx context.Context, challengeToken string, factor string, code string) (*LoginResult, error) {
	challengeHash := security.HashToken(challengeToken)
	challenge, err := s.mfaRepo.FindChallengeByTokenHash(ctx, challengeHash)
	if err != nil {
		return nil, ErrMFANotConfigured
	}

	user, err := s.usersRepo.FindByID(ctx, challenge.UserID)
	if err != nil {
		return nil, err
	}

	if !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	if challenge.ConsumedAt != nil || time.Now().After(challenge.ExpiresAt) {
		return nil, ErrMFANotConfigured
	}

	if !containsFactor(challenge.RequiredFactors, factor) {
		return nil, ErrMFANotConfigured
	}

	if containsFactor(challenge.VerifiedFactors, factor) {
		return nil, ErrMFANotConfigured
	}

	switch factor {
	case "email":
		if challenge.EmailCodeHash == nil {
			return nil, ErrMFANotConfigured
		}
		if security.HashToken(code+":"+challengeToken) != *challenge.EmailCodeHash {
			return nil, mfa.ErrInvalidCode
		}
	case "totp":
		if s.totpKey == nil {
			return nil, ErrMFANotConfigured
		}
		factorRecord, err := s.mfaRepo.GetFactor(ctx, challenge.UserID, "totp")
		if err != nil {
			return nil, ErrMFANotConfigured
		}
		secret, err := security.Decrypt(s.totpKey, factorRecord.SecretEncrypted)
		if err != nil {
			return nil, err
		}
		if !mfa.VerifyTOTP(string(secret), code) {
			return nil, mfa.ErrInvalidCode
		}
	default:
		return nil, ErrMFANotConfigured
	}

	updated := append(challenge.VerifiedFactors, factor)
	var consumedAt *time.Time
	// Any single verified factor satisfies the MFA requirement
	if len(updated) > 0 {
		now := time.Now()
		consumedAt = &now
	}

	if err := s.mfaRepo.UpdateChallenge(ctx, challenge.ID, updated, consumedAt); err != nil {
		return nil, err
	}

	if consumedAt == nil {
		return &LoginResult{
			User:        user,
			MFARequired: true,
			MFAToken:    challengeToken,
			MFAMethods:  remainingFactors(challenge.RequiredFactors, updated),
		}, nil
	}

	if challenge.DeviceID == nil {
		return nil, ErrMFANotConfigured
	}
	deviceID := *challenge.DeviceID
	var ipAddress string
	var userAgent string
	if challenge.IPAddress != nil {
		ipAddress = *challenge.IPAddress
	}
	if challenge.UserAgent != nil {
		userAgent = *challenge.UserAgent
	}

	session, token, err := s.sessions.Create(ctx, challenge.UserID, deviceID, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		User:          user,
		SessionToken:  token,
		SessionExpiry: session.ExpiresAt,
	}, nil
}

func (s *Service) TriggerMFA(ctx context.Context, challengeToken string, factor string) error {
	challengeHash := security.HashToken(challengeToken)
	challenge, err := s.mfaRepo.FindChallengeByTokenHash(ctx, challengeHash)
	if err != nil {
		return ErrMFANotConfigured
	}

	if challenge.ConsumedAt != nil || time.Now().After(challenge.ExpiresAt) {
		return ErrMFANotConfigured
	}

	if factor != "email" {
		return errors.New("unsupported factor trigger")
	}

	user, err := s.usersRepo.FindByID(ctx, challenge.UserID)
	if err != nil {
		return err
	}

	code, err := security.GenerateNumericCode(6)
	if err != nil {
		return err
	}

	hash := security.HashToken(code + ":" + challengeToken)
	expiresAt := time.Now().Add(s.cfg.EmailOTPTTL)
	if err := s.mfaRepo.UpdateEmailCode(ctx, challenge.ID, hash, expiresAt); err != nil {
		return err
	}

	return s.enqueueEmail(ctx, ques.TaskEmailOTP, email.TaskPayload{
		To:      user.Email,
		Subject: "Your login code",
		Text:    fmt.Sprintf("Your login code is %s", code),
	})
}

func (s *Service) Refresh(ctx context.Context, token string, deviceID string) (*LoginResult, error) {
	session, err := s.sessions.Validate(ctx, token, deviceID)
	if err != nil {
		return nil, err
	}
	newToken, err := s.sessions.Rotate(ctx, session.ID)
	if err != nil {
		return nil, err
	}
	user, err := s.usersRepo.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		User:          user,
		SessionToken:  newToken,
		SessionExpiry: time.Now().Add(s.cfg.SessionRefreshTTL),
	}, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	return s.sessions.RevokeByToken(ctx, token)
}

func (s *Service) SendPasswordReset(ctx context.Context, emailAddr string) error {
	user, err := s.usersRepo.FindByEmail(ctx, emailAddr)
	if err != nil {
		return nil
	}
	if !user.PasswordEnabled {
		return nil
	}

	resetToken, err := security.GenerateToken(32)
	if err != nil {
		return err
	}

	hash := security.HashToken(resetToken)
	expiresAt := time.Now().Add(passwordResetTTL)
	if err := s.tokensRepo.CreatePasswordReset(ctx, user.ID, hash, expiresAt); err != nil {
		return err
	}

	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.cfg.FrontendBaseURL, resetToken)
	return s.enqueueEmail(ctx, ques.TaskPasswordReset, email.TaskPayload{
		To:      user.Email,
		Subject: "Reset your password",
		Text:    fmt.Sprintf("Reset your password: %s", resetURL),
	})
}

func (s *Service) ResetPassword(ctx context.Context, token string, newPassword string) error {
	if err := security.ValidatePassword(newPassword); err != nil {
		return err
	}
	hash := security.HashToken(token)
	userID, err := s.tokensRepo.ConsumePasswordReset(ctx, hash)
	if err != nil {
		return err
	}

	passwordHash, err := security.HashPassword(newPassword, s.cfg.BcryptCost)
	if err != nil {
		return err
	}

	return s.usersRepo.SetPassword(ctx, userID, passwordHash, true)
}

func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, current string, next string) error {
	if err := security.ValidatePassword(next); err != nil {
		return err
	}
	user, err := s.usersRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.PasswordHash == nil {
		return ErrPasswordDisabled
	}
	if err := security.ComparePassword(*user.PasswordHash, current); err != nil {
		return ErrInvalidCredentials
	}

	passwordHash, err := security.HashPassword(next, s.cfg.BcryptCost)
	if err != nil {
		return err
	}
	return s.usersRepo.SetPassword(ctx, userID, passwordHash, true)
}

func (s *Service) SetPassword(ctx context.Context, userID uuid.UUID, password string) error {
	if err := security.ValidatePassword(password); err != nil {
		return err
	}
	user, err := s.usersRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.PasswordEnabled {
		return ErrPasswordAlreadySet
	}
	passwordHash, err := security.HashPassword(password, s.cfg.BcryptCost)
	if err != nil {
		return err
	}
	return s.usersRepo.SetPassword(ctx, userID, passwordHash, true)
}

func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	hash := security.HashToken(token)
	userID, err := s.tokensRepo.ConsumeEmailVerification(ctx, hash)
	if err != nil {
		return err
	}
	return s.usersRepo.VerifyEmail(ctx, userID)
}

func (s *Service) ResendVerification(ctx context.Context, emailAddr string) error {
	user, err := s.usersRepo.FindByEmail(ctx, emailAddr)
	if err != nil {
		return nil
	}
	if user.EmailVerified {
		return nil
	}
	return s.sendVerificationEmail(ctx, user)
}

func (s *Service) UpdateEmail(ctx context.Context, userID uuid.UUID, emailAddr string) error {
	if existing, err := s.usersRepo.FindByEmail(ctx, emailAddr); err == nil {
		if existing.ID != userID {
			return ErrUserExists
		}
	}
	if err := s.usersRepo.UpdateEmail(ctx, userID, emailAddr); err != nil {
		return err
	}
	user, err := s.usersRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	return s.sendVerificationEmail(ctx, user)
}

func (s *Service) EnableEmailMFA(ctx context.Context, userID uuid.UUID) error {
	_, err := s.mfaRepo.UpsertFactor(ctx, userID, "email", nil, true)
	return err
}

func (s *Service) DisableEmailMFA(ctx context.Context, userID uuid.UUID) error {
	return s.mfaRepo.Disable(ctx, userID, "email")
}

func (s *Service) EnableTOTP(ctx context.Context, userID uuid.UUID, emailAddr string) (string, string, error) {
	if s.totpKey == nil {
		return "", "", ErrMFANotConfigured
	}
	secret, url, err := mfa.GenerateTOTPSecret(emailAddr)
	if err != nil {
		return "", "", err
	}
	enc, err := security.Encrypt(s.totpKey, []byte(secret))
	if err != nil {
		return "", "", err
	}
	if _, err := s.mfaRepo.UpsertFactor(ctx, userID, "totp", enc, false); err != nil {
		return "", "", err
	}
	return secret, url, nil
}

func (s *Service) VerifyTOTP(ctx context.Context, userID uuid.UUID, code string) error {
	if s.totpKey == nil {
		return ErrMFANotConfigured
	}
	factor, err := s.mfaRepo.GetFactor(ctx, userID, "totp")
	if err != nil {
		return ErrMFANotConfigured
	}
	secret, err := security.Decrypt(s.totpKey, factor.SecretEncrypted)
	if err != nil {
		return err
	}
	if !mfa.VerifyTOTP(string(secret), code) {
		return mfa.ErrInvalidCode
	}
	return s.mfaRepo.Enable(ctx, userID, "totp")
}

func (s *Service) DisableTOTP(ctx context.Context, userID uuid.UUID) error {
	return s.mfaRepo.Disable(ctx, userID, "totp")
}

func (s *Service) sendVerificationEmail(ctx context.Context, user *users.User) error {
	verifyToken, err := security.GenerateToken(32)
	if err != nil {
		return err
	}
	hash := security.HashToken(verifyToken)
	expires := time.Now().Add(emailVerificationTTL)
	if err := s.tokensRepo.CreateEmailVerification(ctx, user.ID, hash, expires); err != nil {
		return err
	}

	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", s.cfg.FrontendBaseURL, verifyToken)
	return s.enqueueEmail(ctx, ques.TaskEmailVerification, email.TaskPayload{
		To:      user.Email,
		Subject: "Verify your email",
		Text:    fmt.Sprintf("Verify your email: %s", verifyURL),
	})
}

func (s *Service) createMFAChallenge(ctx context.Context, user *users.User, deviceID string, ipAddress string, userAgent string, factors []mfa.Factor) (string, []string, error) {
	challengeToken, err := security.GenerateToken(24)
	if err != nil {
		return "", nil, err
	}

	var methods []string
	var emailCodeHash *string
	hasOtherFactors := false
	for _, factor := range factors {
		if factor.FactorType != "email" {
			hasOtherFactors = true
			break
		}
	}

	for _, factor := range factors {
		methods = append(methods, factor.FactorType)
		if factor.FactorType == "email" {
			code, err := security.GenerateNumericCode(6)
			if err != nil {
				return "", nil, err
			}
			hash := security.HashToken(code + ":" + challengeToken)
			emailCodeHash = &hash

			// Only send immediately if email is the only factor
			if !hasOtherFactors {
				if err := s.enqueueEmail(ctx, ques.TaskEmailOTP, email.TaskPayload{
					To:      user.Email,
					Subject: "Your login code",
					Text:    fmt.Sprintf("Your login code is %s", code),
				}); err != nil {
					return "", nil, err
				}
			}
		}
	}

	device := deviceID
	ip := ipAddress
	ua := userAgent

	challenge := mfa.Challenge{
		UserID:          user.ID,
		TokenHash:       security.HashToken(challengeToken),
		RequiredFactors: methods,
		VerifiedFactors: []string{},
		EmailCodeHash:   emailCodeHash,
		ExpiresAt:       time.Now().Add(s.cfg.EmailOTPTTL),
		DeviceID:        &device,
		IPAddress:       &ip,
		UserAgent:       &ua,
	}

	if _, err := s.mfaRepo.CreateChallenge(ctx, challenge); err != nil {
		return "", nil, err
	}

	return challengeToken, methods, nil
}

func (s *Service) enqueueEmail(ctx context.Context, taskType string, payload email.TaskPayload) error {
	if s.asynq == nil {
		return errors.New("asynq not configured")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, err = s.asynq.Enqueue(asynq.NewTask(taskType, data), asynq.Queue(ques.QueueDefault), asynq.MaxRetry(5))
	return err
}

func containsFactor(items []string, factor string) bool {
	for _, item := range items {
		if item == factor {
			return true
		}
	}
	return false
}

func hasAllFactors(required []string, verified []string) bool {
	for _, item := range required {
		if !containsFactor(verified, item) {
			return false
		}
	}
	return true
}

func remainingFactors(required []string, verified []string) []string {
	var remaining []string
	for _, item := range required {
		if !containsFactor(verified, item) {
			remaining = append(remaining, item)
		}
	}
	return remaining
}
