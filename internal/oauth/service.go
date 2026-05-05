package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"kael/internal/config"
	"kael/internal/security"
	"kael/internal/users"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

const (
	ModeLogin = "login"
	ModeLink  = "link"
)

var ErrOAuthStateInvalid = errors.New("oauth state invalid")

// ProviderUser captures normalized OAuth profile data.
type ProviderUser struct {
	Provider       string
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
	AvatarURL      string
}

type Service struct {
	cfg       *config.Config
	repo      *Repository
	usersRepo *users.Repository
	redis     *redis.Client
	client    *http.Client
}

func NewService(cfg *config.Config, repo *Repository, usersRepo *users.Repository, redisClient *redis.Client) *Service {
	return &Service{
		cfg:       cfg,
		repo:      repo,
		usersRepo: usersRepo,
		redis:     redisClient,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *Service) StartAuth(provider string, mode string, userID *uuid.UUID, deviceID string, ipAddress string, userAgent string) (string, error) {
	state, err := security.GenerateToken(16)
	if err != nil {
		return "", err
	}
	if s.redis == nil {
		return "", errors.New("redis not configured")
	}

	payload := map[string]string{
		"provider":   provider,
		"mode":       mode,
		"device_id":  deviceID,
		"ip_address": ipAddress,
		"user_agent": userAgent,
	}
	if userID != nil {
		payload["user_id"] = userID.String()
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	key := s.stateKey(state)
	if err := s.redis.Set(context.Background(), key, encoded, s.cfg.OAuthStateTTL).Err(); err != nil {
		return "", err
	}

	config, err := s.oauthConfig(provider)
	if err != nil {
		return "", err
	}

	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return url, nil
}

func (s *Service) HandleCallback(ctx context.Context, provider string, code string, state string) (*users.User, bool, string, string, string, error) {
	statePayload, err := s.consumeState(state)
	if err != nil {
		return nil, false, "", "", "", err
	}

	if statePayload["provider"] != provider {
		return nil, false, "", "", "", ErrOAuthStateInvalid
	}

	config, err := s.oauthConfig(provider)
	if err != nil {
		return nil, false, "", "", "", err
	}

	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, false, "", "", "", err
	}

	userInfo, err := s.fetchUserInfo(provider, token)
	if err != nil {
		return nil, false, "", "", "", err
	}
	if userInfo.Email == "" {
		return nil, false, "", "", "", errors.New("oauth provider did not return email")
	}

	mode := statePayload["mode"]
	if mode == ModeLink {
		userID, err := uuid.Parse(statePayload["user_id"])
		if err != nil {
			return nil, false, "", "", "", err
		}
		user, linked, err := s.linkAccount(ctx, userID, userInfo)
		return user, linked, statePayload["device_id"], statePayload["ip_address"], statePayload["user_agent"], err
	}

	user, created, err := s.loginOrCreate(ctx, userInfo)
	return user, created, statePayload["device_id"], statePayload["ip_address"], statePayload["user_agent"], err
}

func (s *Service) ListProvidersByUser(ctx context.Context, userID uuid.UUID) ([]string, error) {
	accounts, err := s.repo.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	providers := make([]string, 0, len(accounts))
	for _, a := range accounts {
		providers = append(providers, a.Provider)
	}
	return providers, nil
}

func (s *Service) loginOrCreate(ctx context.Context, userInfo *ProviderUser) (*users.User, bool, error) {
	account, err := s.repo.FindByProviderUserID(ctx, userInfo.Provider, userInfo.ProviderUserID)
	if err == nil {
		user, err := s.usersRepo.FindByID(ctx, account.UserID)
		return user, false, err
	}

	if s.cfg.OAuthAutoLink && userInfo.EmailVerified {
		user, err := s.usersRepo.FindByEmail(ctx, userInfo.Email)
		if err == nil {
			_, err = s.repo.Create(ctx, Account{
				UserID:         user.ID,
				Provider:       userInfo.Provider,
				ProviderUserID: userInfo.ProviderUserID,
				Email:          &userInfo.Email,
				EmailVerified:  userInfo.EmailVerified,
			})
			if err == nil && !user.EmailVerified {
				_ = s.usersRepo.VerifyEmail(ctx, user.ID)
			}
			return user, false, err
		}
	}

	name := userInfo.Name
	avatar := userInfo.AvatarURL
	newUser, err := s.usersRepo.Create(ctx, users.CreateUserParams{
		Email:           userInfo.Email,
		EmailVerified:   userInfo.EmailVerified,
		PasswordEnabled: false,
		Name:            &name,
		AvatarURL:       &avatar,
	})
	if err != nil {
		return nil, false, err
	}

	_, err = s.repo.Create(ctx, Account{
		UserID:         newUser.ID,
		Provider:       userInfo.Provider,
		ProviderUserID: userInfo.ProviderUserID,
		Email:          &userInfo.Email,
		EmailVerified:  userInfo.EmailVerified,
	})
	if err != nil {
		return nil, false, err
	}

	return newUser, true, nil
}

func (s *Service) linkAccount(ctx context.Context, userID uuid.UUID, userInfo *ProviderUser) (*users.User, bool, error) {
	if _, err := s.repo.FindByProviderUserID(ctx, userInfo.Provider, userInfo.ProviderUserID); err == nil {
		return nil, false, fmt.Errorf("oauth account already linked")
	}

	user, err := s.usersRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, false, err
	}

	_, err = s.repo.Create(ctx, Account{
		UserID:         user.ID,
		Provider:       userInfo.Provider,
		ProviderUserID: userInfo.ProviderUserID,
		Email:          &userInfo.Email,
		EmailVerified:  userInfo.EmailVerified,
	})
	if err != nil {
		return nil, false, err
	}

	if userInfo.EmailVerified && !user.EmailVerified {
		_ = s.usersRepo.VerifyEmail(ctx, user.ID)
	}

	return user, false, nil
}

func (s *Service) consumeState(state string) (map[string]string, error) {
	if s.redis == nil || state == "" {
		return nil, ErrOAuthStateInvalid
	}

	key := s.stateKey(state)
	data, err := s.redis.Get(context.Background(), key).Result()
	if err != nil {
		return nil, ErrOAuthStateInvalid
	}

	_ = s.redis.Del(context.Background(), key).Err()

	var payload map[string]string
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return nil, ErrOAuthStateInvalid
	}
	return payload, nil
}

func (s *Service) stateKey(state string) string {
	return fmt.Sprintf("oauth:state:%s", state)
}

func (s *Service) oauthConfig(provider string) (*oauth2.Config, error) {
	switch provider {
	case "google":
		if s.cfg.GoogleClientID == "" || s.cfg.GoogleClientSecret == "" {
			return nil, errors.New("google oauth credentials missing")
		}
		return &oauth2.Config{
			ClientID:     s.cfg.GoogleClientID,
			ClientSecret: s.cfg.GoogleClientSecret,
			RedirectURL:  fmt.Sprintf("%s/oauth/google/callback", s.cfg.APIBaseURL),
			Scopes:       []string{"email", "profile"},
			Endpoint:     google.Endpoint,
		}, nil
	case "github":
		if s.cfg.GitHubClientID == "" || s.cfg.GitHubClientSecret == "" {
			return nil, errors.New("github oauth credentials missing")
		}
		return &oauth2.Config{
			ClientID:     s.cfg.GitHubClientID,
			ClientSecret: s.cfg.GitHubClientSecret,
			RedirectURL:  fmt.Sprintf("%s/oauth/github/callback", s.cfg.APIBaseURL),
			Scopes:       []string{"user:email"},
			Endpoint:     github.Endpoint,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (s *Service) fetchUserInfo(provider string, token *oauth2.Token) (*ProviderUser, error) {
	switch provider {
	case "google":
		return s.fetchGoogleUser(token)
	case "github":
		return s.fetchGitHubUser(token)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

type googleUser struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func (s *Service) fetchGoogleUser(token *oauth2.Token) (*ProviderUser, error) {
	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(token))
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo?alt=json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var gu googleUser
	if err := json.NewDecoder(resp.Body).Decode(&gu); err != nil {
		return nil, err
	}

	return &ProviderUser{
		Provider:       "google",
		ProviderUserID: gu.ID,
		Email:          gu.Email,
		EmailVerified:  gu.VerifiedEmail,
		Name:           gu.Name,
		AvatarURL:      gu.Picture,
	}, nil
}

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
	Email     string `json:"email"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (s *Service) fetchGitHubUser(token *oauth2.Token) (*ProviderUser, error) {
	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(token))
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var gu githubUser
	if err := json.NewDecoder(resp.Body).Decode(&gu); err != nil {
		return nil, err
	}

	email := gu.Email
	verified := false
	if email == "" {
		emailResp, err := client.Get("https://api.github.com/user/emails")
		if err != nil {
			return nil, err
		}
		defer emailResp.Body.Close()

		var emails []githubEmail
		if err := json.NewDecoder(emailResp.Body).Decode(&emails); err != nil {
			return nil, err
		}
		for _, e := range emails {
			if e.Primary {
				email = e.Email
				verified = e.Verified
				break
			}
		}
	} else {
		verified = true
	}

	return &ProviderUser{
		Provider:       "github",
		ProviderUserID: fmt.Sprintf("%d", gu.ID),
		Email:          email,
		EmailVerified:  verified,
		Name:           gu.Name,
		AvatarURL:      gu.AvatarURL,
	}, nil
}
