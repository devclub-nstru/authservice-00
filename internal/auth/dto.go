package auth

import "kael/internal/users"

type SignupRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	Name     string `json:"name" binding:"omitempty"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type PasswordForgotRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type PasswordResetRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8"`
}

type PasswordSetRequest struct {
	Password string `json:"password" binding:"required,min=8"`
}

type EmailVerifyRequest struct {
	Token string `json:"token" binding:"required"`
}

type EmailResendRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type EmailUpdateRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type MFAVerifyRequest struct {
	ChallengeToken string `json:"challenge_token" binding:"required"`
	Factor         string `json:"factor" binding:"required"`
	Code           string `json:"code" binding:"required"`
}

type MFATriggerRequest struct {
	ChallengeToken string `json:"challenge_token" binding:"required"`
	Factor         string `json:"factor" binding:"required"`
}

type UserResponse struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	EmailVerified bool    `json:"email_verified"`
	Name          *string  `json:"name,omitempty"`
	AvatarURL     *string  `json:"avatar_url,omitempty"`
	MFAEnabled    []string `json:"mfa_enabled"`
	OAuthAccounts []string `json:"oauth_accounts"`
}

type AuthResponse struct {
	User         UserResponse `json:"user"`
	MFARequired  bool         `json:"mfa_required"`
	MFAToken     string       `json:"mfa_token,omitempty"`
	MFAMethods   []string     `json:"mfa_methods,omitempty"`
	SessionToken string       `json:"-"`
}

func mapUser(user *users.User) UserResponse {
	return UserResponse{
		ID:            user.ID.String(),
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.Name,
		AvatarURL:     user.AvatarURL,
		MFAEnabled:    []string{},
		OAuthAccounts: []string{},
	}
}

func mapProfile(profile *Profile) UserResponse {
	res := mapUser(profile.User)
	res.MFAEnabled = profile.MFAEnabled
	res.OAuthAccounts = profile.OAuthAccounts
	return res
}
