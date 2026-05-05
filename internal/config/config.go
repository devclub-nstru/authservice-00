package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	AppEnv            string
	DatabaseURL       string
	Port              string
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	ConnectTimeout    time.Duration

	RedisURL      string
	RedisAddr     string
	RedisPassword string
	RedisDB       int

	SessionCookieName     string
	SessionCookieDomain   string
	SessionCookieSecure   bool
	SessionCookieSameSite string
	SessionTTL            time.Duration
	SessionRefreshTTL     time.Duration
	SessionIdleTTL        time.Duration

	BcryptCost int

	FrontendBaseURL    string
	APIBaseURL         string
	OAuthAutoLink      bool
	OAuthStateTTL      time.Duration
	GoogleClientID     string
	GoogleClientSecret string
	GitHubClientID     string
	GitHubClientSecret string

	SMTPHost      string
	SMTPPort      int
	SMTPUser      string
	SMTPPassword  string
	SMTPFromName  string
	SMTPFromEmail string
	SMTPUseTLS    bool

	EmailOTPTTL       time.Duration
	TOTPEncryptionKey string

	AuthRateLimitPerMinute  int
	LoginRateLimitPerMinute int
	MfaRateLimitPerMinute   int
	AsynqWorkerConcurrency  int

	OIDCPrivateKeyPath  string
	OIDCCodeTTL         time.Duration
	OIDCAccessTokenTTL  time.Duration
	OIDCRefreshTokenTTL time.Duration
	OIDCIssuer          string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{
		AppEnv:      getString("APP_ENV", "development"),
		DatabaseURL: getString("DATABASE_URL", ""),
		Port:        getString("PORT", "8080"),

		MaxConns: getInt32("MAX_CONNS", 20),
		MinConns: getInt32("MIN_CONNS", 5),

		MaxConnLifetime:   getDuration("MAX_CONN_LIFETIME", time.Hour),
		MaxConnIdleTime:   getDuration("MAX_CONN_IDLE_TIME", 15*time.Minute),
		HealthCheckPeriod: getDuration("HEALTH_CHECK_PERIOD", time.Minute),
		ConnectTimeout:    getDuration("CONNECT_TIMEOUT", 5*time.Second),

		RedisURL:      getString("REDIS_URL", ""),
		RedisAddr:     getString("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getString("REDIS_PASSWORD", ""),
		RedisDB:       getInt("REDIS_DB", 0),

		SessionCookieName:     getString("SESSION_COOKIE_NAME", "kael_session"),
		SessionCookieDomain:   getString("SESSION_COOKIE_DOMAIN", ""),
		SessionCookieSecure:   getBool("SESSION_COOKIE_SECURE", true),
		SessionCookieSameSite: getString("SESSION_COOKIE_SAMESITE", "Lax"),
		SessionTTL:            getDuration("SESSION_TTL", 24*time.Hour),
		SessionRefreshTTL:     getDuration("SESSION_REFRESH_TTL", 24*time.Hour),
		SessionIdleTTL:        getDuration("SESSION_IDLE_TTL", 30*time.Minute),

		BcryptCost: getInt("BCRYPT_COST", 12),

		FrontendBaseURL:    getString("FRONTEND_BASE_URL", "http://localhost:3000"),
		APIBaseURL:         getString("API_BASE_URL", "http://localhost:8080"),
		OAuthAutoLink:      getBool("OAUTH_AUTO_LINK", true),
		OAuthStateTTL:      getDuration("OAUTH_STATE_TTL", 10*time.Minute),
		GoogleClientID:     getString("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: getString("GOOGLE_CLIENT_SECRET", ""),
		GitHubClientID:     getString("GITHUB_CLIENT_ID", ""),
		GitHubClientSecret: getString("GITHUB_CLIENT_SECRET", ""),

		SMTPHost:      getString("SMTP_HOST", ""),
		SMTPPort:      getInt("SMTP_PORT", 587),
		SMTPUser:      getString("SMTP_USER", ""),
		SMTPPassword:  getString("SMTP_PASSWORD", ""),
		SMTPFromName:  getString("SMTP_FROM_NAME", "Kael"),
		SMTPFromEmail: getString("SMTP_FROM_EMAIL", ""),
		SMTPUseTLS:    getBool("SMTP_USE_TLS", true),

		EmailOTPTTL:       getDuration("EMAIL_OTP_TTL", 10*time.Minute),
		TOTPEncryptionKey: getString("TOTP_ENCRYPTION_KEY", ""),

		AuthRateLimitPerMinute:  getInt("AUTH_RATE_LIMIT_PER_MINUTE", 120),
		LoginRateLimitPerMinute: getInt("LOGIN_RATE_LIMIT_PER_MINUTE", 20),
		MfaRateLimitPerMinute:   getInt("MFA_RATE_LIMIT_PER_MINUTE", 30),
		AsynqWorkerConcurrency:  getInt("ASYNQ_WORKER_CONCURRENCY", 10),

		OIDCPrivateKeyPath:  getString("OIDC_PRIVATE_KEY_PATH", ".keys/oidc_private.pem"),
		OIDCCodeTTL:         getDuration("OIDC_CODE_TTL", 5*time.Minute),
		OIDCAccessTokenTTL:  getDuration("OIDC_ACCESS_TOKEN_TTL", time.Hour),
		OIDCRefreshTokenTTL: getDuration("OIDC_REFRESH_TOKEN_TTL", 30*24*time.Hour),
		OIDCIssuer:          getString("OIDC_ISSUER", ""),
	}

	return cfg, nil
}

func getString(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}

func getInt32(key string, fallback int32) int32 {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}

	i, err := strconv.Atoi(val)
	if err != nil {
		panic(fmt.Sprintf("invalid int for %s: %v", key, err))
	}

	return int32(i)
}

func getInt(key string, fallback int) int {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}

	i, err := strconv.Atoi(val)
	if err != nil {
		panic(fmt.Sprintf("invalid int for %s: %v", key, err))
	}

	return i
}

func getDuration(key string, fallback time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}

	d, err := time.ParseDuration(val)
	if err != nil {
		panic(fmt.Sprintf("invalid duration for %s: %v", key, err))
	}

	return d
}

func getBool(key string, fallback bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}

	b, err := strconv.ParseBool(val)
	if err != nil {
		panic(fmt.Sprintf("invalid bool for %s: %v", key, err))
	}

	return b
}
