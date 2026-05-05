package sessions

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	DeviceID   string
	TokenHash  string
	IPAddress  *string
	UserAgent  *string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	IsActive      bool
	MFAPending    bool
	EmailVerified bool
}
