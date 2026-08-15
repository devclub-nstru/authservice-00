package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"sync"
	"time"

	"kael/internal/ctxkeys"
	"kael/internal/httpx"

	"github.com/gin-gonic/gin"
)

// KeyExtractor defines a function that extracts a rate limiting key from the context.
// It returns the key and a boolean indicating if the key was found.
type KeyExtractor func(c *gin.Context) (string, bool)

// TokenBucket implements a leaky/token bucket rate limiter.
type TokenBucket struct {
	tokens     float64
	capacity   float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// Take attempts to take a token from the bucket. Returns true if successful.
func (tb *TokenBucket) Take() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()

	tb.tokens = math.Min(tb.capacity, tb.tokens+(elapsed*tb.refillRate))
	tb.lastRefill = now

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}
	return false
}

type limiterEntry struct {
	bucket   *TokenBucket
	lastUsed time.Time
}

type limiterStore struct {
	mu       sync.Mutex
	entries  map[string]*limiterEntry
	capacity float64
	rate     float64
}

func newLimiterStore(capacity, rate float64) *limiterStore {
	s := &limiterStore{
		entries:  make(map[string]*limiterEntry),
		capacity: capacity,
		rate:     rate,
	}
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			s.evict(5 * time.Minute)
		}
	}()
	return s
}

func (s *limiterStore) take(key string) bool {
	s.mu.Lock()
	entry, ok := s.entries[key]
	if !ok {
		entry = &limiterEntry{
			bucket: &TokenBucket{
				tokens:     s.capacity,
				capacity:   s.capacity,
				refillRate: s.rate,
				lastRefill: time.Now(),
			},
		}
		s.entries[key] = entry
	}
	entry.lastUsed = time.Now()
	bucket := entry.bucket
	s.mu.Unlock()

	return bucket.Take()
}

func (s *limiterStore) evict(idleTimeout time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-idleTimeout)
	for k, e := range s.entries {
		if e.lastUsed.Before(cutoff) {
			delete(s.entries, k)
		}
	}
}

var (
	storesMu sync.Mutex
	stores   = make(map[string]*limiterStore)
)

func getStore(name string, capacity, rate float64) *limiterStore {
	storesMu.Lock()
	defer storesMu.Unlock()
	if s, ok := stores[name]; ok {
		return s
	}
	s := newLimiterStore(capacity, rate)
	stores[name] = s
	return s
}

// ExtractIP extracts the client IP address.
func ExtractIP() KeyExtractor {
	return func(c *gin.Context) (string, bool) {
		return "ip:" + c.ClientIP(), true
	}
}

// ExtractEmail extracts the email from the JSON request body.
func ExtractEmail() KeyExtractor {
	return func(c *gin.Context) (string, bool) {
		if c.Request.Body == nil {
			return "", false
		}
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			return "", false
		}
		// Restore body
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		var payload struct {
			Email string `json:"email"`
		}
		if err := json.Unmarshal(bodyBytes, &payload); err == nil && payload.Email != "" {
			return "email:" + payload.Email, true
		}
		return "", false
	}
}

// ExtractClientID extracts the client ID from Context or JSON body.
func ExtractClientID() KeyExtractor {
	return func(c *gin.Context) (string, bool) {
		if val, exists := c.Get(ctxkeys.ClientIDKey); exists {
			return "client:" + val.(string), true
		}
		
		if c.Request.Body != nil {
			bodyBytes, err := io.ReadAll(c.Request.Body)
			if err == nil {
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				var payload struct {
					ClientID string `json:"client_id"`
				}
				if err := json.Unmarshal(bodyBytes, &payload); err == nil && payload.ClientID != "" {
					return "client:" + payload.ClientID, true
				}
			}
		}
		return "", false
	}
}

// ExtractUser extracts the User ID from the context.
func ExtractUser() KeyExtractor {
	return func(c *gin.Context) (string, bool) {
		if val, exists := c.Get(ctxkeys.UserIDKey); exists {
			return "user:" + val.(string), true
		}
		return "", false
	}
}

// RateLimit returns a Gin middleware that enforces a token bucket rate limit.
// It uses the provided KeyExtractors to determine the key (e.g., email, IP).
// The first extractor to return a key is used. If none return a key, it falls back to IP.
// limit is the maximum burst capacity, window is the time frame for `limit` tokens to be refilled.
func RateLimit(name string, limit int, window time.Duration, extractors ...KeyExtractor) gin.HandlerFunc {
	if limit <= 0 || window <= 0 {
		return func(c *gin.Context) { c.Next() }
	}

	capacity := float64(limit)
	rate := float64(limit) / window.Seconds()
	store := getStore(name, capacity, rate)

	return func(c *gin.Context) {
		var key string
		found := false
		
		for _, ext := range extractors {
			if k, ok := ext(c); ok {
				key = k
				found = true
				break
			}
		}

		if !found {
			key = "ip:" + c.ClientIP()
		}

		if !store.take(key) {
			httpx.RespondError(c, http.StatusTooManyRequests, "rate_limited", "too many requests, please slow down", nil)
			c.Abort()
			return
		}
		c.Next()
	}
}
