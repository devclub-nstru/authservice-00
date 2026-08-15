package middleware_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kael/internal/middleware"
	"kael/internal/ctxkeys"

	"github.com/gin-gonic/gin"
)

func TestTokenBucketRateLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	
	// Create a rate limiter with a limit of 2 requests per second
	r.Use(middleware.RateLimit("test_bucket", 2, time.Second, middleware.ExtractIP()))
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// First request - should pass
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.RemoteAddr = "192.168.1.1:1234"
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w1.Code)
	}

	// Second request - should pass
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.RemoteAddr = "192.168.1.1:1234"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w2.Code)
	}

	// Third request immediately - should fail (429)
	req3 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req3.RemoteAddr = "192.168.1.1:1234"
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 Too Many Requests, got %d", w3.Code)
	}

	// Wait 600ms - bucket should refill at least 1 token (rate is 2/s, so 1 token per 500ms)
	time.Sleep(600 * time.Millisecond)

	// Fourth request - should pass now
	req4 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req4.RemoteAddr = "192.168.1.1:1234"
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req4)
	if w4.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", w4.Code)
	}
}

func TestExtractEmailRateLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.POST("/login", 
		middleware.RateLimit("login_email", 1, time.Second, middleware.ExtractEmail()),
		func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

	// Req 1: user@example.com (Pass)
	body1 := []byte(`{"email": "user@example.com"}`)
	req1 := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body1))
	req1.RemoteAddr = "1.1.1.1:1234"
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w1.Code)
	}

	// Req 2: same email from DIFFERENT IP -> should fail (limited by email)
	body2 := []byte(`{"email": "user@example.com"}`)
	req2 := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body2))
	req2.RemoteAddr = "2.2.2.2:1234"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w2.Code)
	}

	// Req 3: different email from SAME IP -> should pass (different email)
	body3 := []byte(`{"email": "other@example.com"}`)
	req3 := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body3))
	req3.RemoteAddr = "1.1.1.1:1234"
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w3.Code)
	}
}

func TestExtractUserRateLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		if c.GetHeader("X-User-ID") != "" {
			c.Set(ctxkeys.UserIDKey, c.GetHeader("X-User-ID"))
		}
	})
	r.GET("/me", 
		middleware.RateLimit("me_user", 1, time.Second, middleware.ExtractUser()),
		func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

	req1 := httptest.NewRequest(http.MethodGet, "/me", nil)
	req1.Header.Set("X-User-ID", "user-123")
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	
	req2 := httptest.NewRequest(http.MethodGet, "/me", nil)
	req2.Header.Set("X-User-ID", "user-123")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w1.Code != http.StatusOK { t.Errorf("req1: expected 200, got %d", w1.Code) }
	if w2.Code != http.StatusTooManyRequests { t.Errorf("req2: expected 429, got %d", w2.Code) }
}
