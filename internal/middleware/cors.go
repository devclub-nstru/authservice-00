package middleware

import (
	"net/http"
	"time"

	"kael/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// CORS is a middleware function that adds CORS headers to the response
func CORS(cfg *config.Config, redisClient *redis.Client, db *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		allowed := false

		if origin == "" {
			allowed = true
		} else if origin == cfg.FrontendBaseURL {
			allowed = true
		} else {
			ctx := c.Request.Context()
			isMember, err := redisClient.SIsMember(ctx, "cors:allowed_origins", origin).Result()
			if err == nil && isMember {
				allowed = true
			} else {
				// Cache miss, check if key exists
				exists, err := redisClient.Exists(ctx, "cors:allowed_origins").Result()
				if err == nil && exists == 0 {
					// Lazy load from DB
					rows, err := db.Query(ctx, "SELECT DISTINCT origin FROM client_allowed_origins")
					if err == nil {
						var origins []string
						for rows.Next() {
							var o string
							if err := rows.Scan(&o); err == nil {
								origins = append(origins, o)
							}
						}
						rows.Close()

						if len(origins) > 0 {
							args := make([]interface{}, len(origins))
							for i, v := range origins {
								args[i] = v
								if v == origin {
									allowed = true
								}
							}
							redisClient.SAdd(ctx, "cors:allowed_origins", args...)
							redisClient.Expire(ctx, "cors:allowed_origins", 24*time.Hour)
						} else {
							// Dummy value to prevent constant DB queries
							redisClient.SAdd(ctx, "cors:allowed_origins", "_empty")
							redisClient.Expire(ctx, "cors:allowed_origins", 24*time.Hour)
						}
					}
				}
			}
		}

		if origin != "" && allowed {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		} else if origin == "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", cfg.FrontendBaseURL)
		}

		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-Device-Id")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, PATCH, DELETE")

		if c.Request.Method == "OPTIONS" {
			if !allowed && origin != "" {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
