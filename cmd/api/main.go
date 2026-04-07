package main

import (
	"authservice/internal/config"
	"authservice/internal/database"
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("load config: ", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx := context.Background()
	startedAt := time.Now().UTC()
	pool, err := database.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	router.Use(corsMiddleware(cfg.AllowedOrigins))
	router.SetTrustedProxies(nil)

	router.GET("/health", func(c *gin.Context) {
		dbCtx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		pingStarted := time.Now()
		dbErr := pool.Ping(dbCtx)
		dbLatency := time.Since(pingStarted)
		cancel()

		status := "ok"
		httpStatus := http.StatusOK
		dbStatus := "up"
		if dbErr != nil {
			status = "degraded"
			httpStatus = http.StatusServiceUnavailable
			dbStatus = "down"
		}

		poolStat := pool.Stat()

		c.JSON(httpStatus, gin.H{
			"status": status,
			"uptime": gin.H{
				"startedAt": startedAt,
				"seconds":   int64(time.Since(startedAt).Seconds()),
			},
			"database": gin.H{
				"status":    dbStatus,
				"latencyMs": float64(dbLatency.Microseconds()) / 1000.0,
				"error":     errorString(dbErr),
				"pool": gin.H{
					"acquiredConns":        poolStat.AcquiredConns(),
					"idleConns":            poolStat.IdleConns(),
					"totalConns":           poolStat.TotalConns(),
					"maxConns":             poolStat.MaxConns(),
					"acquireCount":         poolStat.AcquireCount(),
					"emptyAcquireCount":    poolStat.EmptyAcquireCount(),
					"canceledAcquireCount": poolStat.CanceledAcquireCount(),
				},
			},
		})
	})

	logger.Info("starting server", "port", cfg.Port, "env", cfg.Environment)
	if err := router.Run(":" + cfg.Port); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func errorString(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}
