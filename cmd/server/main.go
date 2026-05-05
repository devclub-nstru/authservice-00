package main

import (
	"log"

	"kael/internal/auth"
	"kael/internal/config"
	"kael/internal/database"
	"kael/internal/health"
	"kael/internal/mfa"
	"kael/internal/middleware"
	"kael/internal/oauth"
	"kael/internal/ques"
	"kael/internal/sessions"
	"kael/internal/tokens"
	"kael/internal/users"

	"github.com/gin-gonic/gin"
)

// @title           Kael API
// @version         1.0
// @description     Auth API for devclub services.
// @BasePath        /
func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Unable to load config:", err)
	}

	pool, err := database.Connect(cfg)
	if err != nil {
		log.Fatal("Unable to connect to db:", err)
	}
	defer pool.Close()

	redisClient, err := database.ConnectRedis(cfg)
	if err != nil {
		log.Fatal("Unable to connect to redis:", err)
	}
	defer redisClient.Close()

	asynqClient, err := ques.NewClient(cfg)
	if err != nil {
		log.Fatal("Unable to create asynq client:", err)
	}
	defer asynqClient.Close()

	usersRepo := users.NewRepository(pool)
	sessionsRepo := sessions.NewRepository(pool)
	sessionsService := sessions.NewService(sessionsRepo, cfg)
	mfaRepo := mfa.NewRepository(pool)
	tokensRepo := tokens.NewRepository(pool)
	oauthRepo := oauth.NewRepository(pool)

	oauthService := oauth.NewService(cfg, oauthRepo, usersRepo, redisClient)
	authService, err := auth.NewService(cfg, usersRepo, sessionsService, mfaRepo, tokensRepo, oauthService, asynqClient)
	if err != nil {
		log.Fatal("Unable to initialize auth service:", err)
	}

	authHandler := auth.NewHandler(authService, cfg)
	oauthHandler := oauth.NewHandler(oauthService, authService, cfg)
	sessionsHandler := sessions.NewHandler(sessionsService)
	mfaHandler, err := mfa.NewHandler(mfaRepo, usersRepo, cfg, asynqClient)
	if err != nil {
		log.Fatal("Unable to initialize mfa handler:", err)
	}

	r := gin.Default()
	if cfg.AppEnv == "development" {
		r.Use(middleware.DevStaticDeviceID("test-1"))
	}
	health.RegisterRoutes(r, pool)
	auth.RegisterRoutes(r, authHandler, cfg, sessionsService, redisClient)
	oauth.RegisterRoutes(r, oauthHandler, cfg, sessionsService)
	sessions.RegisterRoutes(r, sessionsHandler, middleware.RequireSession(cfg, sessionsService))
	mfa.RegisterRoutes(r, mfaHandler, cfg, sessionsService)

	log.Printf("Server starting on port %s", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
