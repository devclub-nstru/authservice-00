package main

import (
	"log"

	"kael/internal/auth"
	"kael/internal/clients"
	"kael/internal/config"
	"kael/internal/database"
	"kael/internal/health"
	"kael/internal/mfa"
	"kael/internal/middleware"
	"kael/internal/oauth"
	"kael/internal/oidc"
	"kael/internal/ques"
	"kael/internal/sessions"
	"kael/internal/tokens"
	"kael/internal/users"

	"github.com/gin-gonic/gin"
)

// @title           Kael API
// @version         1.0
// @description     Auth API for DevClub services.
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
	clientsRepo := clients.NewRepository(pool)
	oidcRepo := oidc.NewRepository(pool)

	oauthService := oauth.NewService(cfg, oauthRepo, usersRepo, redisClient)
	authService, err := auth.NewService(cfg, usersRepo, sessionsService, mfaRepo, tokensRepo, oauthService, clientsRepo, oidcRepo, asynqClient)
	if err != nil {
		log.Fatal("Unable to initialize auth service:", err)
	}
	clientsService := clients.NewService(clientsRepo, usersRepo)
	clientsHandler := clients.NewHandler(clientsService)
	oidcService, err := oidc.NewService(cfg, oidcRepo, clientsRepo, usersRepo)
	if err != nil {
		log.Fatal("Unable to initialize OIDC service:", err)
	}
	oidcHandler := oidc.NewHandler(oidcService, cfg, sessionsService)

	authHandler := auth.NewHandler(authService, cfg)
	oauthHandler := oauth.NewHandler(oauthService, authService, cfg)
	sessionsHandler := sessions.NewHandler(sessionsService)
	mfaHandler, err := mfa.NewHandler(mfaRepo, usersRepo, cfg, asynqClient)
	if err != nil {
		log.Fatal("Unable to initialize mfa handler:", err)
	}

	r := gin.Default()
	r.Use(middleware.CORS(cfg))
	health.RegisterRoutes(r, pool)
	auth.RegisterRoutes(r, authHandler, cfg, sessionsService)
	oauth.RegisterRoutes(r, oauthHandler, cfg, sessionsService)
	sessions.RegisterRoutes(r, sessionsHandler, middleware.RequireSession(cfg, sessionsService))
	mfa.RegisterRoutes(r, mfaHandler, cfg, sessionsService)
	clients.RegisterRoutes(r, clientsHandler, middleware.RequireSession(cfg, sessionsService))
	oidc.RegisterRoutes(r, oidcHandler)

	log.Printf("Server starting on port %s", cfg.Port)
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
