package rbac

import (
	"kael/internal/clients"
	"kael/internal/config"
	"kael/internal/middleware"
	"time"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine, handler *Handler, clientsRepo *clients.Repository, cfg *config.Config) {
	m2m := r.Group("/api/v1/m2m/rbac")
	m2m.Use(middleware.RequireClientCredentials(clientsRepo))
	m2m.Use(
		middleware.RateLimit("rl:rbac:client", cfg.RBACRateLimitPerMinute, time.Minute, middleware.ExtractClientID()),
		middleware.RateLimit("rl:rbac:ip", cfg.RBACRateLimitPerMinute, time.Minute, middleware.ExtractIP()),
	)
	{
		// Permissions CRUD
		m2m.POST("/permissions", handler.CreatePermission)
		m2m.GET("/permissions", handler.ListPermissions)
		m2m.GET("/permissions/:id", handler.GetPermission)
		m2m.PUT("/permissions/:id", handler.UpdatePermission)
		m2m.DELETE("/permissions/:id", handler.DeletePermission)

		// Permission Groups CRUD
		m2m.POST("/groups", handler.CreateGroup)
		m2m.GET("/groups", handler.ListGroups)
		m2m.GET("/groups/:id", handler.GetGroup)
		m2m.PUT("/groups/:id", handler.UpdateGroup)
		m2m.DELETE("/groups/:id", handler.DeleteGroup)

		// User Assignments
		m2m.POST("/users/assign", handler.AssignUserGroup)
		m2m.POST("/users/unassign", handler.UnassignUserGroup)
		m2m.GET("/users/permissions", handler.GetUserPermissions)
	}
}
