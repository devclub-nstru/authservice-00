package sessions

import (
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine, handler *Handler, authMiddleware, rlUser, rlIP gin.HandlerFunc) {
	group := r.Group("/sessions")
	group.Use(authMiddleware)
	group.Use(rlUser, rlIP)
	group.GET("", handler.List)
	group.DELETE("/:id", handler.Revoke)
}
