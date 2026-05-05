package clients

import "github.com/gin-gonic/gin"

func RegisterRoutes(r *gin.Engine, handler *Handler, authMiddleware gin.HandlerFunc) {
	group := r.Group("/clients")
	group.Use(authMiddleware)

	group.POST("", handler.CreateClient)
	group.GET("", handler.ListClients)
	group.GET("/:id", handler.GetClient)
	group.PATCH("/:id", handler.UpdateClient)
	group.POST("/:id/rotate-secret", handler.RotateSecret)
	group.DELETE("/:id", handler.DeleteClient)

	group.GET("/:id/users", handler.ListMembers)
	group.DELETE("/:id/members/:userId", handler.RemoveMember)
}
