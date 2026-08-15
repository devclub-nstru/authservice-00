package rbac

import (
	"net/http"

	"kael/internal/ctxkeys"
	"kael/internal/httpx"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func getClientID(c *gin.Context) (uuid.UUID, bool) {
	clientIDStr, exists := c.Get(ctxkeys.ClientIDKey)
	if !exists {
		httpx.RespondError(c, http.StatusUnauthorized, "unauthorized", "client authentication required", nil)
		return uuid.Nil, false
	}
	clientID, err := uuid.Parse(clientIDStr.(string))
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_client_id", "invalid client ID in context", nil)
		return uuid.Nil, false
	}
	return clientID, true
}

// --- Permissions ---

// CreatePermission creates a new client permission
// @Summary      Create permission
// @Description  Create a new RBAC permission for the client
// @Tags         rbac
// @Accept       json
// @Produce      json
// @Param        request body rbac.CreatePermissionRequest true "Permission creation payload"
// @Success      201 {object} httpx.Response{data=rbac.Permission}
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /api/v1/m2m/rbac/permissions [post]
func (h *Handler) CreatePermission(c *gin.Context) {
	clientID, ok := getClientID(c)
	if !ok {
		return
	}
	var req CreatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}
	perm, err := h.service.CreatePermission(c.Request.Context(), clientID, req)
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "create_permission_failed", err.Error(), nil)
		return
	}
	httpx.Respond(c, http.StatusCreated, perm)
}

// GetPermission gets a permission by ID
// @Summary      Get permission
// @Description  Get a permission by ID
// @Tags         rbac
// @Produce      json
// @Param        id path string true "Permission ID"
// @Success      200 {object} httpx.Response{data=rbac.Permission}
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      404 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /api/v1/m2m/rbac/permissions/{id} [get]
func (h *Handler) GetPermission(c *gin.Context) {
	clientID, ok := getClientID(c)
	if !ok {
		return
	}
	permID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_id", "invalid permission ID", nil)
		return
	}
	perm, err := h.service.GetPermission(c.Request.Context(), clientID, permID)
	if err != nil {
		if err == ErrPermissionNotFound {
			httpx.RespondError(c, http.StatusNotFound, "permission_not_found", err.Error(), nil)
			return
		}
		httpx.RespondError(c, http.StatusInternalServerError, "get_permission_failed", err.Error(), nil)
		return
	}
	httpx.Respond(c, http.StatusOK, perm)
}

// ListPermissions lists all client permissions
// @Summary      List permissions
// @Description  List all permissions for the client
// @Tags         rbac
// @Produce      json
// @Success      200 {object} httpx.Response{data=object{permissions=[]rbac.Permission}}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /api/v1/m2m/rbac/permissions [get]
func (h *Handler) ListPermissions(c *gin.Context) {
	clientID, ok := getClientID(c)
	if !ok {
		return
	}
	perms, err := h.service.ListPermissions(c.Request.Context(), clientID)
	if err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "list_permissions_failed", err.Error(), nil)
		return
	}
	if perms == nil {
		perms = []Permission{}
	}
	httpx.Respond(c, http.StatusOK, gin.H{"permissions": perms})
}

// UpdatePermission updates a permission
// @Summary      Update permission
// @Description  Update a permission's attributes
// @Tags         rbac
// @Accept       json
// @Produce      json
// @Param        id path string true "Permission ID"
// @Param        request body rbac.UpdatePermissionRequest true "Update payload"
// @Success      200 {object} httpx.Response{data=rbac.Permission}
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /api/v1/m2m/rbac/permissions/{id} [put]
func (h *Handler) UpdatePermission(c *gin.Context) {
	clientID, ok := getClientID(c)
	if !ok {
		return
	}
	permID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_id", "invalid permission ID", nil)
		return
	}
	var req UpdatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}
	perm, err := h.service.UpdatePermission(c.Request.Context(), clientID, permID, req)
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "update_permission_failed", err.Error(), nil)
		return
	}
	httpx.Respond(c, http.StatusOK, perm)
}

// DeletePermission deletes a permission
// @Summary      Delete permission
// @Description  Delete a permission by ID
// @Tags         rbac
// @Param        id path string true "Permission ID"
// @Success      204 "No Content"
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /api/v1/m2m/rbac/permissions/{id} [delete]
func (h *Handler) DeletePermission(c *gin.Context) {
	clientID, ok := getClientID(c)
	if !ok {
		return
	}
	permID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_id", "invalid permission ID", nil)
		return
	}
	if err := h.service.DeletePermission(c.Request.Context(), clientID, permID); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "delete_permission_failed", err.Error(), nil)
		return
	}
	c.Status(http.StatusNoContent)
}

// --- Groups ---

// CreateGroup creates a new permission group
// @Summary      Create group
// @Description  Create a new permission group
// @Tags         rbac
// @Accept       json
// @Produce      json
// @Param        request body rbac.CreateGroupRequest true "Group creation payload"
// @Success      201 {object} httpx.Response{data=rbac.PermissionGroup}
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /api/v1/m2m/rbac/groups [post]
func (h *Handler) CreateGroup(c *gin.Context) {
	clientID, ok := getClientID(c)
	if !ok {
		return
	}
	var req CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}
	group, err := h.service.CreateGroup(c.Request.Context(), clientID, req)
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "create_group_failed", err.Error(), nil)
		return
	}
	httpx.Respond(c, http.StatusCreated, group)
}

// GetGroup gets a permission group by ID
// @Summary      Get group
// @Description  Get a permission group by ID
// @Tags         rbac
// @Produce      json
// @Param        id path string true "Group ID"
// @Success      200 {object} httpx.Response{data=rbac.PermissionGroup}
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      404 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /api/v1/m2m/rbac/groups/{id} [get]
func (h *Handler) GetGroup(c *gin.Context) {
	clientID, ok := getClientID(c)
	if !ok {
		return
	}
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_id", "invalid group ID", nil)
		return
	}
	group, err := h.service.GetGroup(c.Request.Context(), clientID, groupID)
	if err != nil {
		if err == ErrGroupNotFound {
			httpx.RespondError(c, http.StatusNotFound, "group_not_found", err.Error(), nil)
			return
		}
		httpx.RespondError(c, http.StatusInternalServerError, "get_group_failed", err.Error(), nil)
		return
	}
	httpx.Respond(c, http.StatusOK, group)
}

// ListGroups lists all permission groups
// @Summary      List groups
// @Description  List all permission groups for the client
// @Tags         rbac
// @Produce      json
// @Success      200 {object} httpx.Response{data=object{groups=[]rbac.PermissionGroup}}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /api/v1/m2m/rbac/groups [get]
func (h *Handler) ListGroups(c *gin.Context) {
	clientID, ok := getClientID(c)
	if !ok {
		return
	}
	groups, err := h.service.ListGroups(c.Request.Context(), clientID)
	if err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "list_groups_failed", err.Error(), nil)
		return
	}
	if groups == nil {
		groups = []PermissionGroup{}
	}
	httpx.Respond(c, http.StatusOK, gin.H{"groups": groups})
}

// UpdateGroup updates a permission group
// @Summary      Update group
// @Description  Update a permission group's attributes and permissions
// @Tags         rbac
// @Accept       json
// @Produce      json
// @Param        id path string true "Group ID"
// @Param        request body rbac.UpdateGroupRequest true "Update payload"
// @Success      200 {object} httpx.Response{data=rbac.PermissionGroup}
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /api/v1/m2m/rbac/groups/{id} [put]
func (h *Handler) UpdateGroup(c *gin.Context) {
	clientID, ok := getClientID(c)
	if !ok {
		return
	}
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_id", "invalid group ID", nil)
		return
	}
	var req UpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}
	group, err := h.service.UpdateGroup(c.Request.Context(), clientID, groupID, req)
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "update_group_failed", err.Error(), nil)
		return
	}
	httpx.Respond(c, http.StatusOK, group)
}

// DeleteGroup deletes a permission group
// @Summary      Delete group
// @Description  Delete a permission group by ID
// @Tags         rbac
// @Param        id path string true "Group ID"
// @Success      204 "No Content"
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /api/v1/m2m/rbac/groups/{id} [delete]
func (h *Handler) DeleteGroup(c *gin.Context) {
	clientID, ok := getClientID(c)
	if !ok {
		return
	}
	groupID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_id", "invalid group ID", nil)
		return
	}
	if err := h.service.DeleteGroup(c.Request.Context(), clientID, groupID); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "delete_group_failed", err.Error(), nil)
		return
	}
	c.Status(http.StatusNoContent)
}

// --- User Assignments ---

// AssignUserGroup assigns a group to a user
// @Summary      Assign user group
// @Description  Assign a permission group to a user by email
// @Tags         rbac
// @Accept       json
// @Produce      json
// @Param        request body rbac.AssignUserGroupRequest true "Assign payload"
// @Success      200 {object} httpx.Response{data=rbac.AssignUserGroupResponse}
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /api/v1/m2m/rbac/users/assign [post]
func (h *Handler) AssignUserGroup(c *gin.Context) {
	clientID, ok := getClientID(c)
	if !ok {
		return
	}
	var req AssignUserGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}
	resp, err := h.service.AssignUserGroup(c.Request.Context(), clientID, req)
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "assign_user_group_failed", err.Error(), nil)
		return
	}
	httpx.Respond(c, http.StatusOK, resp)
}

// UnassignUserGroup removes a group assignment from a user
// @Summary      Unassign user group
// @Description  Remove a permission group assignment from a user
// @Tags         rbac
// @Accept       json
// @Produce      json
// @Param        request body rbac.UnassignUserGroupRequest true "Unassign payload"
// @Success      200 {object} httpx.Response{data=object{status=string,email=string}}
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /api/v1/m2m/rbac/users/unassign [post]
func (h *Handler) UnassignUserGroup(c *gin.Context) {
	clientID, ok := getClientID(c)
	if !ok {
		return
	}
	var req UnassignUserGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}
	if err := h.service.UnassignUserGroup(c.Request.Context(), clientID, req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "unassign_user_group_failed", err.Error(), nil)
		return
	}
	httpx.Respond(c, http.StatusOK, gin.H{"status": "unassigned", "email": req.Email})
}

// GetUserPermissions gets effective permissions for a user
// @Summary      Get user permissions
// @Description  Get effective permissions for a user by email
// @Tags         rbac
// @Produce      json
// @Param        email query string true "User Email"
// @Success      200 {object} httpx.Response{data=rbac.UserPermissionsResult}
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      401 {object} httpx.Response{error=httpx.ErrorResponse}
// @Failure      500 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /api/v1/m2m/rbac/users/permissions [get]
func (h *Handler) GetUserPermissions(c *gin.Context) {
	clientID, ok := getClientID(c)
	if !ok {
		return
	}
	email := c.Query("email")
	if email == "" {
		httpx.RespondError(c, http.StatusBadRequest, "missing_email", "query param 'email' is required", nil)
		return
	}
	result, err := h.service.GetUserPermissions(c.Request.Context(), clientID, email)
	if err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "get_user_permissions_failed", err.Error(), nil)
		return
	}
	httpx.Respond(c, http.StatusOK, result)
}

