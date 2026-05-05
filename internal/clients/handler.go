package clients

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

// CreateClient creates a new client application
// @Summary      Create client
// @Description  Register a new OAuth client application
// @Tags         clients
// @Accept       json
// @Produce      json
// @Param        request body CreateClientRequest true "Client creation payload"
// @Success      201 {object} httpx.Response{data=CreateClientResponse}
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /clients [post]
func (h *Handler) CreateClient(c *gin.Context) {
	var req CreateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	ownerID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	client, secret, uris, err := h.service.Create(c.Request.Context(), ownerID, req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	httpx.Respond(c, http.StatusCreated, CreateClientResponse{
		Client:       mapClientResponse(client, uris),
		ClientSecret: secret,
	})
}

// ListClients lists all clients owned by the authenticated user
// @Summary      List clients
// @Description  List all OAuth clients owned by the current user
// @Tags         clients
// @Produce      json
// @Success      200 {object} httpx.Response{data=[]ClientResponse}
// @Router       /clients [get]
func (h *Handler) ListClients(c *gin.Context) {
	ownerID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	clients, err := h.service.List(c.Request.Context(), ownerID)
	if err != nil {
		httpx.RespondError(c, http.StatusInternalServerError, "list_failed", "failed to list clients", nil)
		return
	}

	result := make([]ClientResponse, 0, len(clients))
	for _, cl := range clients {
		result = append(result, mapClientResponse(&cl, nil))
	}
	httpx.Respond(c, http.StatusOK, result)
}

// GetClient returns a single client by ID
// @Summary      Get client
// @Description  Get details of a specific OAuth client
// @Tags         clients
// @Produce      json
// @Param        id path string true "Client UUID"
// @Success      200 {object} httpx.Response{data=ClientResponse}
// @Failure      404 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /clients/{id} [get]
func (h *Handler) GetClient(c *gin.Context) {
	ownerID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_id", "invalid client id", nil)
		return
	}

	client, uris, err := h.service.Get(c.Request.Context(), id, ownerID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	httpx.Respond(c, http.StatusOK, mapClientResponse(client, uris))
}

// UpdateClient updates client metadata
// @Summary      Update client
// @Description  Update name, avatar, or redirect URIs of a client
// @Tags         clients
// @Accept       json
// @Produce      json
// @Param        id path string true "Client UUID"
// @Param        request body UpdateClientRequest true "Update payload"
// @Success      200 {object} httpx.Response{data=map[string]bool}
// @Failure      400 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /clients/{id} [patch]
func (h *Handler) UpdateClient(c *gin.Context) {
	ownerID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_id", "invalid client id", nil)
		return
	}

	var req UpdateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_payload", err.Error(), nil)
		return
	}

	if err := h.service.Update(c.Request.Context(), id, ownerID, req); err != nil {
		h.handleError(c, err)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{"updated": true})
}

// RotateSecret generates a new client secret
// @Summary      Rotate client secret
// @Description  Generate a new client secret (old secret becomes invalid)
// @Tags         clients
// @Produce      json
// @Param        id path string true "Client UUID"
// @Success      200 {object} httpx.Response{data=RotateSecretResponse}
// @Failure      404 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /clients/{id}/rotate-secret [post]
func (h *Handler) RotateSecret(c *gin.Context) {
	ownerID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_id", "invalid client id", nil)
		return
	}

	secret, err := h.service.RotateSecret(c.Request.Context(), id, ownerID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	httpx.Respond(c, http.StatusOK, RotateSecretResponse{ClientSecret: secret})
}

// DeleteClient deletes a client application
// @Summary      Delete client
// @Description  Permanently delete a client and all associated data
// @Tags         clients
// @Produce      json
// @Param        id path string true "Client UUID"
// @Success      200 {object} httpx.Response{data=map[string]bool}
// @Failure      404 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /clients/{id} [delete]
func (h *Handler) DeleteClient(c *gin.Context) {
	ownerID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_id", "invalid client id", nil)
		return
	}

	if err := h.service.Delete(c.Request.Context(), id, ownerID); err != nil {
		h.handleError(c, err)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{"deleted": true})
}

// ListMembers lists all users of a client
// @Summary      List users
// @Description  List all users who are members of a client
// @Tags         clients
// @Produce      json
// @Param        id path string true "Client UUID"
// @Success      200 {object} httpx.Response{data=[]MemberProfile}
// @Router       /clients/{id}/users [get]
func (h *Handler) ListMembers(c *gin.Context) {
	ownerID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_id", "invalid client id", nil)
		return
	}

	members, err := h.service.ListMembers(c.Request.Context(), id, ownerID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	if members == nil {
		members = []MemberProfile{}
	}
	httpx.Respond(c, http.StatusOK, members)
}

// RemoveMember removes a user from a client
// @Summary      Remove member
// @Description  Revoke a user's membership from a client
// @Tags         clients
// @Produce      json
// @Param        id path string true "Client UUID"
// @Param        userId path string true "User UUID"
// @Success      200 {object} httpx.Response{data=map[string]bool}
// @Failure      404 {object} httpx.Response{error=httpx.ErrorResponse}
// @Router       /clients/{id}/members/{userId} [delete]
func (h *Handler) RemoveMember(c *gin.Context) {
	ownerID, err := getUserID(c)
	if err != nil {
		httpx.RespondError(c, http.StatusUnauthorized, "session_missing", "authentication required", nil)
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_id", "invalid client id", nil)
		return
	}

	userID, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		httpx.RespondError(c, http.StatusBadRequest, "invalid_id", "invalid user id", nil)
		return
	}

	if err := h.service.RemoveMember(c.Request.Context(), id, ownerID, userID); err != nil {
		h.handleError(c, err)
		return
	}

	httpx.Respond(c, http.StatusOK, gin.H{"removed": true})
}

func getUserID(c *gin.Context) (uuid.UUID, error) {
	val, ok := c.Get(ctxkeys.UserIDKey)
	if !ok {
		return uuid.Nil, http.ErrNoCookie
	}
	return uuid.Parse(val.(string))
}

func (h *Handler) handleError(c *gin.Context, err error) {
	switch err {
	case ErrClientNotFound:
		httpx.RespondError(c, http.StatusNotFound, "client_not_found", err.Error(), nil)
	case ErrNotOwner:
		httpx.RespondError(c, http.StatusForbidden, "not_owner", err.Error(), nil)
	case ErrNoRedirectURIs:
		httpx.RespondError(c, http.StatusBadRequest, "no_redirect_uris", err.Error(), nil)
	case ErrUserNotFound:
		httpx.RespondError(c, http.StatusNotFound, "user_not_found", err.Error(), nil)
	case ErrAlreadyMember:
		httpx.RespondError(c, http.StatusConflict, "already_member", err.Error(), nil)
	default:
		httpx.RespondError(c, http.StatusBadRequest, "client_error", err.Error(), nil)
	}
}

func mapClientResponse(client *Client, uris []string) ClientResponse {
	if uris == nil {
		uris = []string{}
	}
	return ClientResponse{
		ID:           client.ID.String(),
		ClientID:     client.ClientID,
		Name:         client.Name,
		AvatarURL:    client.AvatarURL,
		RedirectURIs: uris,
		CreatedAt:    client.CreatedAt,
		UpdatedAt:    client.UpdatedAt,
	}
}
