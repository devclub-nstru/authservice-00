package middleware

import (
	"net/http"

	"kael/internal/clients"
	"kael/internal/ctxkeys"
	"kael/internal/httpx"
	"kael/internal/security"

	"github.com/gin-gonic/gin"
)

// RequireClientCredentials authenticates a client via X-Client-ID & X-Client-Secret headers
// or HTTP Basic Auth, and puts the client's UUID (client.ID) into gin.Context with ctxkeys.ClientIDKey.
func RequireClientCredentials(clientsRepo *clients.Repository) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientID := c.GetHeader("X-Client-ID")
		clientSecret := c.GetHeader("X-Client-Secret")

		if clientID == "" || clientSecret == "" {
			// Try HTTP Basic Auth fallback
			id, secret, ok := c.Request.BasicAuth()
			if ok {
				clientID = id
				clientSecret = secret
			}
		}

		if clientID == "" || clientSecret == "" {
			httpx.RespondError(c, http.StatusUnauthorized, "client_auth_required", "X-Client-ID and X-Client-Secret headers required", nil)
			c.Abort()
			return
		}

		client, err := clientsRepo.FindByClientID(c.Request.Context(), clientID)
		if err != nil {
			httpx.RespondError(c, http.StatusUnauthorized, "invalid_client", "invalid client credentials", nil)
			c.Abort()
			return
		}

		secretHash := security.HashToken(clientSecret)
		if secretHash != client.ClientSecretHash {
			httpx.RespondError(c, http.StatusUnauthorized, "invalid_client", "invalid client credentials", nil)
			c.Abort()
			return
		}

		c.Set(ctxkeys.ClientIDKey, client.ID.String())
		c.Next()
	}
}
