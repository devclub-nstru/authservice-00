package oidc

type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required"`
	Code         string `form:"code"`
	RedirectURI  string `form:"redirect_uri"`
	ClientID     string `form:"client_id" binding:"required"`
	ClientSecret string `form:"client_secret"`
	CodeVerifier string `form:"code_verifier"`
	RefreshToken string `form:"refresh_token"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type UserInfoResponse struct {
	Sub           string  `json:"sub"`
	Email         string  `json:"email"`
	EmailVerified bool    `json:"email_verified"`
	Name          *string `json:"name,omitempty"`
	Picture       *string `json:"picture,omitempty"`
}

type RevokeRequest struct {
	Token string `form:"token" json:"token" binding:"required"`
}

type IntrospectRequest struct {
	Token string `form:"token" json:"token" binding:"required"`
}

type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Sub       string `json:"sub,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

type DiscoveryDocument struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	RevocationEndpoint               string   `json:"revocation_endpoint"`
	IntrospectionEndpoint            string   `json:"introspection_endpoint"`
	JWKSUri                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
}
