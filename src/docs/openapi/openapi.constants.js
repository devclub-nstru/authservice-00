export const OPENAPI_TAGS = {
  AUTH: "Auth",
  USERS: "Users",
  ORGANIZATIONS: "Organizations",
  CLIENTS: "Clients",
  SSO: "SSO",
  OAUTH: "OAuth",
};

export const OPENAPI_SECURITY = {
  AUTHENTICATED: [{ bearerAuth: [] }, { cookieAuth: [] }],
};

export const OPENAPI_DESCRIPTIONS = {
  SIGNUP_SUCCESS: "Signup successful",
  LOGIN_SUCCESS: "Login successful",
  LOGOUT_SUCCESS: "Logged out",
  TOKEN_REFRESHED: "Token refreshed",
  EMAIL_VERIFIED: "Email verified",
  REQUEST_ACCEPTED: "Request accepted",
  PASSWORD_UPDATED: "Password updated",
  SESSION_LIST: "Session list",
  SESSION_REVOKED: "Session revoked",
  CURRENT_USER: "Current user",
  USER_UPDATED: "Updated user profile",
  USER_DELETED: "User deleted",
  ORGANIZATION_CREATED: "Organization created",
  ORGANIZATION_LIST: "Organization list",
  ORGANIZATION_DETAILS: "Organization details",
  ORGANIZATION_UPDATED: "Organization updated",
  ORGANIZATION_DELETED: "Organization deleted",
  ORGANIZATION_INVITE_SENT: "Organization invite sent",
  ORGANIZATION_INVITE_LIST: "Organization invites",
  ORGANIZATION_INVITE_DETAILS: "Organization invite details",
  ORGANIZATION_INVITE_ACCEPTED: "Invite accepted",
  ORGANIZATION_INVITE_REVOKED: "Invite revoked",
  ORGANIZATION_MEMBER_ROLE_UPDATED: "Organization member role updated",
  ORGANIZATION_OWNERSHIP_TRANSFERRED: "Organization ownership transferred",
  ORGANIZATION_CLIENT_CREATED: "Organization client created",
  ORGANIZATION_CLIENT_LIST: "Organization clients",
  ORGANIZATION_CLIENT_DETAILS: "Organization client details",
  ORGANIZATION_CLIENT_UPDATED: "Organization client updated",
  ORGANIZATION_CLIENT_DELETED: "Organization client deleted",
  ORGANIZATION_CLIENT_PROVIDER_ADDED: "Organization client provider configured",
  ORGANIZATION_CLIENT_PROVIDER_UPDATED: "Organization client provider updated",
  ORGANIZATION_CLIENT_PROVIDER_REMOVED: "Organization client provider removed",
  ORGANIZATION_CLIENT_WEBHOOK_CONFIGURED:
    "Organization client webhook configured",
  ORGANIZATION_CLIENT_WEBHOOK_DISABLED: "Organization client webhook disabled",
  ORGANIZATION_CLIENT_WEBHOOK_SECRET_ROTATED:
    "Organization client webhook secret rotated",
  ORGANIZATION_CLIENT_SECRET_ROTATED: "Organization client secret rotated",
  ORGANIZATION_CLIENT_USERS: "Organization client users",
  OAUTH_CLIENT_PROVIDERS: "Configured OAuth providers for client",
  OAUTH_AUTHORIZE: "Validate OIDC authorize request and redirect to frontend",
  OAUTH_AUTHORIZE_INIT:
    "Fetch configured providers and authorization URLs for OIDC initiation",
  OAUTH_AUTHORIZE_COMPLETE:
    "Complete authorization for authenticated user and issue authorization code redirect",
  OAUTH_TOKEN: "Exchange authorization code for OIDC tokens",
  OAUTH_USERINFO: "Fetch OIDC userinfo claims from access token",
  OAUTH_JWKS: "Get JWKS used to verify OIDC tokens",
  OAUTH_DISCOVERY: "Get OIDC discovery configuration",
  OAUTH_ORG_CLIENT_START: "Redirect to org-client provider authorization page",
  OAUTH_ORG_CLIENT_CALLBACK:
    "Handle org-client OAuth callback and continue auth flow",
  OAUTH_CONFIRMATION_COMPLETED: "OAuth confirmation completed",
  OAUTH_REDIRECT: "Sets auth cookies and redirects to frontend",
  OAUTH_PROVIDER_REDIRECT: "Redirect to provider authorization page",
  INVALID_INPUT: "Invalid input",
  UNAUTHORIZED: "Unauthorized",
  INVALID_CREDENTIALS: "Invalid credentials",
  INVALID_TOKEN: "Invalid or expired token",
  INVALID_REFRESH_TOKEN: "Invalid or missing refresh token",
  SESSION_NOT_FOUND: "Session not found",
  MISSING_OR_INVALID_CODE: "Missing or invalid authorization code",
};

export const OPENAPI_PATHS = {
  AUTH_SIGNUP: "/api/auth/signup",
  AUTH_LOGIN: "/api/auth/login",
  AUTH_LOGOUT: "/api/auth/logout",
  AUTH_REFRESH: "/api/auth/refresh",
  AUTH_VERIFY_EMAIL: "/api/auth/verify-email/{token}",
  AUTH_RESEND_VERIFICATION: "/api/auth/resend-verification",
  AUTH_FORGOT_PASSWORD: "/api/auth/forgot-password",
  AUTH_RESET_PASSWORD: "/api/auth/reset-password",
  AUTH_SESSIONS: "/api/auth/sessions",
  AUTH_SESSION_BY_ID: "/api/auth/sessions/{id}",
  USERS_ME: "/api/users/me",
  ORGANIZATIONS: "/api/organizations",
  ORGANIZATION_BY_ID: "/api/organizations/{orgId}",
  ORGANIZATION_INVITES: "/api/organizations/{orgId}/invites",
  ORGANIZATION_INVITE_BY_ID: "/api/organizations/{orgId}/invites/{inviteId}",
  ORGANIZATION_MEMBER_ROLE: "/api/organizations/{orgId}/members/{userId}/role",
  ORGANIZATION_TRANSFER_OWNERSHIP:
    "/api/organizations/{orgId}/transfer-ownership",
  ORGANIZATION_CLIENTS: "/api/organizations/{orgId}/clients",
  ORGANIZATION_CLIENT_BY_ID: "/api/organizations/{orgId}/clients/{clientId}",
  ORGANIZATION_CLIENT_USERS:
    "/api/organizations/{orgId}/clients/{clientId}/users",
  ORGANIZATION_CLIENT_SECRET_ROTATE:
    "/api/organizations/{orgId}/clients/{clientId}/secret/rotate",
  ORGANIZATION_CLIENT_PROVIDERS:
    "/api/organizations/{orgId}/clients/{clientId}/providers",
  ORGANIZATION_CLIENT_PROVIDER_BY_ID:
    "/api/organizations/{orgId}/clients/{clientId}/providers/{provider}",
  ORGANIZATION_CLIENT_WEBHOOK:
    "/api/organizations/{orgId}/clients/{clientId}/webhook",
  ORGANIZATION_CLIENT_WEBHOOK_SECRET_ROTATE:
    "/api/organizations/{orgId}/clients/{clientId}/webhook/secret/rotate",
  ORGANIZATION_INVITE_BY_TOKEN: "/api/organizations/invites/{token}",
  ORGANIZATION_INVITE_ACCEPT: "/api/organizations/invites/accept",
  OAUTH_GOOGLE: "/api/oauth/google",
  OAUTH_GOOGLE_CALLBACK: "/api/oauth/google/callback",
  OAUTH_GITHUB: "/api/oauth/github",
  OAUTH_GITHUB_CALLBACK: "/api/oauth/github/callback",
  OAUTH_AUTHORIZE: "/api/oauth/authorize",
  OAUTH_AUTHORIZE_INIT: "/api/oauth/authorize/init",
  OAUTH_AUTHORIZE_COMPLETE: "/api/oauth/authorize/complete",
  OAUTH_TOKEN: "/api/oauth/token",
  OAUTH_USERINFO: "/api/oauth/userinfo",
  OAUTH_JWKS: "/api/oauth/jwks",
  OAUTH_DISCOVERY: "/.well-known/openid-configuration",
  OAUTH_ORG_CLIENT_PROVIDERS:
    "/api/oauth/orgs/{orgId}/clients/{clientId}/providers",
  OAUTH_ORG_CLIENT_START:
    "/api/oauth/orgs/{orgId}/clients/{clientId}/{provider}/start",
  OAUTH_ORG_CLIENT_CALLBACK:
    "/api/oauth/orgs/{orgId}/clients/{clientId}/{provider}/callback",
  OAUTH_ORG_CLIENT_CONFIRM: "/api/oauth/orgs/confirm",
};
