import { OAUTH_PROVIDERS } from "../oauth/oauth.constants.js";
import { ORGANIZATION_ROLES } from "../organization/organization.constants.js";

export const CLIENT_ALLOWED_PROVIDERS = [
  OAUTH_PROVIDERS.GOOGLE,
  OAUTH_PROVIDERS.GITHUB,
];

export const CLIENT_CALLBACK_BASE_PATH = "/api/oauth/orgs";

export const CLIENT_SECRET_BYTES = 32;

export const CLIENT_MANAGE_ROLES = [
  ORGANIZATION_ROLES.OWNER,
  ORGANIZATION_ROLES.ADMIN,
];

export const CLIENT_NAME_LIMITS = {
  MIN: 2,
  MAX: 255,
};

export const CLIENT_REDIRECT_URIS_LIMITS = {
  MIN: 1,
  MAX: 30,
};

export const CLIENT_AUTHORIZED_ORIGINS_LIMITS = {
  MAX: 30,
};

export const CLIENT_PROVIDER_CREDENTIAL_LIMITS = {
  ID_MIN: 1,
  ID_MAX: 255,
  SECRET_MIN: 8,
  SECRET_MAX: 255,
};

export const CLIENT_USER_LIST_PAGINATION = {
  DEFAULT_LIMIT: 50,
  MAX_LIMIT: 200,
  DEFAULT_OFFSET: 0,
};

export const CLIENT_SECRET_CRYPTO = {
  ENCRYPTION_ALGORITHM: "aes-256-gcm",
  IV_BYTES: 12,
  AUTH_TAG_BYTES: 16,
  ENCRYPTION_KEY_BYTES: 32,
};

export const CLIENT_ERRORS = {
  ORGANIZATION_NOT_FOUND: "Organization not found",
  CLIENT_NOT_FOUND: "Organization client not found",
  PROVIDER_NOT_FOUND: "Client provider configuration not found",
  MEMBER_REQUIRED: "You are not a collaborator in this organization",
  INSUFFICIENT_PERMISSIONS:
    "Only organization owners or admins can manage clients",
  CLIENT_NAME_EXISTS: "Client name already exists in this organization",
  PROVIDER_EXISTS: "Provider is already configured for this client",
  INVALID_PROVIDER: "Only google and github providers are supported",
  INVALID_AUTHORIZED_ORIGIN: "Authorized origins must be valid URLs",
  INVALID_REDIRECT_URI: "Redirect URIs must be valid URLs",
  REDIRECT_URI_REQUIRED: "At least one redirect URI is required",
  WEBHOOK_NOT_CONFIGURED: "Client webhook is not configured",
};

export const CLIENT_MESSAGES = {
  CLIENT_DELETED: "Organization client deleted",
  PROVIDER_REMOVED: "Provider removed from client",
  PROVIDER_CONFIGURED: "Provider configured for client",
  PROVIDER_UPDATED: "Provider credentials updated",
  WEBHOOK_CONFIGURED: "Client webhook configured",
  WEBHOOK_DISABLED: "Client webhook disabled",
  WEBHOOK_SECRET_ROTATED: "Client webhook secret rotated",
  CLIENT_SECRET_ROTATED: "Client secret rotated",
};
