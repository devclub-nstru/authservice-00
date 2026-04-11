export const OAUTH_PROVIDERS = {
  GOOGLE: "google",
  GITHUB: "github",
};

export const OAUTH_ERRORS = {
  INVALID_PROVIDER: "Unsupported OAuth provider",
  MISSING_EMAIL: "OAuth provider did not return an email",
  MISSING_CODE: "Missing OAuth authorization code",
};

export const OAUTH_ERROR_CODES = {
  INVALID_PROVIDER: "OAUTH_PROVIDER_INVALID",
  MISSING_EMAIL: "OAUTH_EMAIL_MISSING",
};

export const OAUTH_CALLBACK_QUERY_CODE = "code";

export const OAUTH_ROUTE_PATHS = {
  GOOGLE: "/google",
  GOOGLE_CALLBACK: "/google/callback",
  GITHUB: "/github",
  GITHUB_CALLBACK: "/github/callback",
};
