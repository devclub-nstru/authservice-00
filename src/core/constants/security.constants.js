export const AUTH_HEADER_PREFIX = "Bearer ";
export const JWT_ALGORITHM = "RS256";

export const TOKEN_ERROR_CODES = {
  EXPIRED: "TOKEN_EXPIRED",
  INVALID: "TOKEN_INVALID",
};

export const TOKEN_ERROR_MESSAGES = {
  EXPIRED: "Token has expired",
  INVALID: "Invalid token",
  MISSING_ACCESS: "Missing access token",
  MISSING_REFRESH: "Missing refresh token",
};
