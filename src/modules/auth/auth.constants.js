import { HOUR_MS } from "../../core/constants/time.constants.js";

export const AUTH_TOKEN_BYTES = 32;

export const AUTH_TOKEN_TTL_MS = {
  EMAIL_VERIFICATION: 24 * HOUR_MS,
  PASSWORD_RESET: HOUR_MS,
};

export const AUTH_ERRORS = {
  EMAIL_EXISTS: "Email is already registered",
  INVALID_CREDENTIALS: "Invalid email or password",
  SESSION_NOT_FOUND: "Session not found",
  SESSION_INACTIVE: "Session is no longer active",
  SESSION_EXPIRED: "Session has expired",
  SESSION_VERSION_MISMATCH: "Session token version mismatch",
  SESSION_REFRESH_FAILED: "Session refresh failed",
  INVALID_VERIFICATION_TOKEN: "Invalid or expired verification token",
  INVALID_RESET_TOKEN: "Invalid or expired reset token",
};

export const AUTH_MESSAGES = {
  LOGGED_OUT: "Logged out",
  EMAIL_VERIFIED: "Email verified",
  PASSWORD_UPDATED: "Password updated",
  IF_ACCOUNT_EXISTS_EMAIL_SENT: "If the account exists, an email has been sent",
  IF_ACCOUNT_EXISTS_RESET_SENT:
    "If the account exists, a reset email has been sent",
  SESSION_REVOKED: "Session revoked",
};

export const AUTH_ROUTE_PATHS = {
  VERIFY_EMAIL: "/api/auth/verify-email",
  FRONTEND_RESET_PASSWORD: "/reset-password",
};

export const AUTH_PASSWORD_COMPLEXITY_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$/;

export const AUTH_PASSWORD_COMPLEXITY_MESSAGE =
  "Password must be at least 8 characters and include upper, lower, number, and symbol";

export const AUTH_PROFILE_NAME_LIMITS = {
  MIN: 1,
  MAX: 255,
};

export const AUTH_CLIENT_CONTEXT_LIMITS = {
  MIN: 1,
  MAX: 255,
};

export const AUTH_ONE_TIME_TOKEN_MIN_LENGTH = 16;

export const AUTH_DEVICE_CONSTANTS = {
  DEFAULT_USER_AGENT: "unknown",
  DEFAULT_IP_ADDRESS: "0.0.0.0",
  DEVICE_ID_HASH_ALGORITHM: "sha256",
  GENERATED_DEVICE_ID_BYTES: 24,
  MIN_DEVICE_ID_LENGTH: 8,
  MAX_DEVICE_ID_LENGTH: 255,
};
