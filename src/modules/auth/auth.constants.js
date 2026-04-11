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
