import { HOUR_MS, MINUTE_MS } from "./time.constants.js";

export const RATE_LIMIT_MESSAGE = {
  error: "Too many requests",
  code: "RATE_LIMIT_EXCEEDED",
};

export const RATE_LIMIT_POLICY = {
  STANDARD_HEADERS: "draft-8",
  LEGACY_HEADERS: false,
  SIGNUP: {
    windowMs: HOUR_MS,
    limit: 3,
  },
  LOGIN: {
    windowMs: 15 * MINUTE_MS,
    limit: 5,
  },
  PASSWORD_RESET: {
    windowMs: HOUR_MS,
    limit: 3,
  },
  USER_MUTATION: {
    windowMs: 15 * MINUTE_MS,
    limit: 30,
    error: "Too many user profile update requests",
  },
};
