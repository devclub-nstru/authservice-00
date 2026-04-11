import rateLimit from "express-rate-limit";
import {
  RATE_LIMIT_MESSAGE,
  RATE_LIMIT_POLICY,
} from "../constants/rate-limit.constants.js";

const defaultLimiterOptions = {
  standardHeaders: RATE_LIMIT_POLICY.STANDARD_HEADERS,
  legacyHeaders: RATE_LIMIT_POLICY.LEGACY_HEADERS,
  message: RATE_LIMIT_MESSAGE,
};

export const signupLimiter = rateLimit({
  ...defaultLimiterOptions,
  windowMs: RATE_LIMIT_POLICY.SIGNUP.windowMs,
  limit: RATE_LIMIT_POLICY.SIGNUP.limit,
});

export const loginLimiter = rateLimit({
  ...defaultLimiterOptions,
  windowMs: RATE_LIMIT_POLICY.LOGIN.windowMs,
  limit: RATE_LIMIT_POLICY.LOGIN.limit,
});

export const passwordResetLimiter = rateLimit({
  ...defaultLimiterOptions,
  windowMs: RATE_LIMIT_POLICY.PASSWORD_RESET.windowMs,
  limit: RATE_LIMIT_POLICY.PASSWORD_RESET.limit,
});
