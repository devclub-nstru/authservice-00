import rateLimit from "express-rate-limit";
import { RATE_LIMIT_POLICY } from "../constants/rate-limit.constants.js";

export const userMutationLimiter = rateLimit({
  windowMs: RATE_LIMIT_POLICY.USER_MUTATION.windowMs,
  limit: RATE_LIMIT_POLICY.USER_MUTATION.limit,
  standardHeaders: RATE_LIMIT_POLICY.STANDARD_HEADERS,
  legacyHeaders: RATE_LIMIT_POLICY.LEGACY_HEADERS,
  message: {
    error: RATE_LIMIT_POLICY.USER_MUTATION.error,
    code: "RATE_LIMIT_EXCEEDED",
  },
});
