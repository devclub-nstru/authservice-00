import { verifyAccessToken } from "./token.service.js";
import { unauthorized } from "../../utils/errors.js";
import {
  AUTH_HEADER_PREFIX,
  TOKEN_ERROR_MESSAGES,
} from "../../core/constants/security.constants.js";
import { COOKIE_NAMES } from "../../core/constants/cookie.constants.js";

export const requireAuth = (req, _res, next) => {
  const authHeader = req.headers.authorization;
  const bearerToken = authHeader?.startsWith(AUTH_HEADER_PREFIX)
    ? authHeader.slice(AUTH_HEADER_PREFIX.length)
    : undefined;
  const token = req.cookies[COOKIE_NAMES.ACCESS_TOKEN] || bearerToken;

  if (!token) {
    unauthorized(TOKEN_ERROR_MESSAGES.MISSING_ACCESS);
  }

  const payload = verifyAccessToken(token);
  req.auth = payload;
  next();
};
