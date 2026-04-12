import { verifyAccessToken } from "./token.service.js";
import { findSession } from "./session.service.js";
import { unauthorized } from "../../utils/errors.js";
import {
  AUTH_HEADER_PREFIX,
  TOKEN_ERROR_MESSAGES,
} from "../../core/constants/security.constants.js";
import { COOKIE_NAMES } from "../../core/constants/cookie.constants.js";

export const requireAuth = async (req, _res, next) => {
  const authHeader = req.headers.authorization;
  const bearerToken = authHeader?.startsWith(AUTH_HEADER_PREFIX)
    ? authHeader.slice(AUTH_HEADER_PREFIX.length)
    : undefined;
  const token = req.cookies[COOKIE_NAMES.ACCESS_TOKEN] || bearerToken;

  if (!token) {
    unauthorized(TOKEN_ERROR_MESSAGES.MISSING_ACCESS);
  }

  const payload = verifyAccessToken(token);

  if (!payload?.sid || !payload?.sub || typeof payload?.ver !== "number") {
    unauthorized(TOKEN_ERROR_MESSAGES.INVALID);
  }

  const session = await findSession(payload.sid);
  if (!session || !session.isActive) {
    unauthorized(TOKEN_ERROR_MESSAGES.INVALID);
  }

  if (new Date(session.expiresAt).getTime() <= Date.now()) {
    unauthorized(TOKEN_ERROR_MESSAGES.EXPIRED);
  }

  if (session.userId !== payload.sub || session.version !== payload.ver) {
    unauthorized(TOKEN_ERROR_MESSAGES.INVALID);
  }

  req.auth = payload;
  req.session = session;
  next();
};
