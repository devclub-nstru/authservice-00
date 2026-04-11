import env from "../config/config.js";
import { COOKIE_PATH } from "../constants/cookie.constants.js";
import { MINUTE_MS, DAY_MS } from "../constants/time.constants.js";

const baseCookieOptions = {
  httpOnly: true,
  secure: env.COOKIE_SECURE ?? env.APP_ENV === "production",
  sameSite: env.COOKIE_SAME_SITE,
  domain: env.COOKIE_DOMAIN,
  path: COOKIE_PATH,
};

export const accessCookieOptions = {
  ...baseCookieOptions,
  maxAge: 15 * MINUTE_MS,
};

export const refreshCookieOptions = {
  ...baseCookieOptions,
  maxAge: env.SESSION_TTL_DAYS * DAY_MS,
};
