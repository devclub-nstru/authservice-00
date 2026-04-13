import crypto from "node:crypto";
import { getRedisClient } from "../../core/config/redis.js";
import {
  OIDC_AUTHORIZATION_CODE_TTL_SECONDS,
  OIDC_CODE_KEY_PREFIX,
} from "./oauth.constants.js";

const getCodeKey = (code) => {
  return `${OIDC_CODE_KEY_PREFIX}:${code}`;
};

export const issueOidcAuthorizationCode = async (payload) => {
  const code = crypto.randomBytes(32).toString("base64url");
  const key = getCodeKey(code);

  const value = JSON.stringify({
    ...payload,
    issuedAt: new Date().toISOString(),
  });

  await getRedisClient().set(
    key,
    value,
    "EX",
    OIDC_AUTHORIZATION_CODE_TTL_SECONDS,
  );

  return code;
};

export const consumeOidcAuthorizationCode = async (code) => {
  const key = getCodeKey(code);

  const value = await getRedisClient().eval(
    `
      local current = redis.call('GET', KEYS[1])
      if current then
        redis.call('DEL', KEYS[1])
      end
      return current
    `,
    1,
    key,
  );

  if (!value) {
    return null;
  }

  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
};
