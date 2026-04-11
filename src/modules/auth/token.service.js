import fs from "node:fs";
import jwt from "jsonwebtoken";
import env from "../../core/config/config.js";
import { AppError } from "../../utils/errors.js";
import {
  JWT_ALGORITHM,
  TOKEN_ERROR_CODES,
  TOKEN_ERROR_MESSAGES,
} from "../../core/constants/security.constants.js";

const accessPrivateKey = fs.readFileSync(
  env.ACCESS_TOKEN_PRIVATE_KEY_PATH,
  "utf8",
);
const accessPublicKey = fs.readFileSync(
  env.ACCESS_TOKEN_PUBLIC_KEY_PATH,
  "utf8",
);
const refreshPrivateKey = fs.readFileSync(
  env.REFRESH_TOKEN_PRIVATE_KEY_PATH,
  "utf8",
);
const refreshPublicKey = fs.readFileSync(
  env.REFRESH_TOKEN_PUBLIC_KEY_PATH,
  "utf8",
);

export const signAccessToken = (payload) => {
  return jwt.sign(payload, accessPrivateKey, {
    algorithm: JWT_ALGORITHM,
    expiresIn: env.ACCESS_TOKEN_TTL,
  });
};

export const signRefreshToken = (payload) => {
  return jwt.sign(payload, refreshPrivateKey, {
    algorithm: JWT_ALGORITHM,
    expiresIn: env.REFRESH_TOKEN_TTL,
  });
};

const mapJwtError = (error) => {
  if (error.name === "TokenExpiredError") {
    throw new AppError(TOKEN_ERROR_MESSAGES.EXPIRED, 401, {
      code: TOKEN_ERROR_CODES.EXPIRED,
    });
  }

  throw new AppError(TOKEN_ERROR_MESSAGES.INVALID, 401, {
    code: TOKEN_ERROR_CODES.INVALID,
  });
};

export const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, accessPublicKey, { algorithms: [JWT_ALGORITHM] });
  } catch (error) {
    return mapJwtError(error);
  }
};

export const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, refreshPublicKey, { algorithms: [JWT_ALGORITHM] });
  } catch (error) {
    return mapJwtError(error);
  }
};
