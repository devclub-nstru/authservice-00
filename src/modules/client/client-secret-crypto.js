import crypto from "node:crypto";
import env from "../../core/config/config.js";
import { CLIENT_SECRET_CRYPTO } from "./client.constants.js";

let cachedKey;

const decodeConfiguredKey = (rawKey) => {
  const base64 = Buffer.from(rawKey, "base64");
  if (base64.length === CLIENT_SECRET_CRYPTO.ENCRYPTION_KEY_BYTES) {
    return base64;
  }

  const hex = Buffer.from(rawKey, "hex");
  if (hex.length === CLIENT_SECRET_CRYPTO.ENCRYPTION_KEY_BYTES) {
    return hex;
  }

  throw new Error(
    "OAUTH_CLIENT_SECRET_ENCRYPTION_KEY must decode to exactly 32 bytes",
  );
};

const getEncryptionKey = () => {
  if (cachedKey) {
    return cachedKey;
  }

  cachedKey = decodeConfiguredKey(env.OAUTH_CLIENT_SECRET_ENCRYPTION_KEY);

  return cachedKey;
};

export const encryptClientSecret = (plainSecret) => {
  const iv = crypto.randomBytes(CLIENT_SECRET_CRYPTO.IV_BYTES);
  const cipher = crypto.createCipheriv(
    CLIENT_SECRET_CRYPTO.ENCRYPTION_ALGORITHM,
    getEncryptionKey(),
    iv,
    { authTagLength: CLIENT_SECRET_CRYPTO.AUTH_TAG_BYTES },
  );

  const encrypted = Buffer.concat([
    cipher.update(plainSecret, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return `${iv.toString("base64")}.${authTag.toString("base64")}.${encrypted.toString("base64")}`;
};

export const decryptClientSecret = (ciphertext) => {
  const [ivB64, authTagB64, encryptedB64] = ciphertext.split(".");

  if (!ivB64 || !authTagB64 || !encryptedB64) {
    throw new Error("Invalid encrypted client secret payload");
  }

  const iv = Buffer.from(ivB64, "base64");
  const authTag = Buffer.from(authTagB64, "base64");
  const encrypted = Buffer.from(encryptedB64, "base64");

  const decipher = crypto.createDecipheriv(
    CLIENT_SECRET_CRYPTO.ENCRYPTION_ALGORITHM,
    getEncryptionKey(),
    iv,
    { authTagLength: CLIENT_SECRET_CRYPTO.AUTH_TAG_BYTES },
  );
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString(
    "utf8",
  );
};
