import crypto from "node:crypto";
import { COOKIE_NAMES } from "../../core/constants/cookie.constants.js";
import { AUTH_DEVICE_CONSTANTS } from "./auth.constants.js";

export const getRequestIp = (req) => {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    return forwarded.split(",")[0].trim();
  }

  return (
    req.ip ||
    req.socket?.remoteAddress ||
    AUTH_DEVICE_CONSTANTS.DEFAULT_IP_ADDRESS
  );
};

export const buildDeviceId = ({ userAgent, ipAddress }) => {
  const input = `${userAgent || AUTH_DEVICE_CONSTANTS.DEFAULT_USER_AGENT}`;
  return crypto
    .createHash(AUTH_DEVICE_CONSTANTS.DEVICE_ID_HASH_ALGORITHM)
    .update(input)
    .digest("hex");
};

const isValidDeviceId = (value) => {
  return (
    typeof value === "string" &&
    value.length >= AUTH_DEVICE_CONSTANTS.MIN_DEVICE_ID_LENGTH &&
    value.length <= AUTH_DEVICE_CONSTANTS.MAX_DEVICE_ID_LENGTH
  );
};

const generateDeviceId = () => {
  return crypto
    .randomBytes(AUTH_DEVICE_CONSTANTS.GENERATED_DEVICE_ID_BYTES)
    .toString("base64url");
};

export const buildRequestDevice = (req) => {
  const userAgent =
    req.headers["user-agent"] || AUTH_DEVICE_CONSTANTS.DEFAULT_USER_AGENT;
  const ipAddress = getRequestIp(req);
  const cookieDeviceId = req.cookies?.[COOKIE_NAMES.DEVICE_ID];
  const headerDeviceId = req.headers["x-device-id"];

  if (isValidDeviceId(headerDeviceId)) {
    return {
      userAgent,
      ipAddress,
      deviceId: headerDeviceId,
      shouldSetDeviceCookie: cookieDeviceId !== headerDeviceId,
    };
  }

  if (isValidDeviceId(cookieDeviceId)) {
    return {
      userAgent,
      ipAddress,
      deviceId: cookieDeviceId,
      shouldSetDeviceCookie: false,
    };
  }

  const generatedDeviceId = generateDeviceId();

  return {
    userAgent,
    ipAddress,
    deviceId: generatedDeviceId,
    shouldSetDeviceCookie: true,
  };
};
