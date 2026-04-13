import crypto from "node:crypto";
import db from "../../db/client/db.js";
import env from "../../core/config/config.js";
import { conflict, notFound, unauthorized } from "../../utils/errors.js";
import {
  createEmailVerificationToken,
  createPasswordResetToken,
  createUser,
  findSessionByUserAndDevice,
  findUserByEmail,
  findUserById,
  listActiveSessionsByUserId,
  markEmailVerificationTokenUsed,
  markPasswordResetTokenUsed,
  findValidEmailVerificationToken,
  findValidPasswordResetToken,
  revokeAllSessionsByUserId,
  updateUserById,
} from "./auth.repository.js";
import { comparePassword, hashPassword } from "./password.service.js";
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} from "./token.service.js";
import {
  createOrReuseUserSession,
  createUserSession,
  findSession,
  rotateSession,
  revokeSession,
} from "./session.service.js";
import { deviceAlertQueue } from "../../queues/index.js";
import { queueEmailJob } from "../email/email.queue.js";
import {
  emailVerificationTemplate,
  newDeviceAlertTemplate,
  passwordChangedTemplate,
  passwordResetTemplate,
  welcomeTemplate,
} from "../email/email.templates.js";
import {
  AUTH_ERRORS,
  AUTH_ROUTE_PATHS,
  AUTH_TOKEN_BYTES,
  AUTH_TOKEN_TTL_MS,
} from "./auth.constants.js";
import { EMAIL_SUBJECTS } from "../email/email.constants.js";
import { QUEUE_JOB_NAMES } from "../../core/constants/queue.constants.js";
import { setReloginConfirmationRequirement } from "../oauth/oauth-challenge.service.js";
import { queueServiceLogoutWebhook } from "../webhook/webhook.queue.js";
import { findOrganizationClientById } from "../client/client.repository.js";

const generateOneTimeToken = () =>
  crypto.randomBytes(AUTH_TOKEN_BYTES).toString("hex");

const issueAuthTokens = ({ userId, sessionId, sessionVersion }) => {
  const payload = {
    sub: userId,
    sid: sessionId,
    ver: sessionVersion,
  };

  return {
    accessToken: signAccessToken(payload),
    refreshToken: signRefreshToken(payload),
  };
};

const sanitizeUser = (user) => {
  const { passwordHash, ...safeUser } = user;
  return safeUser;
};

export const signup = async (input, deviceInfo) => {
  const result = await db.transaction(async (tx) => {
    const existing = await findUserByEmail(input.email, tx);
    if (existing) {
      conflict(AUTH_ERRORS.EMAIL_EXISTS);
    }

    const passwordHash = await hashPassword(input.password);

    const user = await createUser(
      {
        email: input.email,
        passwordHash,
        name: input.name,
        avatarUrl: input.avatarUrl,
        emailVerified: false,
      },
      tx,
    );

    const verificationToken = generateOneTimeToken();
    const expiresAt = new Date(
      Date.now() + AUTH_TOKEN_TTL_MS.EMAIL_VERIFICATION,
    );

    await createEmailVerificationToken(
      {
        userId: user.id,
        token: verificationToken,
        email: user.email,
        expiresAt,
      },
      tx,
    );

    const session = await createUserSession(
      {
        userId: user.id,
        orgId: null,
        deviceId: deviceInfo.deviceId,
        userAgent: deviceInfo.userAgent,
        ipAddress: deviceInfo.ipAddress,
      },
      tx,
    );

    await updateUserById(user.id, { lastLoginAt: new Date() }, tx);

    return {
      user,
      session,
      verificationToken,
    };
  });

  const verificationUrl = `${env.API_BASE_URL}${AUTH_ROUTE_PATHS.VERIFY_EMAIL}/${result.verificationToken}`;

  await Promise.all([
    queueEmailJob({
      to: result.user.email,
      subject: EMAIL_SUBJECTS.WELCOME,
      html: welcomeTemplate({ name: result.user.name }),
    }),
    queueEmailJob({
      to: result.user.email,
      subject: EMAIL_SUBJECTS.VERIFY_EMAIL,
      html: emailVerificationTemplate({ verifyUrl: verificationUrl }),
    }),
  ]);

  const tokens = issueAuthTokens({
    userId: result.user.id,
    sessionId: result.session.id,
    sessionVersion: result.session.version,
  });

  return {
    ...tokens,
    user: sanitizeUser(result.user),
    session: result.session,
  };
};

export const login = async (input, deviceInfo) => {
  const user = await findUserByEmail(input.email);
  if (!user || !user.passwordHash) {
    unauthorized(AUTH_ERRORS.INVALID_CREDENTIALS);
  }

  const matches = await comparePassword(input.password, user.passwordHash);
  if (!matches) {
    unauthorized(AUTH_ERRORS.INVALID_CREDENTIALS);
  }

  const { knownDevice, session } = await db.transaction(async (tx) => {
    const existingDeviceSession = await findSessionByUserAndDevice(
      user.id,
      deviceInfo.deviceId,
      tx,
    );

    const nextSession = await createOrReuseUserSession(
      {
        userId: user.id,
        orgId: null,
        deviceId: deviceInfo.deviceId,
        userAgent: deviceInfo.userAgent,
        ipAddress: deviceInfo.ipAddress,
      },
      tx,
    );

    await updateUserById(user.id, { lastLoginAt: new Date() }, tx);

    return {
      knownDevice: existingDeviceSession,
      session: nextSession,
    };
  });

  if (!knownDevice) {
    await deviceAlertQueue.add(QUEUE_JOB_NAMES.NEW_DEVICE_ALERT, {
      userId: user.id,
      email: user.email,
      userAgent: deviceInfo.userAgent,
      ipAddress: deviceInfo.ipAddress,
    });

    await queueEmailJob({
      to: user.email,
      subject: EMAIL_SUBJECTS.NEW_DEVICE,
      html: newDeviceAlertTemplate({
        userAgent: deviceInfo.userAgent,
        ipAddress: deviceInfo.ipAddress,
        loggedInAt: new Date().toISOString(),
      }),
    });
  }

  const tokens = issueAuthTokens({
    userId: user.id,
    sessionId: session.id,
    sessionVersion: session.version,
  });

  return {
    ...tokens,
    user: sanitizeUser(user),
    session,
  };
};

export const logout = async ({
  userId,
  sessionId,
  clientId,
  clientContext,
}) => {
  const revoked = await revokeSession(userId, sessionId);
  if (!revoked) {
    notFound(AUTH_ERRORS.SESSION_NOT_FOUND);
  }

  if (!clientId || !revoked.orgId) {
    return;
  }

  const organizationClient = await findOrganizationClientById(
    revoked.orgId,
    clientId,
  );

  if (!organizationClient) {
    return;
  }

  await Promise.all([
    setReloginConfirmationRequirement({
      orgId: revoked.orgId,
      clientId,
      userId,
      clientContext: clientContext || null,
    }),
    queueServiceLogoutWebhook({
      orgId: revoked.orgId,
      clientId,
      userId,
      sessionId: revoked.id,
      clientContext: clientContext || null,
    }),
  ]);
};

export const refreshAuth = async (refreshToken) => {
  const payload = verifyRefreshToken(refreshToken);

  const currentSession = await findSession(payload.sid);
  if (!currentSession || !currentSession.isActive) {
    unauthorized(AUTH_ERRORS.SESSION_INACTIVE);
  }

  if (new Date(currentSession.expiresAt).getTime() <= Date.now()) {
    unauthorized(AUTH_ERRORS.SESSION_EXPIRED);
  }

  if (currentSession.userId !== payload.sub) {
    await revokeSession(currentSession.userId, currentSession.id);
    unauthorized(AUTH_ERRORS.SESSION_VERSION_MISMATCH);
  }

  if (currentSession.version !== payload.ver) {
    await revokeSession(currentSession.userId, currentSession.id);
    unauthorized(AUTH_ERRORS.SESSION_VERSION_MISMATCH);
  }

  const rotated = await rotateSession(
    currentSession.id,
    currentSession.version,
  );
  if (!rotated) {
    await revokeSession(currentSession.userId, currentSession.id);
    unauthorized(AUTH_ERRORS.SESSION_VERSION_MISMATCH);
  }

  const tokens = issueAuthTokens({
    userId: payload.sub,
    sessionId: rotated.id,
    sessionVersion: rotated.version,
  });

  return {
    ...tokens,
    session: rotated,
  };
};

export const verifyEmail = async (token) => {
  const verificationRecord = await findValidEmailVerificationToken(token);
  if (!verificationRecord) {
    unauthorized(AUTH_ERRORS.INVALID_VERIFICATION_TOKEN);
  }

  await db.transaction(async (tx) => {
    await markEmailVerificationTokenUsed(verificationRecord.id, tx);
    await updateUserById(
      verificationRecord.userId,
      { emailVerified: true },
      tx,
    );
  });
};

export const resendVerificationEmail = async ({ email }) => {
  const user = await findUserByEmail(email);
  if (!user) {
    return;
  }

  if (user.emailVerified) {
    return;
  }

  const token = generateOneTimeToken();
  const expiresAt = new Date(Date.now() + AUTH_TOKEN_TTL_MS.EMAIL_VERIFICATION);

  await createEmailVerificationToken({
    userId: user.id,
    email,
    token,
    expiresAt,
  });

  await queueEmailJob({
    to: email,
    subject: EMAIL_SUBJECTS.VERIFY_EMAIL,
    html: emailVerificationTemplate({
      verifyUrl: `${env.API_BASE_URL}${AUTH_ROUTE_PATHS.VERIFY_EMAIL}/${token}`,
    }),
  });
};

export const forgotPassword = async ({ email }) => {
  const user = await findUserByEmail(email);
  if (!user) {
    return;
  }

  const token = generateOneTimeToken();
  const expiresAt = new Date(Date.now() + AUTH_TOKEN_TTL_MS.PASSWORD_RESET);

  await createPasswordResetToken({
    userId: user.id,
    token,
    expiresAt,
  });

  await queueEmailJob({
    to: user.email,
    subject: EMAIL_SUBJECTS.RESET_PASSWORD,
    html: passwordResetTemplate({
      resetUrl: `${env.FRONTEND_URL}${AUTH_ROUTE_PATHS.FRONTEND_RESET_PASSWORD}?token=${token}`,
    }),
  });
};

export const resetPassword = async ({ token, password }) => {
  const resetRecord = await findValidPasswordResetToken(token);
  if (!resetRecord) {
    unauthorized(AUTH_ERRORS.INVALID_RESET_TOKEN);
  }

  await db.transaction(async (tx) => {
    const passwordHash = await hashPassword(password);

    await markPasswordResetTokenUsed(resetRecord.id, tx);
    await updateUserById(resetRecord.userId, { passwordHash }, tx);
    await revokeAllSessionsByUserId(resetRecord.userId, tx);
  });

  const user = await findUserById(resetRecord.userId);
  if (user) {
    await queueEmailJob({
      to: user.email,
      subject: EMAIL_SUBJECTS.PASSWORD_CHANGED,
      html: passwordChangedTemplate({ changedAt: new Date().toISOString() }),
    });
  }
};

export const getUserSessions = async (userId) => {
  return listActiveSessionsByUserId(userId);
};

export const revokeUserSession = async (userId, sessionId) => {
  const session = await revokeSession(userId, sessionId);
  if (!session) {
    notFound(AUTH_ERRORS.SESSION_NOT_FOUND);
  }
};
