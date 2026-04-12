import crypto from "node:crypto";
import fs from "node:fs";
import db from "../../db/client/db.js";
import env from "../../core/config/config.js";
import {
  findUserById,
  createUser,
  findUserByEmail,
  upsertOauthAccount,
} from "./oauth.repository.js";
import {
  exchangeGoogleCode,
  fetchGoogleProfile,
  getGoogleAuthorizationUrl,
} from "./providers/google.provider.js";
import {
  exchangeGithubCode,
  fetchGithubProfile,
  getGithubAuthorizationUrl,
} from "./providers/github.provider.js";
import { createOrReuseUserSession } from "../auth/session.service.js";
import {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
} from "../auth/token.service.js";
import { AppError } from "../../utils/errors.js";
import {
  OAUTH_AUTHORIZE_CODE_CHALLENGE_METHODS,
  OAUTH_ERROR_CODES,
  OAUTH_ERRORS,
  OAUTH_FLOW_TYPES,
  OAUTH_OIDC_GRANT_TYPES,
  OAUTH_PROVIDERS,
  OAUTH_TOKEN_USE,
} from "./oauth.constants.js";
import {
  findActiveOrganizationClientProvider,
  findOrganizationClientByClientId,
  findOrganizationClientById,
  listActiveOrganizationClientProviders,
  upsertOrganizationClientUser,
} from "../client/client.repository.js";
import { decryptClientSecret } from "../client/client-secret-crypto.js";
import {
  createOauthState,
  consumeOauthState,
  readOauthState,
} from "./oauth-state.service.js";
import {
  consumeOidcAuthorizationCode,
  issueOidcAuthorizationCode,
} from "./oauth-code.service.js";
import {
  consumeReloginChallenge,
  consumeReloginConfirmationRequirement,
  createReloginChallenge,
} from "./oauth-challenge.service.js";
import { findSession } from "../auth/session.service.js";
import { comparePassword } from "../auth/password.service.js";

const OIDC_AUTHORIZE_REQUEST_TYPE = "oidc_authorize_request";
const OIDC_FRONTEND_AUTHORIZE_PATH = "/authorize";
const OIDC_AUTHORIZATION_CODE_TTL_SECONDS = 120;
const OIDC_DEFAULT_TOKEN_TTL_SECONDS = 900;
const OIDC_SUPPORTED_SCOPES = ["openid", "profile", "email"];

const normalizeScopeList = (scope) => {
  if (!scope) {
    return ["openid"];
  }

  const input = Array.isArray(scope) ? scope : String(scope).split(/\s+/);
  const normalized = Array.from(
    new Set(input.map((entry) => String(entry).trim()).filter(Boolean)),
  );

  if (!normalized.includes("openid")) {
    normalized.unshift("openid");
  }

  return normalized.filter((value) => OIDC_SUPPORTED_SCOPES.includes(value));
};

const parseDurationToSeconds = (value) => {
  const match = String(value || "")
    .trim()
    .match(/^(\d+)([smhd])$/i);
  if (!match) {
    return OIDC_DEFAULT_TOKEN_TTL_SECONDS;
  }

  const amount = Number(match[1]);
  const unit = match[2].toLowerCase();

  if (unit === "s") return amount;
  if (unit === "m") return amount * 60;
  if (unit === "h") return amount * 3600;
  if (unit === "d") return amount * 86400;

  return OIDC_DEFAULT_TOKEN_TTL_SECONDS;
};

const ACCESS_TOKEN_TTL_SECONDS = parseDurationToSeconds(env.ACCESS_TOKEN_TTL);

const extractBasicClientCredentials = (authorizationHeader) => {
  if (!authorizationHeader || !authorizationHeader.startsWith("Basic ")) {
    return null;
  }

  const encoded = authorizationHeader.slice("Basic ".length).trim();
  if (!encoded) {
    return null;
  }

  try {
    const decoded = Buffer.from(encoded, "base64").toString("utf8");
    const delimiterIndex = decoded.indexOf(":");
    if (delimiterIndex <= 0) {
      return null;
    }

    return {
      clientId: decoded.slice(0, delimiterIndex),
      clientSecret: decoded.slice(delimiterIndex + 1),
    };
  } catch {
    return null;
  }
};

const buildOidcAuthorizationRedirectUrl = ({ redirectUri, code, state }) => {
  const url = new URL(redirectUri);
  url.searchParams.set("code", code);

  if (state) {
    url.searchParams.set("state", state);
  }

  return url.toString();
};

const buildJwksKey = () => {
  const pem = fs.readFileSync(env.ACCESS_TOKEN_PUBLIC_KEY_PATH, "utf8");
  const keyObject = crypto.createPublicKey(pem);
  const exported = keyObject.export({ format: "jwk" });
  const kid = crypto
    .createHash("sha256")
    .update(`${exported.n}:${exported.e}`)
    .digest("base64url");

  return {
    ...exported,
    use: "sig",
    alg: "RS256",
    kid,
  };
};

const OIDC_JWKS_KEY = buildJwksKey();

const getProviderAuthorizationUrl = (provider, credentials = {}) => {
  if (provider === OAUTH_PROVIDERS.GOOGLE) {
    return getGoogleAuthorizationUrl(credentials);
  }

  if (provider === OAUTH_PROVIDERS.GITHUB) {
    return getGithubAuthorizationUrl(credentials);
  }

  throw new AppError(OAUTH_ERRORS.INVALID_PROVIDER, 400, {
    code: OAUTH_ERROR_CODES.INVALID_PROVIDER,
  });
};

const getProviderProfile = async (provider, code, credentials = {}) => {
  if (provider === OAUTH_PROVIDERS.GOOGLE) {
    const tokenPayload = await exchangeGoogleCode(code, credentials);
    const profile = await fetchGoogleProfile(tokenPayload.access_token);

    return {
      profile,
      accessToken: tokenPayload.access_token,
      refreshToken: tokenPayload.refresh_token,
      expiresAt: tokenPayload.expires_in
        ? new Date(Date.now() + tokenPayload.expires_in * 1000)
        : null,
    };
  }

  if (provider === OAUTH_PROVIDERS.GITHUB) {
    const tokenPayload = await exchangeGithubCode(code, credentials);
    const profile = await fetchGithubProfile(tokenPayload.access_token);

    return {
      profile,
      accessToken: tokenPayload.access_token,
      refreshToken: tokenPayload.refresh_token,
      expiresAt: null,
    };
  }

  throw new AppError(OAUTH_ERRORS.INVALID_PROVIDER, 400, {
    code: OAUTH_ERROR_CODES.INVALID_PROVIDER,
  });
};

export const getOauthStartUrl = (provider) => {
  return getProviderAuthorizationUrl(provider);
};

const validateReturnTo = (returnTo, redirectUris) => {
  const returnToUrl = new URL(returnTo);
  const normalizedReturnTo = returnToUrl.toString();
  const allowedRedirectUris = Array.isArray(redirectUris) ? redirectUris : [];

  if (allowedRedirectUris.length === 0) {
    throw new AppError(OAUTH_ERRORS.RETURN_TO_NOT_ALLOWED, 400, {
      code: OAUTH_ERROR_CODES.RETURN_TO_NOT_ALLOWED,
      details: {
        reason: "No redirect URIs configured for client",
      },
    });
  }

  if (!allowedRedirectUris.includes(normalizedReturnTo)) {
    throw new AppError(OAUTH_ERRORS.RETURN_TO_NOT_ALLOWED, 400, {
      code: OAUTH_ERROR_CODES.RETURN_TO_NOT_ALLOWED,
      details: {
        returnTo: normalizedReturnTo,
      },
    });
  }

  return normalizedReturnTo;
};

const validateClientRedirectUri = (redirectUri, redirectUris) => {
  let normalizedRedirectUri;

  try {
    normalizedRedirectUri = new URL(redirectUri).toString();
  } catch {
    throw new AppError(OAUTH_ERRORS.INVALID_REDIRECT_URI, 400, {
      code: OAUTH_ERROR_CODES.INVALID_REDIRECT_URI,
    });
  }

  const allowedRedirectUris = Array.isArray(redirectUris) ? redirectUris : [];
  if (!allowedRedirectUris.includes(normalizedRedirectUri)) {
    throw new AppError(OAUTH_ERRORS.INVALID_REDIRECT_URI, 400, {
      code: OAUTH_ERROR_CODES.INVALID_REDIRECT_URI,
      details: {
        redirectUri: normalizedRedirectUri,
      },
    });
  }

  return normalizedRedirectUri;
};

const buildFrontendAuthorizeRedirectUrl = (requestToken) => {
  const url = new URL(OIDC_FRONTEND_AUTHORIZE_PATH, env.FRONTEND_URL);
  url.searchParams.set("request", requestToken);
  return url.toString();
};

const resolveClientOauthProviderConfig = async (orgId, clientId, provider) => {
  const providerConfig = await findActiveOrganizationClientProvider(
    orgId,
    clientId,
    provider,
  );

  if (!providerConfig) {
    throw new AppError(OAUTH_ERRORS.CLIENT_PROVIDER_NOT_CONFIGURED, 404, {
      code: OAUTH_ERROR_CODES.CLIENT_PROVIDER_NOT_CONFIGURED,
    });
  }

  return providerConfig;
};

const buildTokenPayload = (user, session) => ({
  sub: user.id,
  sid: session.id,
  ver: session.version,
});

const completeOauthAuthSession = async ({
  provider,
  providerData,
  deviceInfo,
  orgId = null,
  clientId = null,
}) => {
  if (!providerData.profile.email) {
    throw new AppError(OAUTH_ERRORS.MISSING_EMAIL, 400, {
      code: OAUTH_ERROR_CODES.MISSING_EMAIL,
    });
  }

  const { user, session } = await db.transaction(async (tx) => {
    let oauthUser = await findUserByEmail(providerData.profile.email, tx);

    if (!oauthUser) {
      oauthUser = await createUser(
        {
          email: providerData.profile.email,
          name: providerData.profile.name,
          avatarUrl: providerData.profile.avatarUrl,
          emailVerified: true,
          passwordHash: null,
        },
        tx,
      );
    }

    await upsertOauthAccount(
      {
        userId: oauthUser.id,
        provider,
        providerAccountId: providerData.profile.providerAccountId,
        accessToken: providerData.accessToken,
        refreshToken: providerData.refreshToken,
        expiresAt: providerData.expiresAt,
      },
      tx,
    );

    const sessionRow = await createOrReuseUserSession(
      {
        userId: oauthUser.id,
        orgId,
        clientId,
        deviceId: deviceInfo.deviceId,
        userAgent: deviceInfo.userAgent,
        ipAddress: deviceInfo.ipAddress,
      },
      tx,
    );

    if (clientId) {
      await upsertOrganizationClientUser(clientId, oauthUser.id, tx);
    }

    return { user: oauthUser, session: sessionRow };
  });

  const payload = buildTokenPayload(user, session);

  return {
    user,
    session,
    accessToken: signAccessToken(payload),
    refreshToken: signRefreshToken(payload),
  };
};

export const startOidcAuthorize = async ({
  responseType,
  clientId,
  redirectUri,
  scope,
  state,
  nonce,
  codeChallenge,
  codeChallengeMethod,
}) => {
  if (responseType !== "code") {
    throw new AppError(OAUTH_ERRORS.INVALID_RESPONSE_TYPE, 400, {
      code: OAUTH_ERROR_CODES.INVALID_RESPONSE_TYPE,
    });
  }

  const client = await findOrganizationClientByClientId(clientId);
  if (!client) {
    throw new AppError(OAUTH_ERRORS.INVALID_CLIENT, 404, {
      code: OAUTH_ERROR_CODES.INVALID_CLIENT,
    });
  }

  const normalizedRedirectUri = validateClientRedirectUri(
    redirectUri,
    client.redirectUris,
  );

  const normalizedScopes = normalizeScopeList(scope);

  if (codeChallengeMethod && !codeChallenge) {
    throw new AppError(OAUTH_ERRORS.UNSUPPORTED_CODE_CHALLENGE_METHOD, 400, {
      code: OAUTH_ERROR_CODES.UNSUPPORTED_CODE_CHALLENGE_METHOD,
    });
  }

  if (codeChallenge && !codeChallengeMethod) {
    throw new AppError(OAUTH_ERRORS.UNSUPPORTED_CODE_CHALLENGE_METHOD, 400, {
      code: OAUTH_ERROR_CODES.UNSUPPORTED_CODE_CHALLENGE_METHOD,
    });
  }

  if (
    codeChallengeMethod &&
    codeChallengeMethod !== OAUTH_AUTHORIZE_CODE_CHALLENGE_METHODS.S256
  ) {
    throw new AppError(OAUTH_ERRORS.UNSUPPORTED_CODE_CHALLENGE_METHOD, 400, {
      code: OAUTH_ERROR_CODES.UNSUPPORTED_CODE_CHALLENGE_METHOD,
    });
  }

  const requestToken = await createOauthState({
    type: OIDC_AUTHORIZE_REQUEST_TYPE,
    responseType,
    clientId: client.id,
    orgId: client.orgId,
    redirectUri: normalizedRedirectUri,
    scope: normalizedScopes,
    state: state || null,
    nonce: nonce || null,
    codeChallenge: codeChallenge || null,
    codeChallengeMethod: codeChallengeMethod || null,
  });

  return {
    requestToken,
    redirectUrl: buildFrontendAuthorizeRedirectUrl(requestToken),
  };
};

export const getOidcAuthorizeInitiation = async ({ requestToken }) => {
  const request = await readOauthState(requestToken);
  if (!request || request.type !== OIDC_AUTHORIZE_REQUEST_TYPE) {
    throw new AppError(OAUTH_ERRORS.INVALID_REQUEST_REFERENCE, 400, {
      code: OAUTH_ERROR_CODES.INVALID_REQUEST_REFERENCE,
    });
  }

  const client = await findOrganizationClientById(
    request.orgId,
    request.clientId,
  );
  if (!client) {
    throw new AppError(OAUTH_ERRORS.INVALID_CLIENT, 404, {
      code: OAUTH_ERROR_CODES.INVALID_CLIENT,
    });
  }

  const normalizedRedirectUri = validateClientRedirectUri(
    request.redirectUri,
    client.redirectUris,
  );

  const providers = await listActiveOrganizationClientProviders(
    client.orgId,
    client.id,
  );

  const providerLinks = await Promise.all(
    providers.map(async (entry) => {
      const start = await getOrganizationClientOauthStart({
        orgId: client.orgId,
        clientId: client.id,
        provider: entry.provider,
        returnTo: normalizedRedirectUri,
        flowType: OAUTH_FLOW_TYPES.SIGNIN,
        oidcContext: {
          responseType: request.responseType,
          scope: request.scope,
          state: request.state,
          nonce: request.nonce,
          codeChallenge: request.codeChallenge,
          codeChallengeMethod: request.codeChallengeMethod,
        },
      });

      return {
        provider: entry.provider,
        authorizationUrl: start.redirectUrl,
      };
    }),
  );

  return {
    client: {
      id: client.id,
      orgId: client.orgId,
      name: client.name,
    },
    request: {
      responseType: request.responseType,
      clientId: client.id,
      redirectUri: normalizedRedirectUri,
      scope: request.scope,
      state: request.state,
      nonce: request.nonce,
      codeChallenge: request.codeChallenge,
      codeChallengeMethod: request.codeChallengeMethod,
    },
    providers: providerLinks,
  };
};

const buildOidcAccessTokenPayload = ({ userId, clientId, scope }) => {
  return {
    iss: env.API_BASE_URL,
    aud: clientId,
    sub: userId,
    client_id: clientId,
    token_use: OAUTH_TOKEN_USE.OIDC_ACCESS,
    scope: scope.join(" "),
  };
};

const buildOidcIdTokenPayload = ({
  user,
  clientId,
  scope,
  nonce,
  authenticatedAt,
}) => {
  const payload = {
    iss: env.API_BASE_URL,
    aud: clientId,
    sub: user.id,
    auth_time: Math.floor(new Date(authenticatedAt).getTime() / 1000),
  };

  if (nonce) {
    payload.nonce = nonce;
  }

  if (scope.includes("email")) {
    payload.email = user.email;
    payload.email_verified = Boolean(user.emailVerified);
  }

  if (scope.includes("profile")) {
    payload.name = user.name || undefined;
    payload.picture = user.avatarUrl || undefined;
  }

  return payload;
};

const issueAuthorizationCodeForRequest = async ({ request, userId }) => {
  const client = await findOrganizationClientById(
    request.orgId,
    request.clientId,
  );
  if (!client) {
    throw new AppError(OAUTH_ERRORS.INVALID_CLIENT, 404, {
      code: OAUTH_ERROR_CODES.INVALID_CLIENT,
    });
  }

  const normalizedRedirectUri = validateClientRedirectUri(
    request.redirectUri,
    client.redirectUris,
  );

  await upsertOrganizationClientUser(client.id, userId);

  const code = await issueOidcAuthorizationCode({
    type: OIDC_AUTHORIZE_REQUEST_TYPE,
    clientId: client.id,
    orgId: client.orgId,
    userId,
    redirectUri: normalizedRedirectUri,
    scope: normalizeScopeList(request.scope),
    state: request.state || null,
    nonce: request.nonce || null,
    codeChallenge: request.codeChallenge || null,
    codeChallengeMethod: request.codeChallengeMethod || null,
    authenticatedAt: new Date().toISOString(),
  });

  return {
    code,
    redirectUrl: buildOidcAuthorizationRedirectUrl({
      redirectUri: normalizedRedirectUri,
      code,
      state: request.state,
    }),
  };
};

export const completeOidcAuthorizeRequest = async ({
  requestToken,
  userId,
}) => {
  const request = await consumeOauthState(requestToken);
  if (!request || request.type !== OIDC_AUTHORIZE_REQUEST_TYPE) {
    throw new AppError(OAUTH_ERRORS.INVALID_REQUEST_REFERENCE, 400, {
      code: OAUTH_ERROR_CODES.INVALID_REQUEST_REFERENCE,
    });
  }

  return issueAuthorizationCodeForRequest({ request, userId });
};

export const exchangeOidcToken = async ({ body, authorizationHeader }) => {
  if (body.grant_type !== OAUTH_OIDC_GRANT_TYPES.AUTHORIZATION_CODE) {
    throw new AppError(OAUTH_ERRORS.UNSUPPORTED_GRANT_TYPE, 400, {
      code: OAUTH_ERROR_CODES.UNSUPPORTED_GRANT_TYPE,
    });
  }

  const basicCredentials = extractBasicClientCredentials(authorizationHeader);
  const clientId = basicCredentials?.clientId || body.client_id;
  const clientSecret = basicCredentials?.clientSecret || body.client_secret;

  if (!clientId || !clientSecret) {
    throw new AppError(OAUTH_ERRORS.INVALID_CLIENT_SECRET, 401, {
      code: OAUTH_ERROR_CODES.INVALID_CLIENT_SECRET,
    });
  }

  const client = await findOrganizationClientByClientId(clientId);
  if (!client || !client.clientSecretHash) {
    throw new AppError(OAUTH_ERRORS.INVALID_CLIENT, 401, {
      code: OAUTH_ERROR_CODES.INVALID_CLIENT,
    });
  }

  const validSecret = await comparePassword(
    clientSecret,
    client.clientSecretHash,
  );
  if (!validSecret) {
    throw new AppError(OAUTH_ERRORS.INVALID_CLIENT_SECRET, 401, {
      code: OAUTH_ERROR_CODES.INVALID_CLIENT_SECRET,
    });
  }

  const codePayload = await consumeOidcAuthorizationCode(body.code);
  if (!codePayload || codePayload.type !== OIDC_AUTHORIZE_REQUEST_TYPE) {
    throw new AppError(OAUTH_ERRORS.INVALID_GRANT, 400, {
      code: OAUTH_ERROR_CODES.INVALID_GRANT,
    });
  }

  if (codePayload.clientId !== client.id) {
    throw new AppError(OAUTH_ERRORS.INVALID_GRANT, 400, {
      code: OAUTH_ERROR_CODES.INVALID_GRANT,
    });
  }

  const normalizedRedirectUri = validateClientRedirectUri(
    body.redirect_uri,
    client.redirectUris,
  );
  if (normalizedRedirectUri !== codePayload.redirectUri) {
    throw new AppError(OAUTH_ERRORS.INVALID_GRANT, 400, {
      code: OAUTH_ERROR_CODES.INVALID_GRANT,
    });
  }

  if (codePayload.codeChallenge || codePayload.codeChallengeMethod) {
    if (
      codePayload.codeChallengeMethod !==
      OAUTH_AUTHORIZE_CODE_CHALLENGE_METHODS.S256
    ) {
      throw new AppError(OAUTH_ERRORS.UNSUPPORTED_CODE_CHALLENGE_METHOD, 400, {
        code: OAUTH_ERROR_CODES.UNSUPPORTED_CODE_CHALLENGE_METHOD,
      });
    }

    if (!body.code_verifier) {
      throw new AppError(OAUTH_ERRORS.INVALID_CODE_VERIFIER, 400, {
        code: OAUTH_ERROR_CODES.INVALID_CODE_VERIFIER,
      });
    }

    const computedChallenge = crypto
      .createHash("sha256")
      .update(body.code_verifier)
      .digest("base64url");

    if (computedChallenge !== codePayload.codeChallenge) {
      throw new AppError(OAUTH_ERRORS.INVALID_CODE_VERIFIER, 400, {
        code: OAUTH_ERROR_CODES.INVALID_CODE_VERIFIER,
      });
    }
  }

  const user = await findUserById(codePayload.userId);
  if (!user) {
    throw new AppError(OAUTH_ERRORS.INVALID_GRANT, 400, {
      code: OAUTH_ERROR_CODES.INVALID_GRANT,
    });
  }

  const scope = normalizeScopeList(codePayload.scope);
  const accessToken = signAccessToken(
    buildOidcAccessTokenPayload({
      userId: user.id,
      clientId: client.id,
      scope,
    }),
  );
  const idToken = signAccessToken(
    buildOidcIdTokenPayload({
      user,
      clientId: client.id,
      scope,
      nonce: codePayload.nonce,
      authenticatedAt: codePayload.authenticatedAt || codePayload.issuedAt,
    }),
  );

  return {
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    access_token: accessToken,
    id_token: idToken,
    scope: scope.join(" "),
  };
};

export const getOidcUserInfo = async (accessToken) => {
  const payload = verifyAccessToken(accessToken);

  if (payload?.token_use !== OAUTH_TOKEN_USE.OIDC_ACCESS) {
    throw new AppError(OAUTH_ERRORS.INVALID_GRANT, 401, {
      code: OAUTH_ERROR_CODES.INVALID_GRANT,
    });
  }

  const user = await findUserById(payload.sub);
  if (!user) {
    throw new AppError(OAUTH_ERRORS.INVALID_GRANT, 401, {
      code: OAUTH_ERROR_CODES.INVALID_GRANT,
    });
  }

  const scope = normalizeScopeList(payload.scope);
  const response = {
    sub: user.id,
  };

  if (scope.includes("email")) {
    response.email = user.email;
    response.email_verified = Boolean(user.emailVerified);
  }

  if (scope.includes("profile")) {
    response.name = user.name;
    response.picture = user.avatarUrl;
  }

  return response;
};

export const getOidcJwks = () => {
  return {
    keys: [OIDC_JWKS_KEY],
  };
};

export const getOidcDiscoveryDocument = () => {
  return {
    issuer: env.API_BASE_URL,
    authorization_endpoint: `${env.API_BASE_URL}/api/oauth/authorize`,
    token_endpoint: `${env.API_BASE_URL}/api/oauth/token`,
    userinfo_endpoint: `${env.API_BASE_URL}/api/oauth/userinfo`,
    jwks_uri: `${env.API_BASE_URL}/api/oauth/jwks`,
    response_types_supported: ["code"],
    grant_types_supported: [OAUTH_OIDC_GRANT_TYPES.AUTHORIZATION_CODE],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: OIDC_SUPPORTED_SCOPES,
    claims_supported: [
      "sub",
      "aud",
      "iss",
      "exp",
      "iat",
      "auth_time",
      "nonce",
      "email",
      "email_verified",
      "name",
      "picture",
    ],
    token_endpoint_auth_methods_supported: [
      "client_secret_basic",
      "client_secret_post",
    ],
    code_challenge_methods_supported: [
      OAUTH_AUTHORIZE_CODE_CHALLENGE_METHODS.S256,
    ],
  };
};

export const listOrganizationClientOauthProviders = async ({
  orgId,
  clientId,
}) => {
  const client = await findOrganizationClientById(orgId, clientId);
  if (!client) {
    throw new AppError(OAUTH_ERRORS.CLIENT_PROVIDER_NOT_CONFIGURED, 404, {
      code: OAUTH_ERROR_CODES.CLIENT_PROVIDER_NOT_CONFIGURED,
    });
  }

  const providers = await listActiveOrganizationClientProviders(
    orgId,
    clientId,
  );

  return {
    client: {
      id: client.id,
      orgId: client.orgId,
      name: client.name,
    },
    providers: providers.map((entry) => ({
      provider: entry.provider,
      startUrl: `${env.API_BASE_URL}/api/oauth/orgs/${orgId}/clients/${clientId}/${entry.provider}/start`,
    })),
  };
};

export const getOrganizationClientOauthStart = async ({
  orgId,
  clientId,
  provider,
  returnTo,
  flowType = OAUTH_FLOW_TYPES.SIGNIN,
  clientContext,
  oidcContext,
}) => {
  const providerConfig = await resolveClientOauthProviderConfig(
    orgId,
    clientId,
    provider,
  );

  const normalizedReturnTo = validateReturnTo(
    returnTo || env.FRONTEND_URL,
    providerConfig.redirectUris,
  );

  const stateToken = await createOauthState({
    orgId,
    clientId,
    provider,
    returnTo: normalizedReturnTo,
    flowType,
    clientContext: clientContext || null,
    oidcContext: oidcContext || null,
  });

  const redirectUrl = getProviderAuthorizationUrl(provider, {
    clientId: providerConfig.providerClientId,
    redirectUri: providerConfig.callbackUrl,
    state: stateToken,
    nonce: oidcContext?.nonce,
    scope:
      provider === OAUTH_PROVIDERS.GOOGLE && Array.isArray(oidcContext?.scope)
        ? oidcContext.scope.join(" ")
        : undefined,
  });

  return {
    stateToken,
    redirectUrl,
  };
};

export const handleOauthCallback = async ({ provider, code, deviceInfo }) => {
  const providerData = await getProviderProfile(provider, code);
  const result = await completeOauthAuthSession({
    provider,
    providerData,
    deviceInfo,
    orgId: null,
  });

  return {
    ...result,
    redirectTo: env.FRONTEND_URL,
  };
};

export const handleOrganizationClientOauthCallback = async ({
  orgId,
  clientId,
  provider,
  code,
  stateToken,
  deviceInfo,
}) => {
  const state = await consumeOauthState(stateToken);
  if (!state) {
    throw new AppError(OAUTH_ERRORS.INVALID_STATE, 400, {
      code: OAUTH_ERROR_CODES.INVALID_STATE,
    });
  }

  if (
    state.orgId !== orgId ||
    state.clientId !== clientId ||
    state.provider !== provider
  ) {
    throw new AppError(OAUTH_ERRORS.STATE_MISMATCH, 400, {
      code: OAUTH_ERROR_CODES.INVALID_STATE,
    });
  }

  const providerConfig = await resolveClientOauthProviderConfig(
    orgId,
    clientId,
    provider,
  );

  if (!providerConfig.providerClientSecretCiphertext) {
    throw new AppError(OAUTH_ERRORS.CLIENT_PROVIDER_SECRET_UNAVAILABLE, 400, {
      code: OAUTH_ERROR_CODES.CLIENT_PROVIDER_SECRET_UNAVAILABLE,
    });
  }

  const providerData = await getProviderProfile(provider, code, {
    clientId: providerConfig.providerClientId,
    clientSecret: decryptClientSecret(
      providerConfig.providerClientSecretCiphertext,
    ),
    redirectUri: providerConfig.callbackUrl,
  });

  const authResult = await completeOauthAuthSession({
    provider,
    providerData,
    deviceInfo,
    orgId,
    clientId,
  });

  const reloginRequirement = await consumeReloginConfirmationRequirement({
    orgId,
    clientId,
    userId: authResult.user.id,
  });

  if (state.oidcContext) {
    const authorizationResult = await issueAuthorizationCodeForRequest({
      request: {
        type: OIDC_AUTHORIZE_REQUEST_TYPE,
        orgId,
        clientId,
        redirectUri: state.returnTo,
        scope: state.oidcContext.scope,
        state: state.oidcContext.state,
        nonce: state.oidcContext.nonce,
        codeChallenge: state.oidcContext.codeChallenge,
        codeChallengeMethod: state.oidcContext.codeChallengeMethod,
      },
      userId: authResult.user.id,
    });

    return {
      ...authResult,
      redirectTo: authorizationResult.redirectUrl,
      flowType: state.flowType,
      clientContext: state.clientContext,
      confirmationRequired: false,
      oidcCompleted: true,
    };
  }

  if (reloginRequirement) {
    const challengeToken = await createReloginChallenge({
      userId: authResult.user.id,
      sessionId: authResult.session.id,
      sessionVersion: authResult.session.version,
      orgId,
      clientId,
      flowType: state.flowType,
      clientContext: state.clientContext,
      redirectTo: state.returnTo,
    });

    return {
      ...authResult,
      redirectTo: state.returnTo,
      flowType: state.flowType,
      clientContext: state.clientContext,
      confirmationRequired: true,
      challengeToken,
    };
  }

  return {
    ...authResult,
    redirectTo: state.returnTo,
    flowType: state.flowType,
    clientContext: state.clientContext,
    confirmationRequired: false,
  };
};

export const confirmOrganizationOauthChallenge = async (challengeToken) => {
  const challenge = await consumeReloginChallenge(challengeToken);
  if (!challenge) {
    throw new AppError(OAUTH_ERRORS.INVALID_STATE, 400, {
      code: OAUTH_ERROR_CODES.INVALID_STATE,
    });
  }

  const session = await findSession(challenge.sessionId);
  if (
    !session ||
    !session.isActive ||
    session.version !== challenge.sessionVersion
  ) {
    throw new AppError(OAUTH_ERRORS.INVALID_STATE, 400, {
      code: OAUTH_ERROR_CODES.INVALID_STATE,
    });
  }

  const payload = {
    sub: challenge.userId,
    sid: challenge.sessionId,
    ver: challenge.sessionVersion,
  };

  return {
    accessToken: signAccessToken(payload),
    refreshToken: signRefreshToken(payload),
    redirectTo: challenge.redirectTo,
    flowType: challenge.flowType,
    clientContext: challenge.clientContext,
  };
};
