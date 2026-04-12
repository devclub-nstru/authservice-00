import {
  accessCookieOptions,
  deviceCookieOptions,
  refreshCookieOptions,
} from "../../core/auth/cookie.js";
import { badRequest } from "../../utils/errors.js";
import {
  AUDIT_CATEGORY,
  AUDIT_EVENTS,
  AUDIT_STATUS,
} from "../audit/audit.events.js";
import {
  buildAuditContextFromRequest,
  emitAuditEvent,
} from "../audit/audit.service.js";
import { buildRequestDevice } from "../auth/device.service.js";
import {
  completeOidcAuthorizeRequest,
  exchangeOidcToken,
  getOidcDiscoveryDocument,
  getOidcJwks,
  getOidcUserInfo,
  getOrganizationClientOauthStart,
  getOidcAuthorizeInitiation,
  handleOauthCallback,
  handleOrganizationClientOauthCallback,
  getOauthStartUrl,
  listOrganizationClientOauthProviders,
  startOidcAuthorize,
} from "./oauth.service.js";
import {
  OAUTH_CALLBACK_QUERY_CODE,
  OAUTH_CALLBACK_QUERY_STATE,
  OAUTH_ERRORS,
} from "./oauth.constants.js";
import { COOKIE_NAMES } from "../../core/constants/cookie.constants.js";
import { AUDIT_MESSAGES } from "../audit/audit.messages.js";
import {
  confirmOrganizationOauthChallengeSchema,
  oidcAuthorizeCompleteBodySchema,
  oidcAuthorizeInitQuerySchema,
  oidcAuthorizeQuerySchema,
  oidcTokenBodySchema,
  organizationOauthCallbackQuerySchema,
  organizationOauthParamSchema,
  organizationOauthProvidersParamSchema,
  organizationOauthStartQuerySchema,
} from "../../validations/oauth/oauth.validators.js";
import { confirmOrganizationOauthChallenge } from "./oauth.service.js";
import { OAUTH_CALLBACK_QUERY_CHALLENGE_TOKEN } from "./oauth.constants.js";

const setAuthCookies = (res, tokens, deviceInfo = null) => {
  res.cookie(
    COOKIE_NAMES.ACCESS_TOKEN,
    tokens.accessToken,
    accessCookieOptions,
  );
  res.cookie(
    COOKIE_NAMES.REFRESH_TOKEN,
    tokens.refreshToken,
    refreshCookieOptions,
  );

  if (deviceInfo?.deviceId) {
    res.cookie(
      COOKIE_NAMES.DEVICE_ID,
      deviceInfo.deviceId,
      deviceCookieOptions,
    );
  }
};

export const oidcAuthorizeHandler = async (req, res) => {
  const query = oidcAuthorizeQuerySchema.parse(req.query);
  const auditContext = buildAuditContextFromRequest(req);

  const result = await startOidcAuthorize({
    responseType: query.response_type,
    clientId: query.client_id,
    redirectUri: query.redirect_uri,
    scope: query.scope,
    state: query.state,
    nonce: query.nonce,
    codeChallenge: query.code_challenge,
    codeChallengeMethod: query.code_challenge_method,
  });

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.OAUTH_START,
    category: AUDIT_CATEGORY.OAUTH,
    status: AUDIT_STATUS.SUCCESS,
    message: AUDIT_MESSAGES.OAUTH_START,
    metadata: {
      clientId: query.client_id,
      responseType: query.response_type,
      redirectUri: query.redirect_uri,
    },
  });

  res.redirect(result.redirectUrl);
};

export const oidcAuthorizeCompleteHandler = async (req, res) => {
  const payload = oidcAuthorizeCompleteBodySchema.parse(req.body || {});

  const result = await completeOidcAuthorizeRequest({
    requestToken: payload.request,
    userId: req.auth.sub,
  });

  res.status(200).json(result);
};

export const oidcAuthorizeInitHandler = async (req, res) => {
  const query = oidcAuthorizeInitQuerySchema.parse(req.query);
  const auditContext = buildAuditContextFromRequest(req);

  const result = await getOidcAuthorizeInitiation({
    requestToken: query.request,
  });

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.OAUTH_START,
    category: AUDIT_CATEGORY.OAUTH,
    status: AUDIT_STATUS.SUCCESS,
    orgId: result.client.orgId,
    message: AUDIT_MESSAGES.OAUTH_START,
    metadata: {
      clientId: result.client.id,
      providers: result.providers.length,
      initiation: "oidc",
    },
  });

  res.status(200).json(result);
};

export const oidcTokenHandler = async (req, res) => {
  const payload = oidcTokenBodySchema.parse(req.body || {});

  const result = await exchangeOidcToken({
    body: payload,
    authorizationHeader: req.headers.authorization,
  });

  res.status(200).json(result);
};

export const oidcUserInfoHandler = async (req, res) => {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith("Bearer ")) {
    badRequest("Missing Bearer access token");
  }

  const token = authorization.slice("Bearer ".length).trim();
  const result = await getOidcUserInfo(token);

  res.status(200).json(result);
};

export const oidcJwksHandler = async (_req, res) => {
  res.status(200).json(getOidcJwks());
};

export const oidcDiscoveryHandler = async (_req, res) => {
  res.status(200).json(getOidcDiscoveryDocument());
};

export const oauthStartHandler = async (req, res) => {
  const provider = req.params.provider;
  const auditContext = buildAuditContextFromRequest(req);
  const redirectUrl = getOauthStartUrl(provider);

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.OAUTH_START,
    category: AUDIT_CATEGORY.OAUTH,
    status: AUDIT_STATUS.SUCCESS,
    message: AUDIT_MESSAGES.OAUTH_START,
    metadata: {
      provider,
    },
  });

  res.redirect(redirectUrl);
};

export const oauthCallbackHandler = async (req, res) => {
  const provider = req.params.provider;
  const code = req.query[OAUTH_CALLBACK_QUERY_CODE];
  const auditContext = buildAuditContextFromRequest(req);

  if (!code || typeof code !== "string") {
    await emitAuditEvent({
      ...auditContext,
      event: AUDIT_EVENTS.OAUTH_CALLBACK_FAILED,
      category: AUDIT_CATEGORY.OAUTH,
      status: AUDIT_STATUS.FAILURE,
      severity: "warn",
      message: AUDIT_MESSAGES.OAUTH_CALLBACK_FAILED_MISSING_CODE,
      metadata: {
        provider,
      },
    });

    badRequest(OAUTH_ERRORS.MISSING_CODE);
  }

  try {
    const deviceInfo = buildRequestDevice(req);
    const result = await handleOauthCallback({
      provider,
      code,
      deviceInfo,
    });

    await emitAuditEvent({
      ...auditContext,
      actorUserId: result.user.id,
      sessionId: result.session.id,
      event: AUDIT_EVENTS.OAUTH_CALLBACK_SUCCESS,
      category: AUDIT_CATEGORY.OAUTH,
      status: AUDIT_STATUS.SUCCESS,
      message: AUDIT_MESSAGES.OAUTH_CALLBACK_SUCCESS,
      metadata: {
        provider,
        email: result.user.email,
      },
    });

    setAuthCookies(res, result, deviceInfo);
    res.redirect(result.redirectTo);
  } catch (error) {
    await emitAuditEvent({
      ...auditContext,
      event: AUDIT_EVENTS.OAUTH_CALLBACK_FAILED,
      category: AUDIT_CATEGORY.OAUTH,
      status: AUDIT_STATUS.FAILURE,
      severity: "warn",
      message: AUDIT_MESSAGES.OAUTH_CALLBACK_FAILED,
      metadata: {
        provider,
        reason: error.message,
      },
    });

    throw error;
  }
};

const buildRedirectWithQuery = (baseUrl, params) => {
  const url = new URL(baseUrl);

  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") {
      return;
    }

    url.searchParams.set(key, String(value));
  });

  return url.toString();
};

export const listOrganizationOauthProvidersHandler = async (req, res) => {
  const { orgId, clientId } = organizationOauthProvidersParamSchema.parse(
    req.params,
  );

  const result = await listOrganizationClientOauthProviders({
    orgId,
    clientId,
  });

  res.status(200).json(result);
};

export const organizationOauthStartHandler = async (req, res) => {
  const { orgId, clientId, provider } = organizationOauthParamSchema.parse(
    req.params,
  );
  const query = organizationOauthStartQuerySchema.parse(req.query);
  const auditContext = buildAuditContextFromRequest(req);

  const result = await getOrganizationClientOauthStart({
    orgId,
    clientId,
    provider,
    returnTo: query.returnTo,
    flowType: query.flowType,
    clientContext: query.clientContext,
  });

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.OAUTH_START,
    category: AUDIT_CATEGORY.OAUTH,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.OAUTH_START,
    metadata: {
      provider,
      clientId,
      flowType: query.flowType,
    },
  });

  res.redirect(result.redirectUrl);
};

export const organizationOauthCallbackHandler = async (req, res) => {
  const { orgId, clientId, provider } = organizationOauthParamSchema.parse(
    req.params,
  );
  const query = organizationOauthCallbackQuerySchema.parse({
    code: req.query[OAUTH_CALLBACK_QUERY_CODE],
    state: req.query[OAUTH_CALLBACK_QUERY_STATE],
  });
  const auditContext = buildAuditContextFromRequest(req);

  try {
    const deviceInfo = buildRequestDevice(req);
    const result = await handleOrganizationClientOauthCallback({
      orgId,
      clientId,
      provider,
      code: query.code,
      stateToken: query.state,
      deviceInfo,
    });

    await emitAuditEvent({
      ...auditContext,
      actorUserId: result.user.id,
      sessionId: result.session.id,
      event: AUDIT_EVENTS.OAUTH_CALLBACK_SUCCESS,
      category: AUDIT_CATEGORY.OAUTH,
      status: AUDIT_STATUS.SUCCESS,
      orgId,
      message: AUDIT_MESSAGES.OAUTH_CALLBACK_SUCCESS,
      metadata: {
        provider,
        clientId,
        flowType: result.flowType,
      },
    });

    if (result.confirmationRequired) {
      res.redirect(
        buildRedirectWithQuery(result.redirectTo, {
          oauth: "confirm",
          flowType: result.flowType,
          clientContext: result.clientContext,
          [OAUTH_CALLBACK_QUERY_CHALLENGE_TOKEN]: result.challengeToken,
        }),
      );
      return;
    }

    if (result.oidcCompleted) {
      setAuthCookies(res, result, deviceInfo);
      res.redirect(result.redirectTo);
      return;
    }

    setAuthCookies(res, result, deviceInfo);
    res.redirect(
      buildRedirectWithQuery(result.redirectTo, {
        oauth: "success",
        flowType: result.flowType,
        clientContext: result.clientContext,
      }),
    );
  } catch (error) {
    await emitAuditEvent({
      ...auditContext,
      event: AUDIT_EVENTS.OAUTH_CALLBACK_FAILED,
      category: AUDIT_CATEGORY.OAUTH,
      status: AUDIT_STATUS.FAILURE,
      severity: "warn",
      orgId,
      message: AUDIT_MESSAGES.OAUTH_CALLBACK_FAILED,
      metadata: {
        provider,
        clientId,
        reason: error.message,
      },
    });

    throw error;
  }
};

export const confirmOrganizationOauthChallengeHandler = async (req, res) => {
  const payload = confirmOrganizationOauthChallengeSchema.parse(req.body);
  const deviceInfo = buildRequestDevice(req);

  const result = await confirmOrganizationOauthChallenge(
    payload.challengeToken,
  );

  setAuthCookies(res, result, deviceInfo);
  res.status(200).json({
    redirectTo: buildRedirectWithQuery(result.redirectTo, {
      oauth: "success",
      flowType: result.flowType,
      clientContext: result.clientContext,
    }),
  });
};
